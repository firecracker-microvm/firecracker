"""
This module is imported by pytest at the start of every test session. Fixtures
herein are made available to every test collected by pytest.

# Fixture Goals

- Running a test on a microvm is as easy as importing a microvm fixture.
- Adding a new microvm image (kernel, rootfs) for tests to run on is as easy as
  uploading that image to a key-value store, e.g., an s3 bucket.

# Solution

- Keep microvm test images in an s3 bucket, structured as follows:

``` tree
s3://<bucket-url>/microvm-images/
    <microvm_test_image_folder_n>/
        kernel/
            <optional_kernel_name.>vmlinux.bin
        fsfiles/
            <rootfs_name>rootfs.ext4
            <other_fsfile_n>
            ...
        <other_resource_n>
        ...
    ...
```

- Tag `<microvm_test_image_folder_n>` with the capabilities of that image:

``` json
TagSet = [{"key": "capability:<cap_name>", "value": ""}, ...]
```

- Make available fixtures that expose microvms based on any given capability.
  For example, a test function using the fixture `test_microvm_any` should run
  on all microvm images in the s3 bucket, while a test using the fixture
  `test_microvm_with_net` should only run on the microvm images tagged with
  `capability:net`. Note that a test function that uses a parameterized fixture
  will yield one test case for every possible parameter of that fixture. For
  example, using `test_microvm_any` in a test will create as many test cases
  as there are microvm images in the s3 bucket.

- Provide fixtures that simplify other common testing operations, like http
  over local unix domain sockets.

# Example

```
def test_with_any_microvm(test_microvm_any, uhttp):

    response = uhttp.put(
        test_microvm_any.microvm_cfg_url,
        json={'vcpu_count': 2}
    )
    assert(uhttp.is_good_response(response.status_code))

    # [...]

    response = uhttp.put(
        test_microvm_any.actions_url + '/1',
        json={'action_id': '1', 'action_type': 'InstanceStart'}
    )
    assert(uhttp.is_good_response(response.status_code))
```

The test above makes use of the "any" test microvm fixture, so this test will
be run on every microvm image in the bucket, each as a separate test case.

# Notes

- Reading up on pytest fixtures is probably needed when editing this file.
- Programming here is not defensive, since tests systems turn false negatives
  into a quality-improving positive feedback loop.

# TODO

- A fixture that wraps `subprocess.run('<command>, shell=True, check=True)`,
  and also controls output verbosity by appending `>/dev/null [&2>1]`.
- A fixture that allows per-test-function dependency installation.
- Monitor of socket file creation via inotify.
- Support generating fixtures with more than one capability. This is supported
  by the MicrovmImageFetcher, but not by the fixture template.
"""

import os
import time
import tempfile
import shutil
import uuid

import pytest

from microvm_image import MicrovmImageS3Fetcher
from microvm import MicrovmSlot, Microvm


TEST_MICROVM_IMAGES_S3_BUCKET = 'spec.firecracker'
""" The bucket that holds Firecracker microvm test images. """

ENV_TMPDIR_VAR = 'TR_TMPDIR'
"""
If this environment variable is set, its value will become the root for
temporary directories created by the test session.
"""

DEFAULT_ROOT_TESTSESSION_PATH = '/tmp/firecracker_test_session/'
""" If ENV_TMPDIR_VAR is not set, this path will be used. """


if os.geteuid() != 0:
    """ Some tests create system-level resources, so we should run as root. """
    raise PermissionError("Test session needs to be run as root.")


@pytest.fixture
def test_session_root_path():
    """
    Ensures and yields the testrun root directory. If created here, it is also
    destroyed during teardown.
    """

    created_test_session_root_path = False

    try:
        test_session_root_path = os.environ[ENV_TMPDIR_VAR]
    except:
        test_session_root_path = DEFAULT_ROOT_TESTSESSION_PATH

    if not os.path.exists(test_session_root_path):
        os.makedirs(test_session_root_path)
        created_test_session_root_path = True

    yield test_session_root_path

    if created_test_session_root_path:
        shutil.rmtree(test_session_root_path)


@pytest.fixture
def testsession_tmp_path(test_session_root_path):
    """ Yields a random temporary directory. Destroyed on teardown. """
    test_session_tmp_path = tempfile.mkdtemp(prefix=test_session_root_path)
    yield test_session_tmp_path
    shutil.rmtree(test_session_tmp_path)


@pytest.fixture
def microvm_slot(test_session_root_path):
    """ Yields a microvm slot with an UUID as the slot id. """
    slot = MicrovmSlot(
        id=str(uuid.uuid4()),
        microvm_root_path=test_session_root_path
    )
    slot.setup()
    yield slot
    slot.teardown()


@pytest.fixture
def microvm(microvm_slot):
    """ Yields a spawned microvm in a given microvm slot. """

    microvm = Microvm(microvm_slot, id=str(uuid.uuid4()))
    microvm.spawn()

    while True:
        if os.path.exists(
                os.path.join(microvm.slot.path, microvm.api_usocket_name)
        ):
            break
        else:
            time.sleep(0.001)
            # TODO: Switch to getting notified when the socket file is created.

    yield microvm

    microvm.kill()


@pytest.fixture
def microvm_image_fetcher():
    """ Returns an borg object that knows about fetching microvm images. """
    return MicrovmImageS3Fetcher(TEST_MICROVM_IMAGES_S3_BUCKET)


@pytest.fixture(
    params=microvm_image_fetcher().list_microvm_images(
        capability_filter=['*']
    )
)
def test_microvm_any(request, microvm, microvm_image_fetcher):
    """
    When using a pytest parameterized fixture, a test case is created for each
    parameter in the list. We generate the list dynamically based on the
    capability filter. This will result in
    `len(microvm_image_fetcher.list_microvm_images(capability_filter=['*']))`
    test cases for each test that depends on this fixture, each receiving a
    microvm slot with a different microvm image.
    """
    microvm_image_fetcher.get_microvm_image(request.param, microvm.slot)
    yield microvm


test_microvm_cap_fixture_template = (
    "@pytest.fixture("
    "    params=microvm_image_fetcher().list_microvm_images(\n"
    "        capability_filter=['CAP']\n"
    "    )\n"
    ")\n"
    "def test_microvm_with_CAP(request, microvm, microvm_image_fetcher):\n"
    "    microvm_image_fetcher.get_microvm_image(\n"
    "        request.param, microvm.slot\n"
    "    )\n"
    "    yield microvm"
)

for capability in microvm_image_fetcher().enum_capabilities():
    test_microvm_cap_fixture = (
        test_microvm_cap_fixture_template.replace('CAP', capability)
    )
    exec(test_microvm_cap_fixture)
"""
To make test writing easy, we want to dynamically create fixtures with all
capabilities present in the test microvm images bucket. `pytest` doesn't
provide a way to do that outright, but luckily all of python is just lists of
of lists and a cursor, so exec() works fine here.

TODO: Support generating fixtures with more than one capability. This is
      supported by the MicrovmImageFetcher, but not by the fixture template.
"""
