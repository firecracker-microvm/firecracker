"""Imported by pytest at the start of every test session.

# Fixture Goals

Fixtures herein are made available to every test collected by pytest. They are
designed with the following goals in mind:
- Running a test on a microvm is as easy as importing a microvm fixture.
- Adding a new microvm image (kernel, rootfs) for tests to run on is as easy as
  uploading that image to a key-value store, e.g., an s3 bucket.

# Solution

- Keep microvm test images in an S3 bucket, structured as follows:

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
  on all microvm images in the S3 bucket, while a test using the fixture
  `test_microvm_with_net` should only run on the microvm images tagged with
  `capability:net`. Note that a test function that uses a parameterized fixture
  will yield one test case for every possible parameter of that fixture. For
  example, using `test_microvm_any` in a test will create as many test cases
  as there are microvm images in the S3 bucket.

- Provide fixtures that simplify other common testing operations, like http
  over local unix domain sockets.

# Example

```
def test_with_any_microvm(test_microvm_any):

    response = test_microvm_any.machine_cfg.put(
        vcpu_count=8
    )
    assert(test_microvm_any.api_session.is_good_response(response.status_code))

    # [...]

    response = test_microvm_any.actions.put(action_type='InstanceStart')
    assert(test_microvm_any.api_session.is_good_response(response.status_code))
```

The test above makes use of the "any" test microvm fixture, so this test will
be run on every microvm image in the bucket, each as a separate test case.

# Notes

- Reading up on pytest fixtures is probably needed when editing this file.

# TODO

- A fixture that wraps `subprocess.run('<command>, shell=True, check=True)`,
  and also controls output verbosity by appending `>/dev/null [&2>1]`.
- A fixture that allows per-test-function dependency installation.
- Support generating fixtures with more than one capability. This is supported
  by the MicrovmImageFetcher, but not by the fixture template.
"""

import threading
import os
import shutil
import sys
import tempfile
import uuid

import pytest

import host_tools.cargo_build as build_tools
import host_tools.network as net_tools

from framework.microvm import Microvm
from framework.s3fetcher import MicrovmImageS3Fetcher


SPEC_S3_BUCKET = 'spec.firecracker'
"""The s3 bucket that holds global Firecracker specifications."""

DEFAULT_TEST_IMAGES_S3_BUCKET = 'spec.firecracker'
"""The default s3 bucket that holds Firecracker microvm test images."""

ENV_TEST_IMAGES_S3_BUCKET = 'TEST_MICROVM_IMAGES_S3_BUCKET'
"""Environment variable for configuring the test microvm s3 bucket.

If variable exists in `os.environ`, its value will be used as the s3 bucket
for microvm test images.
"""

ENV_TMPDIR_VAR = 'TR_TMPDIR'
"""Environment variable for configuring temporary directory.

If variable exists in `os.environ`, its value it will be used for the test
session root and temporary directories.
"""

DEFAULT_ROOT_TESTSESSION_PATH = '/tmp/firecracker_test_session/'
"""If ENV_TMPDIR_VAR is not set, this path will be used instead."""

IP4_GENERATOR_CREATE_LOCK = threading.Lock()


# This codebase uses Python features available in Python 3.6 or above
if sys.version_info < (3, 6):
    raise SystemError("This codebase requires Python 3.6 or above.")


# Some tests create system-level resources; ensure we run as root.
if os.geteuid() != 0:
    raise PermissionError("Test session needs to be run as root.")


@pytest.fixture(autouse=True, scope='session')
def test_session_root_path():
    """Ensure and yield the testrun root directory.

    If created here, it is also destroyed during teardown. The root directory
    is created per test session.
    """
    created_test_session_root_path = False

    try:
        root_path = os.environ[ENV_TMPDIR_VAR]
    except KeyError:
        root_path = DEFAULT_ROOT_TESTSESSION_PATH

    if not os.path.exists(root_path):
        os.makedirs(root_path)
        created_test_session_root_path = True

    yield root_path

    if created_test_session_root_path:
        shutil.rmtree(root_path)


@pytest.fixture
def test_session_tmp_path(test_session_root_path):
    """Yield a random temporary directory. Destroyed on teardown."""
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.

    tmp_path = tempfile.mkdtemp(prefix=test_session_root_path)
    yield tmp_path
    shutil.rmtree(tmp_path)


@pytest.fixture
def microvm(test_session_root_path):
    """Instantiate a microvm."""
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.

    # Make sure the necessary binaries are there before instantiating the
    # microvm.
    fc_binary, jailer_binary = build_tools.get_firecracker_binaries(
        test_session_root_path
    )

    microvm_id = str(uuid.uuid4())

    vm = Microvm(
        resource_path=test_session_root_path,
        fc_binary_path=fc_binary,
        jailer_binary_path=jailer_binary,
        microvm_id=microvm_id
    )
    vm.setup()

    yield vm
    vm.kill()


@pytest.fixture
def network_config():
    """Yield a UniqueIPv4Generator."""
    with IP4_GENERATOR_CREATE_LOCK:
        ipv4_generator = net_tools.UniqueIPv4Generator.get_instance()
    yield ipv4_generator


@pytest.fixture
def microvm_image_fetcher():
    """Return a borg object that knows about fetching microvm images.

    If `ENV_TEST_IMAGES_S3_BUCKET` is set in the environment, target the bucket
    specified therein, else use the default.
    """
    if ENV_TEST_IMAGES_S3_BUCKET in os.environ:
        test_images_s3_bucket = os.environ.get(ENV_TEST_IMAGES_S3_BUCKET)
    else:
        test_images_s3_bucket = DEFAULT_TEST_IMAGES_S3_BUCKET

    return MicrovmImageS3Fetcher(test_images_s3_bucket)


@pytest.fixture(
    params=microvm_image_fetcher().list_microvm_images(
        capability_filter=['*']
    )
)
def test_microvm_any(request, microvm, microvm_image_fetcher):
    """Yield a microvm that can have any image in the spec bucket.

    A test case using this fixture will run for every microvm image.

    When using a pytest parameterized fixture, a test case is created for each
    parameter in the list. We generate the list dynamically based on the
    capability filter. This will result in
    `len(microvm_image_fetcher.list_microvm_images(capability_filter=['*']))`
    test cases for each test that depends on this fixture, each receiving a
    microvm instance with a different microvm image.
    """
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.

    microvm_image_fetcher.get_microvm_image(request.param, microvm)
    yield microvm


TEST_MICROVM_CAP_FIXTURE_TEMPLATE = (
    "@pytest.fixture("
    "    params=microvm_image_fetcher().list_microvm_images(\n"
    "        capability_filter=['CAP']\n"
    "    )\n"
    ")\n"
    "def test_microvm_with_CAP(request, microvm, microvm_image_fetcher):\n"
    "    microvm_image_fetcher.get_microvm_image(\n"
    "        request.param, microvm\n"
    "    )\n"
    "    yield microvm"
)

# To make test writing easy, we want to dynamically create fixtures with all
# capabilities present in the test microvm images bucket. `pytest` doesn't
# provide a way to do that outright, but luckily all of python is just lists of
# of lists and a cursor, so exec() works fine here.
for capability in microvm_image_fetcher().enum_capabilities():
    test_microvm_cap_fixture = (
        TEST_MICROVM_CAP_FIXTURE_TEMPLATE.replace('CAP', capability)
    )
    # pylint: disable=exec-used
    # This is the most straightforward way to achieve this result.
    exec(test_microvm_cap_fixture)
