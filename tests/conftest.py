# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
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
s3://<bucket-url>/img/
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
- A fixture that allows per-test-function dependency installation.
- Support generating fixtures with more than one capability. This is supported
  by the MicrovmImageFetcher, but not by the fixture template.
"""

import os
import platform
import shutil
import sys
import tempfile
import uuid

import pytest

import host_tools.cargo_build as build_tools
import host_tools.network as net_tools

import framework.utils as utils
from framework.microvm import Microvm
from framework.s3fetcher import MicrovmImageS3Fetcher
from framework.scheduler import PytestScheduler


SPEC_S3_BUCKET = 'spec.ccfc.min'
"""The s3 bucket that holds global Firecracker specifications."""

DEFAULT_TEST_IMAGES_S3_BUCKET = 'spec.ccfc.min'
"""The default s3 bucket that holds Firecracker microvm test images."""

ENV_TEST_IMAGES_S3_BUCKET = 'TEST_MICROVM_IMAGES_S3_BUCKET'
"""Environment variable for configuring the test microvm s3 bucket.

If variable exists in `os.environ`, its value will be used as the s3 bucket
for microvm test images.
"""


# This codebase uses Python features available in Python 3.6 or above
if sys.version_info < (3, 6):
    raise SystemError("This codebase requires Python 3.6 or above.")


# Some tests create system-level resources; ensure we run as root.
if os.geteuid() != 0:
    raise PermissionError("Test session needs to be run as root.")


def _test_images_s3_bucket():
    """Auxiliary function for getting this session's bucket name."""
    return os.environ.get(
        ENV_TEST_IMAGES_S3_BUCKET,
        DEFAULT_TEST_IMAGES_S3_BUCKET
    )


MICROVM_S3_FETCHER = MicrovmImageS3Fetcher(_test_images_s3_bucket())


def init_microvm(root_path, bin_cloner_path,
                 fc_binary=None, jailer_binary=None):
    """Auxiliary function for instantiating a microvm and setting it up."""
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.
    microvm_id = str(uuid.uuid4())

    if fc_binary is None:
        fc_binary, jailer_binary = build_tools.get_firecracker_binaries()

    # Make sure we always have both binaries.
    assert fc_binary
    assert jailer_binary

    vm = Microvm(
         resource_path=root_path,
         fc_binary_path=fc_binary,
         jailer_binary_path=jailer_binary,
         microvm_id=microvm_id,
         bin_cloner_path=bin_cloner_path)
    vm.setup()
    return vm


def pytest_configure(config):
    """Pytest hook - initialization.

    Initialize the test scheduler and IPC services.
    """
    PytestScheduler.instance().register_mp_singleton(
        net_tools.UniqueIPv4Generator.instance()
    )
    config.pluginmanager.register(PytestScheduler.instance())


def pytest_addoption(parser):
    """Pytest hook. Add concurrency command line option.

    For some reason, pytest doesn't properly pick up this hook in our plugin
    class, so we need to call it from here.
    """
    return PytestScheduler.instance().do_pytest_addoption(parser)


@pytest.fixture(autouse=True, scope='session')
def test_session_root_path():
    """Ensure and yield the testrun root directory.

    Created at session initialization time, this directory will be
    session-unique. This is important, since the scheduler will run
    multiple pytest sessions concurrently.
    """
    root_path = tempfile.mkdtemp(prefix="fctest-")

    yield root_path

    shutil.rmtree(root_path)


@pytest.fixture
def test_session_tmp_path(test_session_root_path):
    """Yield a random temporary directory. Destroyed on teardown."""
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.

    tmp_path = tempfile.mkdtemp(prefix=test_session_root_path)
    yield tmp_path
    shutil.rmtree(tmp_path)


def _gcc_compile(src_file, output_file, extra_flags="-static -O3"):
    """Build a source file with gcc."""
    compile_cmd = 'gcc {} -o {} {}'.format(
        src_file,
        output_file,
        extra_flags
    )
    utils.run_cmd(compile_cmd)


@pytest.fixture(scope='session')
def bin_cloner_path(test_session_root_path):
    """Build a binary that `clone`s into the jailer.

    It's necessary because Python doesn't interface well with the `clone()`
    syscall directly.
    """
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.
    cloner_bin_path = os.path.join(test_session_root_path, 'newpid_cloner')
    _gcc_compile(
        'host_tools/newpid_cloner.c',
        cloner_bin_path
    )
    yield cloner_bin_path


@pytest.fixture(scope='session')
def bin_vsock_path(test_session_root_path):
    """Build a simple vsock client/server application."""
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.
    vsock_helper_bin_path = os.path.join(
        test_session_root_path,
        'vsock_helper'
    )
    _gcc_compile(
        'host_tools/vsock_helper.c',
        vsock_helper_bin_path
    )
    yield vsock_helper_bin_path


@pytest.fixture(scope='session')
def change_net_config_space_bin(test_session_root_path):
    """Build a binary that changes the MMIO config space."""
    # pylint: disable=redefined-outer-name
    change_net_config_space_bin = os.path.join(
        test_session_root_path,
        'change_net_config_space'
    )
    _gcc_compile(
        'host_tools/change_net_config_space.c',
        change_net_config_space_bin,
        extra_flags=""
    )
    yield change_net_config_space_bin


@pytest.fixture(scope='session')
def bin_seccomp_paths(test_session_root_path):
    """Build jailers and jailed binaries to test seccomp.

    They currently consist of:

    * a jailer with a simple syscall whitelist;
    * a jailer with a (syscall, arguments) advanced whitelist;
    * a jailed binary that follows the seccomp rules;
    * a jailed binary that breaks the seccomp rules.
    """
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.
    seccomp_build_path = os.path.join(
        test_session_root_path,
        build_tools.CARGO_RELEASE_REL_PATH
    )

    extra_args = '--release --target {}-unknown-linux-musl'
    extra_args = extra_args.format(platform.machine())
    build_tools.cargo_build(seccomp_build_path,
                            extra_args=extra_args,
                            src_dir='integration_tests/security/demo_seccomp')

    release_binaries_path = os.path.join(
        test_session_root_path,
        build_tools.CARGO_RELEASE_REL_PATH,
        build_tools.RELEASE_BINARIES_REL_PATH
    )

    demo_basic_jailer = os.path.normpath(
        os.path.join(
            release_binaries_path,
            'demo_basic_jailer'
        )
    )
    demo_advanced_jailer = os.path.normpath(
        os.path.join(
            release_binaries_path,
            'demo_advanced_jailer'
        )
    )
    demo_harmless = os.path.normpath(
        os.path.join(
            release_binaries_path,
            'demo_harmless'
        )
    )
    demo_malicious = os.path.normpath(
        os.path.join(
            release_binaries_path,
            'demo_malicious'
        )
    )

    yield {
        'demo_basic_jailer': demo_basic_jailer,
        'demo_advanced_jailer': demo_advanced_jailer,
        'demo_harmless': demo_harmless,
        'demo_malicious': demo_malicious
    }


@pytest.fixture()
def microvm(test_session_root_path, bin_cloner_path):
    """Instantiate a microvm."""
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.

    # Make sure the necessary binaries are there before instantiating the
    # microvm.
    vm = init_microvm(test_session_root_path, bin_cloner_path)
    yield vm
    vm.kill()
    shutil.rmtree(os.path.join(test_session_root_path, vm.id))


@pytest.fixture
def network_config():
    """Yield a UniqueIPv4Generator."""
    yield net_tools.UniqueIPv4Generator.instance()


@pytest.fixture(
    params=MICROVM_S3_FETCHER.list_microvm_images(
        capability_filter=['*']
    )
)
def test_microvm_any(request, microvm):
    """Yield a microvm that can have any image in the spec bucket.

    A test case using this fixture will run for every microvm image.

    When using a pytest parameterized fixture, a test case is created for each
    parameter in the list. We generate the list dynamically based on the
    capability filter. This will result in
    `len(MICROVM_S3_FETCHER.list_microvm_images(capability_filter=['*']))`
    test cases for each test that depends on this fixture, each receiving a
    microvm instance with a different microvm image.
    """
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.

    MICROVM_S3_FETCHER.init_vm_resources(request.param, microvm)
    yield microvm


@pytest.fixture
def test_multiple_microvms(
        test_session_root_path,
        context,
        bin_cloner_path
):
    """Yield one or more microvms based on the context provided.

    `context` is a dynamically parameterized fixture created inside the special
    function `pytest_generate_tests` and it holds a tuple containing the name
    of the guest image used to spawn a microvm and the number of microvms
    to spawn.
    """
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.
    microvms = []
    (microvm_resources, how_many) = context

    # When the context specifies multiple microvms, we use the first vm to
    # populate the other ones by hardlinking its resources.
    first_vm = init_microvm(test_session_root_path, bin_cloner_path)
    MICROVM_S3_FETCHER.init_vm_resources(
        microvm_resources,
        first_vm
    )
    microvms.append(first_vm)

    # It is safe to do this as the dynamically generated fixture `context`
    # asserts that the `how_many` parameter is always positive
    # (i.e strictly greater than 0).
    for _ in range(how_many - 1):
        vm = init_microvm(test_session_root_path, bin_cloner_path)
        MICROVM_S3_FETCHER.hardlink_vm_resources(
            microvm_resources,
            first_vm,
            vm
        )
        microvms.append(vm)

    yield microvms

    for i in range(how_many):
        microvms[i].kill()
        shutil.rmtree(os.path.join(test_session_root_path, microvms[i].id))


def pytest_generate_tests(metafunc):
    """Implement customized parametrization scheme.

    This is a special hook which is called by the pytest infrastructure when
    collecting a test function. The `metafunc` contains the requesting test
    context. Amongst other things, the `metafunc` provides the list of fixture
    names that the calling test function is using.  If we find a fixture that
    is called `context`, we check the calling function through the
    `metafunc.function` field for the `_pool_size` attribute which we
    previously set with a decorator. Then we create the list of parameters
    for this fixture.
    The parameter will be a list of tuples of the form (cap, pool_size).
    For each parameter from the list (i.e. tuple) a different test case
    scenario will be created.
    """
    if 'context' in metafunc.fixturenames:
        # In order to create the params for the current fixture, we need the
        # capability and the number of vms we want to spawn.

        # 1. Look if the test function set the pool size through the decorator.
        # If it did not, we set it to 1.
        how_many = int(getattr(metafunc.function, '_pool_size', None))
        assert how_many > 0

        # 2. Check if the test function set the capability field through
        # the decorator. If it did not, we set it to any.
        cap = getattr(metafunc.function, '_capability', '*')

        # 3. Before parametrization, get the list of images that have the
        # desired capability. By parametrize-ing the fixture with it, we
        # trigger tests cases for each of them.
        image_list = MICROVM_S3_FETCHER.list_microvm_images(
            capability_filter=[cap]
        )
        metafunc.parametrize(
            'context',
            [(item, how_many) for item in image_list],
            ids=['{}, {} instance(s)'.format(
                item, how_many
            ) for item in image_list]
        )


TEST_MICROVM_CAP_FIXTURE_TEMPLATE = (
    "@pytest.fixture("
    "    params=MICROVM_S3_FETCHER.list_microvm_images(\n"
    "        capability_filter=['CAP']\n"
    "    )\n"
    ")\n"
    "def test_microvm_with_CAP(request, microvm):\n"
    "    MICROVM_S3_FETCHER.init_vm_resources(\n"
    "        request.param, microvm\n"
    "    )\n"
    "    yield microvm"
)

# To make test writing easy, we want to dynamically create fixtures with all
# capabilities present in the test microvm images bucket. `pytest` doesn't
# provide a way to do that outright, but luckily all of python is just lists of
# of lists and a cursor, so exec() works fine here.
for capability in MICROVM_S3_FETCHER.enum_capabilities():
    TEST_MICROVM_CAP_FIXTURE = (
        TEST_MICROVM_CAP_FIXTURE_TEMPLATE.replace('CAP', capability)
    )
    # pylint: disable=exec-used
    # This is the most straightforward way to achieve this result.
    exec(TEST_MICROVM_CAP_FIXTURE)
