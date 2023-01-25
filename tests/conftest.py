# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Pytest fixtures and redefined-outer-name don't mix well. Disable it.
# pylint:disable=redefined-outer-name
# We import some fixtures that are unused. Disable that too.
# pylint:disable=unused-import

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

import inspect
import json
import os
import platform
import re
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

import host_tools.cargo_build as build_tools
from host_tools.ip_generator import network_config, subnet_generator
from framework import utils
from framework import defs
from framework.artifacts import ArtifactCollection, FirecrackerArtifact
from framework.microvm import Microvm
from framework.s3fetcher import MicrovmImageS3Fetcher
from framework.utils import get_firecracker_version_from_toml
from framework.with_filelock import with_filelock
from framework.properties import GLOBAL_PROPS
from framework.utils_cpu_templates import SUPPORTED_CPU_TEMPLATES

# Tests root directory.
SCRIPT_FOLDER = os.path.dirname(os.path.realpath(__file__))

# This codebase uses Python features available in Python 3.6 or above
if sys.version_info < (3, 6):
    raise SystemError("This codebase requires Python 3.6 or above.")


# Some tests create system-level resources; ensure we run as root.
if os.geteuid() != 0:
    raise PermissionError("Test session needs to be run as root.")


def _test_images_s3_bucket():
    """Auxiliary function for getting this session's bucket name."""
    return os.environ.get(
        defs.ENV_TEST_IMAGES_S3_BUCKET, defs.DEFAULT_TEST_IMAGES_S3_BUCKET
    )


ARTIFACTS_COLLECTION = ArtifactCollection(_test_images_s3_bucket())
MICROVM_S3_FETCHER = MicrovmImageS3Fetcher(_test_images_s3_bucket())


# pylint: disable=too-few-public-methods
class ResultsDumperInterface:
    """Interface for dumping results to file."""

    def dump(self, result):
        """Dump the results in JSON format."""


# pylint: disable=too-few-public-methods
class NopResultsDumper(ResultsDumperInterface):
    """Interface for dummy dumping results to file."""

    def dump(self, result):
        """Do not do anything."""


# pylint: disable=too-few-public-methods
class JsonFileDumper(ResultsDumperInterface):
    """Class responsible with outputting test results to files."""

    def __init__(self, request):
        """Initialize the instance."""
        self._results_file = None

        test_name = request.node.originalname
        self._root_path = defs.TEST_RESULTS_DIR
        # Create the root directory, if it doesn't exist.
        self._root_path.mkdir(exist_ok=True)
        self._results_file = os.path.join(
            self._root_path,
            "{}_results_{}.json".format(test_name, utils.get_kernel_version(level=1)),
        )

    @staticmethod
    def __dump_pretty_json(file, data, flags):
        """Write the `data` dictionary to the output file in pretty format."""
        with open(file, flags, encoding="utf-8") as file_fd:
            json.dump(data, file_fd, indent=4)
            file_fd.write("\n")  # Add newline cause Py JSON does not
            file_fd.flush()

    def dump(self, result):
        """Dump the results in JSON format."""
        if self._results_file:
            self.__dump_pretty_json(self._results_file, result, "a")


def init_microvm(root_path, bin_cloner_path, fc_binary=None, jailer_binary=None):
    """Auxiliary function for instantiating a microvm and setting it up."""
    microvm_id = str(uuid.uuid4())

    # Update permissions for custom binaries.
    if fc_binary is not None:
        os.chmod(fc_binary, 0o555)
    if jailer_binary is not None:
        os.chmod(jailer_binary, 0o555)

    if fc_binary is None or jailer_binary is None:
        fc_binary, jailer_binary = build_tools.get_firecracker_binaries()

    # Make sure we always have both binaries.
    assert fc_binary
    assert jailer_binary

    vm = Microvm(
        resource_path=root_path,
        fc_binary_path=fc_binary,
        jailer_binary_path=jailer_binary,
        microvm_id=microvm_id,
        bin_cloner_path=bin_cloner_path,
    )
    vm.setup()
    return vm


def pytest_configure(config):
    """Pytest hook - initialization"""
    config.addinivalue_line("markers", "nonci: mark test as nonci.")


def pytest_addoption(parser):
    """Pytest hook. Add command line options."""
    parser.addoption(
        "--dump-results-to-file",
        action="store_true",
        help="Flag to dump test results to the test_results folder.",
    )
    parser.addoption("--nonci", action="store_true", help="run tests marked with nonci")


def pytest_collection_modifyitems(config, items):
    """Pytest hook. Skip some tests."""
    skip_markers = {}

    for skip_marker_name in ["nonci"]:
        if not config.getoption(f"--{skip_marker_name}"):
            skip_markers[skip_marker_name] = pytest.mark.skip(
                reason=f"Skipping {skip_marker_name} test"
            )

    for item in items:
        for skip_marker_name, skip_marker in skip_markers.items():
            if skip_marker_name in item.keywords:
                item.add_marker(skip_marker)


def pytest_runtest_makereport(item, call):
    """Decorate test results with additional properties."""
    if call.when != "setup":
        return

    for prop_name, prop_val in GLOBAL_PROPS.items():
        # if record_testsuite_property worked with xdist we could use that
        # https://docs.pytest.org/en/7.1.x/reference/reference.html#record-testsuite-property
        # to record the properties once per report. But here we record each
        # prop per test. It just results in larger report files.
        item.user_properties.append((prop_name, prop_val))

    function_docstring = inspect.getdoc(item.function)
    description = []
    attributes = {}
    for line in function_docstring.split("\n"):
        # extract tags like @type, @issue, etc
        match = re.match(r"\s*@(?P<attr>\w+):\s*(?P<value>\w+)", line)
        if match:
            attr, value = match["attr"], match["value"]
            attributes[attr] = value
        else:
            description.append(line)
    for attr_name, attr_value in attributes.items():
        item.user_properties.append((attr_name, attr_value))
    item.user_properties.append(("description", "".join(description)))


def test_session_root_path():
    """Create and return the testrun session root directory.

    Testrun session root directory confines any other test temporary file.
    If it exists, consider this as a noop.
    """
    os.makedirs(defs.DEFAULT_TEST_SESSION_ROOT_PATH, exist_ok=True)
    return defs.DEFAULT_TEST_SESSION_ROOT_PATH


@pytest.fixture(autouse=True, scope="session")
def test_fc_session_root_path():
    """Ensure and yield the fc session root directory.

    Create a unique temporary session directory. This is important, since the
    scheduler will run multiple pytest sessions concurrently.
    """
    fc_session_root_path = tempfile.mkdtemp(
        prefix="fctest-", dir=f"{test_session_root_path()}"
    )
    yield fc_session_root_path
    shutil.rmtree(fc_session_root_path)


@pytest.fixture
def test_session_tmp_path(test_fc_session_root_path):
    """Yield a random temporary directory. Destroyed on teardown."""

    tmp_path = tempfile.mkdtemp(prefix=test_fc_session_root_path)
    yield tmp_path
    shutil.rmtree(tmp_path)


@pytest.fixture
def results_file_dumper(request):
    """Yield the custom --dump-results-to-file test flag."""
    if request.config.getoption("--dump-results-to-file"):
        return JsonFileDumper(request)

    return NopResultsDumper()


@with_filelock
def _gcc_compile(src_file, output_file, extra_flags="-static -O3"):
    """Build a source file with gcc."""
    output_file = Path(output_file)
    if not output_file.exists():
        compile_cmd = f"gcc {src_file} -o {output_file} {extra_flags}"
        utils.run_cmd(compile_cmd)


@pytest.fixture(scope="session")
def bin_cloner_path(test_fc_session_root_path):
    """Build a binary that `clone`s into the jailer.

    It's necessary because Python doesn't interface well with the `clone()`
    syscall directly.
    """
    cloner_bin_path = os.path.join(test_fc_session_root_path, "newpid_cloner")
    _gcc_compile("host_tools/newpid_cloner.c", cloner_bin_path)
    yield cloner_bin_path


@pytest.fixture(scope="session")
def bin_vsock_path(test_fc_session_root_path):
    """Build a simple vsock client/server application."""
    vsock_helper_bin_path = os.path.join(test_fc_session_root_path, "vsock_helper")
    _gcc_compile("host_tools/vsock_helper.c", vsock_helper_bin_path)
    yield vsock_helper_bin_path


@pytest.fixture(scope="session")
def change_net_config_space_bin(test_fc_session_root_path):
    """Build a binary that changes the MMIO config space."""
    change_net_config_space_bin = os.path.join(
        test_fc_session_root_path, "change_net_config_space"
    )
    _gcc_compile(
        "host_tools/change_net_config_space.c",
        change_net_config_space_bin,
        extra_flags="",
    )
    yield change_net_config_space_bin


@pytest.fixture(scope="session")
def bin_seccomp_paths(test_fc_session_root_path):
    """Build jailers and jailed binaries to test seccomp.

    They currently consist of:

    * a jailer that receives filter generated using seccompiler-bin;
    * a jailed binary that follows the seccomp rules;
    * a jailed binary that breaks the seccomp rules.
    """
    seccomp_build_path = os.path.join(
        test_fc_session_root_path, build_tools.CARGO_RELEASE_REL_PATH
    )

    extra_args = "--release --target {}-unknown-linux-musl"
    extra_args = extra_args.format(platform.machine())
    build_tools.cargo_build(
        seccomp_build_path,
        extra_args=extra_args,
        src_dir="integration_tests/security/demo_seccomp",
    )

    release_binaries_path = os.path.join(
        test_fc_session_root_path,
        build_tools.CARGO_RELEASE_REL_PATH,
        build_tools.RELEASE_BINARIES_REL_PATH,
    )

    demo_jailer = os.path.normpath(os.path.join(release_binaries_path, "demo_jailer"))
    demo_harmless = os.path.normpath(
        os.path.join(release_binaries_path, "demo_harmless")
    )
    demo_malicious = os.path.normpath(
        os.path.join(release_binaries_path, "demo_malicious")
    )
    demo_panic = os.path.normpath(os.path.join(release_binaries_path, "demo_panic"))

    yield {
        "demo_jailer": demo_jailer,
        "demo_harmless": demo_harmless,
        "demo_malicious": demo_malicious,
        "demo_panic": demo_panic,
    }


@pytest.fixture(scope="session")
def uffd_handler_paths(test_fc_session_root_path):
    """Build UFFD handler binaries."""
    uffd_build_path = os.path.join(
        test_fc_session_root_path, build_tools.CARGO_RELEASE_REL_PATH
    )

    extra_args = "--release --target {}-unknown-linux-musl"
    extra_args = extra_args.format(platform.machine())
    build_tools.cargo_build(
        uffd_build_path, extra_args=extra_args, src_dir="host_tools/uffd"
    )

    release_binaries_path = os.path.join(
        test_fc_session_root_path,
        build_tools.CARGO_RELEASE_REL_PATH,
        build_tools.RELEASE_BINARIES_REL_PATH,
    )

    valid_handler = os.path.normpath(
        os.path.join(release_binaries_path, "valid_handler")
    )

    malicious_handler = os.path.normpath(
        os.path.join(release_binaries_path, "malicious_handler")
    )

    yield {
        "valid_handler": valid_handler,
        "malicious_handler": malicious_handler,
    }


@pytest.fixture()
def microvm(test_fc_session_root_path, bin_cloner_path):
    """Instantiate a microvm."""
    # Make sure the necessary binaries are there before instantiating the
    # microvm.
    vm = init_microvm(test_fc_session_root_path, bin_cloner_path)
    yield vm
    vm.kill()
    shutil.rmtree(os.path.join(test_fc_session_root_path, vm.id))


@pytest.fixture()
def microvm_factory(tmp_path, bin_cloner_path):
    """Fixture to create microvms simply.

    tmp_path is cleaned up by pytest after 3 sessions.
    However, since we only run one session per docker container execution,
    tmp_path is never cleaned up by pytest for us.
    In order to avoid running out of space when instantiating many microvms,
    we remove the directory manually when the fixture is destroyed
    (that is after every test).
    One can comment the removal line, if it helps with debugging.
    """

    class MicroVMFactory:
        """MicroVM factory"""

        def __init__(self, tmp_path, bin_cloner):
            self.tmp_path = tmp_path
            self.bin_cloner_path = bin_cloner
            self.vms = []

        def build(self, kernel=None, rootfs=None):
            """Build a fresh microvm."""
            vm = init_microvm(self.tmp_path, self.bin_cloner_path)
            self.vms.append(vm)
            if kernel is not None:
                kernel_path = Path(kernel.local_path())
                vm.kernel_file = kernel_path
            if rootfs is not None:
                rootfs_path = Path(rootfs.local_path())
                rootfs_path2 = Path(vm.path) / rootfs_path.name
                # TBD only iff ext4 / rw
                shutil.copyfile(rootfs_path, rootfs_path2)
                vm.rootfs_file = rootfs_path2
                vm.ssh_config["ssh_key_path"] = rootfs.ssh_key().local_path()
            return vm

        def kill(self):
            """Clean up all built VMs"""
            for vm in self.vms:
                vm.kill()
            shutil.rmtree(self.tmp_path)

    uvm_factory = MicroVMFactory(tmp_path, bin_cloner_path)
    yield uvm_factory
    uvm_factory.kill()


@pytest.fixture(params=MICROVM_S3_FETCHER.list_microvm_images(capability_filter=["*"]))
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

    MICROVM_S3_FETCHER.init_vm_resources(request.param, microvm)
    yield microvm


def firecracker_id(fc):
    """Render a nice ID for pytest parametrize."""
    if isinstance(fc, FirecrackerArtifact):
        return f"firecracker-{fc.version}"
    return None


def firecracker_artifacts(*args, **kwargs):
    """Return all supported firecracker binaries."""
    params = {
        "min_version": "1.1.0",
        "max_version": get_firecracker_version_from_toml(),
    }
    params.update(kwargs)
    return ARTIFACTS_COLLECTION.firecrackers(
        *args,
        **params,
    )


@pytest.fixture(params=firecracker_artifacts(), ids=firecracker_id)
def firecracker_release(request):
    """Return all supported firecracker binaries."""
    firecracker = request.param
    firecracker.download()
    firecracker.jailer().download()
    return firecracker


@pytest.fixture(params=ARTIFACTS_COLLECTION.kernels(), ids=lambda kernel: kernel.name())
def guest_kernel(request):
    """Return all supported guest kernels."""
    kernel = request.param
    kernel.download()
    return kernel


@pytest.fixture(
    params=ARTIFACTS_COLLECTION.disks("ubuntu"), ids=lambda rootfs: rootfs.name()
)
def rootfs(request):
    """Return all supported rootfs."""
    rootfs = request.param
    rootfs.download()
    rootfs.ssh_key().download()
    return rootfs


@pytest.fixture(params=SUPPORTED_CPU_TEMPLATES)
def cpu_template(request):
    """Return all CPU templates supported by the vendor."""
    return request.param


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
    TEST_MICROVM_CAP_FIXTURE = TEST_MICROVM_CAP_FIXTURE_TEMPLATE.replace(
        "CAP", capability
    )
    # pylint: disable=exec-used
    # This is the most straightforward way to achieve this result.
    exec(TEST_MICROVM_CAP_FIXTURE)
