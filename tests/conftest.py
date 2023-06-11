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
import os
import platform
import re
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

import host_tools.cargo_build as build_tools
from framework import defs, utils
from framework.artifacts import ArtifactCollection, DiskArtifact, FirecrackerArtifact
from framework.defs import _test_images_s3_bucket
from framework.microvm import Microvm
from framework.properties import global_props
from framework.s3fetcher import MicrovmImageS3Fetcher
from framework.utils import get_firecracker_version_from_toml, is_io_uring_supported
from framework.utils_cpu_templates import (
    SUPPORTED_CPU_TEMPLATES,
    SUPPORTED_CUSTOM_CPU_TEMPLATES,
)
from host_tools.ip_generator import network_config, subnet_generator
from host_tools.metrics import get_metrics_logger

# Tests root directory.
SCRIPT_FOLDER = os.path.dirname(os.path.realpath(__file__))

# This codebase uses Python features available in Python 3.10 or above
if sys.version_info < (3, 10):
    raise SystemError("This codebase requires Python 3.10 or above.")


# Some tests create system-level resources; ensure we run as root.
if os.geteuid() != 0:
    raise PermissionError("Test session needs to be run as root.")


ARTIFACTS_COLLECTION = ArtifactCollection(_test_images_s3_bucket())
MICROVM_S3_FETCHER = MicrovmImageS3Fetcher(_test_images_s3_bucket())
METRICS = get_metrics_logger()


@pytest.fixture(scope="function", autouse=True)
def record_props(request, record_property):
    """Decorate test results with additional properties.

    Note: there is no need to call this fixture explicitly
    """
    # Augment test result with global properties
    for prop_name, prop_val in global_props.__dict__.items():
        # if record_testsuite_property worked with xdist we could use that
        # https://docs.pytest.org/en/7.1.x/reference/reference.html#record-testsuite-property
        # to record the properties once per report. But here we record each
        # prop per test. It just results in larger report files.
        record_property(prop_name, prop_val)

    # Extract attributes from the docstrings
    function_docstring = inspect.getdoc(request.function)
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
        record_property(attr_name, attr_value)
    record_property("description", "".join(description))


def pytest_runtest_logreport(report):
    """Send general test metrics to CloudWatch"""
    if report.when == "call":
        dimensions = {
            "test": report.nodeid,
            "instance": global_props.instance,
            "cpu_model": global_props.cpu_model,
            "host_kernel": "linux-" + global_props.host_linux_version,
        }
        METRICS.set_property("result", report.outcome)
        METRICS.set_property("location", report.location)
        for prop_name, prop_val in report.user_properties:
            METRICS.set_property(prop_name, prop_val)
        METRICS.set_dimensions(dimensions)
        METRICS.put_metric(
            "duration",
            report.duration,
            unit="Seconds",
        )
        METRICS.put_metric(
            "failed",
            1 if report.outcome == "failed" else 0,
            unit="Count",
        )
        METRICS.flush()


@pytest.fixture()
def metrics(request):
    """Fixture to pass the metrics scope

    We use a fixture instead of the @metrics_scope decorator as that conflicts
    with tests.

    Due to how aws-embedded-metrics works, this fixture is per-test rather
    than per-session, and we flush the metrics after each test.

    Ref: https://github.com/awslabs/aws-embedded-metrics-python
    """
    metrics_logger = get_metrics_logger()
    for prop_name, prop_val in request.node.user_properties:
        metrics_logger.set_property(prop_name, prop_val)
    yield metrics_logger
    metrics_logger.flush()


@pytest.fixture
def record_property(record_property, metrics):
    """Override pytest's record_property to also set a property in our metrics context."""

    def sub(key, value):
        record_property(key, value)
        metrics.set_property(key, value)

    return sub


@pytest.fixture(autouse=True, scope="session")
def test_fc_session_root_path():
    """Ensure and yield the fc session root directory.

    Create a unique temporary session directory. This is important, since the
    scheduler will run multiple pytest sessions concurrently.
    """
    os.makedirs(defs.DEFAULT_TEST_SESSION_ROOT_PATH, exist_ok=True)
    fc_session_root_path = tempfile.mkdtemp(
        prefix="fctest-", dir=defs.DEFAULT_TEST_SESSION_ROOT_PATH
    )
    yield fc_session_root_path
    shutil.rmtree(fc_session_root_path)


@pytest.fixture(scope="session")
def bin_cloner_path(test_fc_session_root_path):
    """Build a binary that `clone`s into the jailer.

    It's necessary because Python doesn't interface well with the `clone()`
    syscall directly.
    """
    cloner_bin_path = os.path.join(test_fc_session_root_path, "newpid_cloner")
    build_tools.gcc_compile("host_tools/newpid_cloner.c", cloner_bin_path)
    yield cloner_bin_path


@pytest.fixture(scope="session")
def bin_vsock_path(test_fc_session_root_path):
    """Build a simple vsock client/server application."""
    vsock_helper_bin_path = os.path.join(test_fc_session_root_path, "vsock_helper")
    build_tools.gcc_compile("host_tools/vsock_helper.c", vsock_helper_bin_path)
    yield vsock_helper_bin_path


@pytest.fixture(scope="session")
def change_net_config_space_bin(test_fc_session_root_path):
    """Build a binary that changes the MMIO config space."""
    change_net_config_space_bin = os.path.join(
        test_fc_session_root_path, "change_net_config_space"
    )
    build_tools.gcc_compile(
        "host_tools/change_net_config_space.c",
        change_net_config_space_bin,
        extra_flags="-static",
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
    vm = Microvm(
        resource_path=test_fc_session_root_path,
        bin_cloner_path=bin_cloner_path,
    )
    yield vm
    vm.kill()
    shutil.rmtree(os.path.join(test_fc_session_root_path, vm.id))


@pytest.fixture
def fc_tmp_path(test_fc_session_root_path):
    """A tmp_path substitute

    We should use pytest's tmp_path fixture instead of this, but this can create
    very long paths, which can run into the UDS 108 character limit.
    """
    return Path(tempfile.mkdtemp(dir=test_fc_session_root_path))


@pytest.fixture()
def microvm_factory(fc_tmp_path, bin_cloner_path):
    """Fixture to create microvms simply.

    In order to avoid running out of space when instantiating many microvms,
    we remove the directory manually when the fixture is destroyed
    (that is after every test).
    One can comment the removal line, if it helps with debugging.
    """

    class MicroVMFactory:
        """MicroVM factory"""

        def __init__(self, tmp_path, bin_cloner):
            self.tmp_path = Path(tmp_path)
            self.bin_cloner_path = bin_cloner
            self.vms = []

        def build(self, kernel=None, rootfs=None, **kwargs):
            """Build a microvm"""
            vm = Microvm(
                resource_path=self.tmp_path,
                bin_cloner_path=self.bin_cloner_path,
                **kwargs,
            )
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

    uvm_factory = MicroVMFactory(fc_tmp_path, bin_cloner_path)
    yield uvm_factory
    uvm_factory.kill()


def firecracker_id(fc):
    """Render a nice ID for pytest parametrize."""
    if isinstance(fc, FirecrackerArtifact):
        return f"firecracker-{fc.version}"
    return None


def firecracker_artifacts(*args, **kwargs):
    """Return all supported firecracker binaries."""
    version = get_firecracker_version_from_toml()
    # until the next minor version (but not including)
    max_version = (version.major, version.minor + 1, 0)
    params = {
        "min_version": "1.2.0",
        "max_version_open": ".".join(str(x) for x in max_version),
    }
    params.update(kwargs)
    return ARTIFACTS_COLLECTION.firecrackers(*args, **params)


@pytest.fixture(params=firecracker_artifacts(), ids=firecracker_id)
def firecracker_release(request, record_property):
    """Return all supported firecracker binaries."""
    firecracker = request.param
    firecracker.download(perms=0o555)
    firecracker.jailer().download(perms=0o555)
    record_property("firecracker_release", firecracker.version)
    return firecracker


@pytest.fixture(params=ARTIFACTS_COLLECTION.kernels(), ids=lambda kernel: kernel.name())
def guest_kernel(request, record_property):
    """Return all supported guest kernels."""
    kernel = request.param
    # linux-major.minor
    kernel.prop = "linux-" + kernel.name().removesuffix(".bin").split("-")[-1]
    record_property("guest_kernel", kernel.prop)
    kernel.download()
    return kernel


@pytest.fixture(params=ARTIFACTS_COLLECTION.disks("ubuntu"), ids=lambda fs: fs.name())
def rootfs(request, record_property):
    """Return all supported rootfs."""
    fs = request.param
    record_property("rootfs", fs.name())
    fs.download()
    fs.ssh_key().download()
    return fs


@pytest.fixture(
    params=ARTIFACTS_COLLECTION.disks("bionic-msrtools"),
    ids=lambda fs: fs.name() if isinstance(fs, DiskArtifact) else None,
)
def rootfs_msrtools(request, record_property):
    """Common disk fixture for tests needing msrtools

    When we regenerate the rootfs, we should include this always
    """
    fs = request.param
    record_property("rootfs", fs.name())
    fs.download()
    fs.ssh_key().download()
    return fs


@pytest.fixture(params=SUPPORTED_CPU_TEMPLATES)
def cpu_template(request, record_property):
    """Return all CPU templates supported by the vendor."""
    record_property("cpu_template", request.param)
    return request.param


@pytest.fixture(params=SUPPORTED_CUSTOM_CPU_TEMPLATES)
def custom_cpu_template(request, record_property):
    """Return all dummy custom CPU templates supported by the vendor."""
    record_property("custom_cpu_template", request.param)
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


@pytest.fixture(params=["Sync", "Async"])
def io_engine(request):
    """All supported io_engines"""
    if request.param == "Async" and not is_io_uring_supported():
        pytest.skip("io_uring not supported in this kernel")
    return request.param
