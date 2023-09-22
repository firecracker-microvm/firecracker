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
  creating a fixture that references some local paths

# Notes

- Reading up on pytest fixtures is probably needed when editing this file.
  https://docs.pytest.org/en/7.2.x/explanation/fixtures.html
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
from framework.artifacts import firecracker_artifacts, kernel_params, rootfs_params
from framework.microvm import MicroVMFactory
from framework.properties import global_props
from framework.utils_cpu_templates import (
    custom_cpu_templates_params,
    static_cpu_templates_params,
)
from host_tools.ip_generator import network_config, subnet_generator
from host_tools.metrics import get_metrics_logger

# This codebase uses Python features available in Python 3.10 or above
if sys.version_info < (3, 10):
    raise SystemError("This codebase requires Python 3.10 or above.")


# Some tests create system-level resources; ensure we run as root.
if os.geteuid() != 0:
    raise PermissionError("Test session needs to be run as root.")


METRICS = get_metrics_logger()


def pytest_addoption(parser):
    """Pytest hook. Add command line options."""
    parser.addoption(
        "--perf-fail",
        action="store_true",
        help="fail the test if the baseline does not match",
    )
    parser.addoption(
        "--binary-dir",
        action="store",
        help="use firecracker/jailer binaries from this directory instead of compiling from source",
    )


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
    seccomp_build_path = (
        Path(test_fc_session_root_path) / build_tools.CARGO_RELEASE_REL_PATH
    )
    release_binaries_path = seccomp_build_path / build_tools.RELEASE_BINARIES_REL_PATH

    seccomp_examples = ["jailer", "harmless", "malicious", "panic"]

    demos = {}

    for example in seccomp_examples:
        build_tools.cargo_build(
            seccomp_build_path,
            f"--release --target {platform.machine()}-unknown-linux-musl --example seccomp_{example}",
        )

        demos[f"demo_{example}"] = release_binaries_path / f"examples/seccomp_{example}"

    yield demos


@pytest.fixture(scope="session")
def uffd_handler_paths(test_fc_session_root_path):
    """Build UFFD handler binaries."""
    uffd_build_path = (
        Path(test_fc_session_root_path) / build_tools.CARGO_RELEASE_REL_PATH
    )
    release_binaries_path = uffd_build_path / build_tools.RELEASE_BINARIES_REL_PATH

    uffd_handlers = ["malicious", "valid"]

    handlers = {}

    for handler in uffd_handlers:
        build_tools.cargo_build(
            uffd_build_path,
            f"--release --target {platform.machine()}-unknown-linux-musl --example uffd_{handler}_handler",
        )

        handlers[f"{handler}_handler"] = (
            release_binaries_path / f"examples/uffd_{handler}_handler"
        )

    yield handlers


@pytest.fixture()
def fc_tmp_path(test_fc_session_root_path):
    """A tmp_path substitute

    We should use pytest's tmp_path fixture instead of this, but this can create
    very long paths, which can run into the UDS 108 character limit.
    """
    return Path(tempfile.mkdtemp(dir=test_fc_session_root_path))


@pytest.fixture()
def microvm_factory(fc_tmp_path, bin_cloner_path, request):
    """Fixture to create microvms simply.

    In order to avoid running out of space when instantiating many microvms,
    we remove the directory manually when the fixture is destroyed
    (that is after every test).
    One can comment the removal line, if it helps with debugging.
    """

    if binary_dir := request.config.getoption("--binary-dir"):
        fc_binary_path = Path(binary_dir) / "firecracker"
        jailer_binary_path = Path(binary_dir) / "jailer"
    else:
        fc_binary_path, jailer_binary_path = build_tools.get_firecracker_binaries()

    uvm_factory = MicroVMFactory(
        fc_tmp_path, bin_cloner_path, fc_binary_path, jailer_binary_path
    )
    yield uvm_factory
    uvm_factory.kill()
    shutil.rmtree(fc_tmp_path)


@pytest.fixture(params=firecracker_artifacts())
def firecracker_release(request, record_property):
    """Return all supported firecracker binaries."""
    firecracker = request.param
    record_property("firecracker_release", firecracker.name)
    return firecracker


@pytest.fixture(params=static_cpu_templates_params())
def cpu_template(request, record_property):
    """Return all static CPU templates supported by the vendor."""
    record_property("static_cpu_template", request.param)
    return request.param


@pytest.fixture(params=custom_cpu_templates_params())
def custom_cpu_template(request, record_property):
    """Return all dummy custom CPU templates supported by the vendor."""
    record_property("custom_cpu_template", request.param["name"])
    return request.param


@pytest.fixture(params=["Sync", "Async"])
def io_engine(request):
    """All supported io_engines"""
    if request.param == "Async" and not utils.is_io_uring_supported():
        pytest.skip("io_uring not supported in this kernel")
    return request.param


@pytest.fixture
def results_dir(request):
    """
    Fixture yielding the path to a directory into which the test can dump its results

    Directories are unique per test, and named after the test name. Everything the tests puts
    into its directory will to be uploaded to S3. Directory will be placed inside defs.TEST_RESULTS_DIR.

    For example
    ```py
    def test_my_file(results_dir):
        (results_dir / "output.txt").write_text("Hello World")
    ```
    will result in `defs.TEST_RESULTS_DIR`/test_my_file/output.txt.
    """
    results_dir = defs.TEST_RESULTS_DIR / request.node.originalname
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir


def guest_kernel_fxt(request, record_property):
    """Return all supported guest kernels."""
    kernel = request.param
    # vmlinux-5.10.167 -> linux-5.10
    prop = kernel.stem[2:]
    record_property("guest_kernel", prop)
    return kernel


def rootfs_fxt(request, record_property):
    """Return all supported rootfs."""
    fs = request.param
    record_property("rootfs", fs.name)
    return fs


# Fixtures for all guest kernels, and specific versions
guest_kernel = pytest.fixture(guest_kernel_fxt, params=kernel_params("vmlinux-*"))
guest_kernel_linux_4_14 = pytest.fixture(
    guest_kernel_fxt, params=kernel_params("vmlinux-4.14*")
)
guest_kernel_linux_5_10 = pytest.fixture(
    guest_kernel_fxt, params=kernel_params("vmlinux-5.10*")
)

# Fixtures for all Ubuntu rootfs, and specific versions
rootfs = pytest.fixture(rootfs_fxt, params=rootfs_params("*.squashfs"))
rootfs_ubuntu_22 = pytest.fixture(
    rootfs_fxt, params=rootfs_params("ubuntu-22*.squashfs")
)
rootfs_rw = pytest.fixture(rootfs_fxt, params=rootfs_params("*.ext4"))


@pytest.fixture
def uvm_plain(microvm_factory, guest_kernel_linux_5_10, rootfs_ubuntu_22):
    """Create a vanilla VM, non-parametrized
    kernel: 5.10
    rootfs: Ubuntu 22.04
    """
    return microvm_factory.build(guest_kernel_linux_5_10, rootfs_ubuntu_22)


@pytest.fixture
def uvm_plain_rw(microvm_factory, guest_kernel_linux_5_10, rootfs_rw):
    """Create a vanilla VM, non-parametrized
    kernel: 5.10
    rootfs: Ubuntu 22.04
    """
    return microvm_factory.build(guest_kernel_linux_5_10, rootfs_rw)


@pytest.fixture
def uvm_nano(uvm_plain):
    """A preconfigured uvm with 2vCPUs and 256MiB of memory
    ready to .start()
    """
    uvm_plain.spawn()
    uvm_plain.basic_config(vcpu_count=2, mem_size_mib=256)
    return uvm_plain


@pytest.fixture()
def artifact_dir():
    """Return the location of the CI artifacts"""
    return defs.ARTIFACT_DIR


@pytest.fixture
def uvm_with_initrd(
    microvm_factory, guest_kernel_linux_5_10, record_property, artifact_dir
):
    """
    See file:../docs/initrd.md
    """
    fs = artifact_dir / "initramfs.cpio"
    record_property("rootfs", fs.name)
    uvm = microvm_factory.build(guest_kernel_linux_5_10)
    uvm.initrd_file = fs
    yield uvm


# backwards compatibility
test_microvm_with_api = uvm_plain
