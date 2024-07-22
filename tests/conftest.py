# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

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
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict

import pytest

import host_tools.cargo_build as build_tools
from framework import defs, utils
from framework.artifacts import kernel_params, kernels_unfiltered, rootfs_params
from framework.microvm import MicroVMFactory
from framework.properties import global_props
from framework.utils_cpu_templates import (
    custom_cpu_templates_params,
    static_cpu_templates_params,
)
from host_tools.metrics import get_metrics_logger

# This codebase uses Python features available in Python 3.10 or above
if sys.version_info < (3, 10):
    raise SystemError("This codebase requires Python 3.10 or above.")


# Some tests create system-level resources; ensure we run as root.
if os.geteuid() != 0:
    raise PermissionError("Test session needs to be run as root.")


METRICS = get_metrics_logger()
PHASE_REPORT_KEY = pytest.StashKey[Dict[str, pytest.CollectReport]]()


def pytest_addoption(parser):
    """Pytest hook. Add command line options."""
    parser.addoption(
        "--binary-dir",
        action="store",
        help="use firecracker/jailer binaries from this directory instead of compiling from source",
    )


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):  # pylint:disable=unused-argument
    """Plugin to get test results in fixtures

    https://docs.pytest.org/en/latest/example/simple.html#making-test-result-information-available-in-fixtures
    """
    # execute all other hooks to obtain the report object
    rep = yield

    # store test results for each phase of a call, which can
    # be "setup", "call", "teardown"
    item.stash.setdefault(PHASE_REPORT_KEY, {})[rep.when] = rep

    return rep


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

    # The pytest's test protocol has three phases for each test item: setup,
    # call and teardown. At the end of each phase, pytest_runtest_logreport()
    # is called.
    # https://github.com/pytest-dev/pytest/blob/d489247505a953885a156e61d4473497cbc167ea/src/_pytest/hookspec.py#L643
    # https://github.com/pytest-dev/pytest/blob/d489247505a953885a156e61d4473497cbc167ea/src/_pytest/hookspec.py#L800
    METRICS.set_dimensions(
        # fine-grained
        {
            "test": report.nodeid,
            "instance": global_props.instance,
            "cpu_model": global_props.cpu_model,
            "host_kernel": "linux-" + global_props.host_linux_version,
            "phase": report.when,
        },
        # per test
        {
            "test": report.nodeid,
            "instance": global_props.instance,
            "cpu_model": global_props.cpu_model,
            "host_kernel": "linux-" + global_props.host_linux_version,
        },
        # per phase
        {"phase": report.when},
        # per host kernel
        {"host_kernel": "linux-" + global_props.host_linux_version},
        # per CPU
        {"cpu_model": global_props.cpu_model},
        # and global
        {},
    )
    METRICS.set_property("result", report.outcome)
    METRICS.set_property("location", report.location)
    for prop_name, prop_val in report.user_properties:
        METRICS.set_property(prop_name, prop_val)
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


@pytest.fixture
def bin_seccomp_paths():
    """Build jailers and jailed binaries to test seccomp.

    They currently consist of:

    * a jailer that receives filter generated using seccompiler-bin;
    * a jailed binary that follows the seccomp rules;
    * a jailed binary that breaks the seccomp rules.
    """
    demos = {
        f"demo_{example}": build_tools.get_example(f"seccomp_{example}")
        for example in ["jailer", "harmless", "malicious", "panic"]
    }
    yield demos


@pytest.fixture
def uffd_handler_paths():
    """Build UFFD handler binaries."""
    handlers = {
        f"{handler}_handler": build_tools.get_example(f"uffd_{handler}_handler")
        for handler in ["malicious", "valid", "fault_all"]
    }
    yield handlers


@pytest.fixture()
def microvm_factory(request, record_property, results_dir):
    """Fixture to create microvms simply.

    In order to avoid running out of space when instantiating many microvms,
    we remove the directory manually when the fixture is destroyed
    (that is after every test).
    One can comment the removal line, if it helps with debugging.
    """

    if binary_dir := request.config.getoption("--binary-dir"):
        fc_binary_path = Path(binary_dir) / "firecracker"
        jailer_binary_path = Path(binary_dir) / "jailer"
        if not fc_binary_path.exists():
            raise RuntimeError("Firecracker binary does not exist")
    else:
        fc_binary_path, jailer_binary_path = build_tools.get_firecracker_binaries()
    record_property("firecracker_bin", str(fc_binary_path))

    # We could override the chroot base like so
    # jailer_kwargs={"chroot_base": "/srv/jailo"}
    uvm_factory = MicroVMFactory(fc_binary_path, jailer_binary_path)
    yield uvm_factory

    # if the test failed, save important files from the root of the uVM into `test_results` for troubleshooting
    report = request.node.stash[PHASE_REPORT_KEY]
    if "call" in report and report["call"].failed:
        for uvm in uvm_factory.vms:
            uvm_data = results_dir / uvm.id
            uvm_data.mkdir()

            uvm_root = Path(uvm.chroot())
            for item in os.listdir(uvm_root):
                src = uvm_root / item
                if not os.path.isfile(src):
                    continue
                dst = uvm_data / item
                shutil.copy(src, dst)

    uvm_factory.kill()


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


@pytest.fixture(
    params=list(static_cpu_templates_params()) + list(custom_cpu_templates_params())
)
def cpu_template_any(request, record_property):
    """This fixture combines static and custom CPU templates"""
    if "name" in request.param:
        record_property("custom_cpu_template", request.param["name"])
    else:
        record_property("static_cpu_template", request.param)
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
# Use the unfiltered selector, since we don't officially support 6.1 yet.
# TODO: switch to default selector once we add full 6.1 support.
guest_kernel_linux_6_1 = pytest.fixture(
    guest_kernel_fxt,
    params=kernel_params("vmlinux-6.1*", select=kernels_unfiltered),
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
def uvm_plain_any(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """All guest kernels
    kernel: all
    rootfs: Ubuntu 22.04
    """
    return microvm_factory.build(guest_kernel, rootfs_ubuntu_22)


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
