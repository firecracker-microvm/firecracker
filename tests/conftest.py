# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

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
import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

import host_tools.cargo_build as build_tools
from framework import defs, utils
from framework.artifacts import disks, kernel_params
from framework.defs import DEFAULT_BINARY_DIR
from framework.microvm import MicroVMFactory
from framework.properties import global_props
from framework.utils_cpu_templates import (
    custom_cpu_templates_params,
    get_cpu_template_name,
    static_cpu_templates_params,
)
from host_tools.metrics import get_metrics_logger
from host_tools.network import NetNs

# This codebase uses Python features available in Python 3.10 or above
if sys.version_info < (3, 10):
    raise SystemError("This codebase requires Python 3.10 or above.")


# Some tests create system-level resources; ensure we run as root.
if os.geteuid() != 0:
    raise PermissionError("Test session needs to be run as root.")


METRICS = get_metrics_logger()
PHASE_REPORT_KEY = pytest.StashKey[dict[str, pytest.CollectReport]]()


def pytest_addoption(parser):
    """Pytest hook. Add command line options."""
    parser.addoption(
        "--binary-dir",
        action="store",
        help="use firecracker/jailer binaries from this directory instead of compiling from source",
    )

    parser.addoption(
        "--custom-cpu-template",
        action="store",
        help="Path to custom CPU template to be applied unless overwritten by a test",
        default=None,
        type=Path,
    )


def pytest_report_header():
    """Pytest hook to print relevant metadata in the logs"""
    return f"EC2 AMI: {global_props.ami}"


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
    record_property("description", function_docstring)


def pytest_runtest_logreport(report):
    """Send general test metrics to CloudWatch"""

    # only publish metrics from the main process
    worker_id = os.environ.get("PYTEST_XDIST_WORKER")
    if worker_id is not None:
        return

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
    METRICS.set_property("pytest_xdist_worker", worker_id)
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


@pytest.fixture(scope="session")
def netns_factory(worker_id):
    """A network namespace factory

    Network namespaces are created once per test session and re-used in subsequent tests.
    """
    # pylint:disable=protected-access

    class NetNsFactory:
        """A Network namespace factory that reuses namespaces."""

        def __init__(self, prefix: str):
            self._all = []
            self._returned = []
            self.prefix = prefix

        def get(self, _netns_id):
            """Get a free network namespace"""
            if len(self._returned) > 0:
                ns = self._returned.pop(0)
                while ns.is_used():
                    pass
                return ns
            ns = NetNs(self.prefix + str(len(self._all)))
            # change the cleanup function so it is returned to the pool
            ns._cleanup_orig = ns.cleanup
            ns.cleanup = lambda: self._returned.append(ns)
            self._all.append(ns)
            return ns

    netns_fcty = NetNsFactory(f"netns-{worker_id}-")
    yield netns_fcty.get

    for netns in netns_fcty._all:
        netns._cleanup_orig()


@pytest.fixture()
def microvm_factory(request, record_property, results_dir, netns_factory):
    """Fixture to create microvms simply."""

    binary_dir = request.config.getoption("--binary-dir") or DEFAULT_BINARY_DIR
    if isinstance(binary_dir, str):
        binary_dir = Path(binary_dir)

    record_property("firecracker_bin", str(binary_dir / "firecracker"))

    # If `--custom-cpu-template` option is provided, the given CPU template will
    # be applied afterwards unless overwritten.
    custom_cpu_template_path = request.config.getoption("--custom-cpu-template")
    custom_cpu_template = (
        {
            "name": custom_cpu_template_path.stem,
            "template": json.loads(custom_cpu_template_path.read_text("utf-8")),
        }
        if custom_cpu_template_path
        else None
    )
    # We could override the chroot base like so
    # jailer_kwargs={"chroot_base": "/srv/jailo"}
    uvm_factory = MicroVMFactory(
        binary_dir,
        netns_factory=netns_factory,
        custom_cpu_template=custom_cpu_template,
    )
    yield uvm_factory

    # if the test failed, save important files from the root of the uVM into `test_results` for troubleshooting
    report = request.node.stash[PHASE_REPORT_KEY]
    if "call" in report and report["call"].failed:
        for uvm in uvm_factory.vms:
            uvm_data = results_dir / uvm.id
            uvm_data.mkdir()
            uvm_data.joinpath("host-dmesg.log").write_text(
                utils.run_cmd(["dmesg", "-dPx"]).stdout
            )
            shutil.copy(f"/firecracker/build/img/{platform.machine()}/id_rsa", uvm_data)

            uvm_root = Path(uvm.chroot())
            for item in os.listdir(uvm_root):
                src = uvm_root / item
                if not os.path.isfile(src):
                    continue
                dst = uvm_data / item
                shutil.move(src, dst)
                console_data = uvm.console_data
                if console_data:
                    uvm_data.joinpath("guest-console.log").write_text(console_data)

    uvm_factory.kill()


@pytest.fixture(params=custom_cpu_templates_params())
def custom_cpu_template(request, record_property):
    """Return all dummy custom CPU templates supported by the vendor."""
    record_property("custom_cpu_template", request.param["name"])
    return request.param


@pytest.fixture(
    params=[
        pytest.param(None, id="NO_CPU_TMPL"),
        *static_cpu_templates_params(),
        *custom_cpu_templates_params(),
    ],
)
def cpu_template_any(request, record_property):
    """This fixture combines no template, static and custom CPU templates"""
    record_property(
        "cpu_template", get_cpu_template_name(request.param, with_type=True)
    )
    return request.param


@pytest.fixture(params=["Sync", "Async"])
def io_engine(request):
    """All supported io_engines"""
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


# Fixtures for all guest kernels, and specific versions
guest_kernel = pytest.fixture(guest_kernel_fxt, params=kernel_params("vmlinux-*"))
guest_kernel_acpi = pytest.fixture(
    guest_kernel_fxt,
    params=filter(
        lambda kernel: "no-acpi" not in kernel.id, kernel_params("vmlinux-*")
    ),
)
guest_kernel_linux_5_10 = pytest.fixture(
    guest_kernel_fxt,
    params=filter(
        lambda kernel: "no-acpi" not in kernel.id, kernel_params("vmlinux-5.10*")
    ),
)
guest_kernel_linux_6_1 = pytest.fixture(
    guest_kernel_fxt,
    params=kernel_params("vmlinux-6.1*"),
)


@pytest.fixture
def rootfs():
    """Return an Ubuntu 24.04 read-only rootfs"""
    return disks("ubuntu-24.04.squashfs")[0]


@pytest.fixture
def rootfs_rw():
    """Return an Ubuntu 24.04 ext4 rootfs"""
    return disks("ubuntu-24.04.ext4")[0]


@pytest.fixture
def uvm_plain(microvm_factory, guest_kernel_linux_5_10, rootfs):
    """Create a vanilla VM, non-parametrized"""
    return microvm_factory.build(guest_kernel_linux_5_10, rootfs)


@pytest.fixture
def uvm_plain_rw(microvm_factory, guest_kernel_linux_5_10, rootfs_rw):
    """Create a vanilla VM, non-parametrized"""
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
def uvm_plain_any(microvm_factory, guest_kernel, rootfs):
    """All guest kernels
    kernel: all
    rootfs: Ubuntu 24.04
    """
    return microvm_factory.build(guest_kernel, rootfs)


guest_kernel_6_1_debug = pytest.fixture(
    guest_kernel_fxt,
    params=kernel_params("vmlinux-6.1*", artifact_dir=defs.ARTIFACT_DIR / "debug"),
)


@pytest.fixture
def uvm_plain_debug(microvm_factory, guest_kernel_6_1_debug, rootfs_rw):
    """VM running a kernel with debug/trace Kconfig options"""
    return microvm_factory.build(guest_kernel_6_1_debug, rootfs_rw)


@pytest.fixture
def vcpu_count():
    """Return default vcpu_count. Use indirect parametrization to override."""
    return 2


@pytest.fixture
def mem_size_mib():
    """Return memory size. Use indirect parametrization to override."""
    return 256


def uvm_booted(
    microvm_factory, guest_kernel, rootfs, cpu_template, vcpu_count=2, mem_size_mib=256
):
    """Return a booted uvm"""
    uvm = microvm_factory.build(guest_kernel, rootfs)
    uvm.spawn()
    uvm.basic_config(vcpu_count=vcpu_count, mem_size_mib=mem_size_mib)
    uvm.set_cpu_template(cpu_template)
    uvm.add_net_iface()
    uvm.start()
    return uvm


def uvm_restored(microvm_factory, guest_kernel, rootfs, cpu_template, **kwargs):
    """Return a restored uvm"""
    uvm = uvm_booted(microvm_factory, guest_kernel, rootfs, cpu_template, **kwargs)
    snapshot = uvm.snapshot_full()
    uvm.kill()
    uvm2 = microvm_factory.build_from_snapshot(snapshot)
    uvm2.cpu_template_name = uvm.cpu_template_name
    return uvm2


@pytest.fixture(params=[uvm_booted, uvm_restored])
def uvm_ctor(request):
    """Fixture to return uvms with different constructors"""
    return request.param


@pytest.fixture
def uvm_any(
    microvm_factory,
    uvm_ctor,
    guest_kernel,
    rootfs,
    cpu_template_any,
    vcpu_count,
    mem_size_mib,
):
    """Return booted and restored uvms"""
    return uvm_ctor(
        microvm_factory,
        guest_kernel,
        rootfs,
        cpu_template_any,
        vcpu_count=vcpu_count,
        mem_size_mib=mem_size_mib,
    )


@pytest.fixture
def uvm_any_booted(
    microvm_factory, guest_kernel, rootfs, cpu_template_any, vcpu_count, mem_size_mib
):
    """Return booted uvms"""
    return uvm_booted(
        microvm_factory,
        guest_kernel,
        rootfs,
        cpu_template_any,
        vcpu_count=vcpu_count,
        mem_size_mib=mem_size_mib,
    )
