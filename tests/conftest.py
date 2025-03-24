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

import ctypes
import inspect
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

import host_tools.cargo_build as build_tools
from framework import defs, utils
from framework.artifacts import ALL_GUEST_KERNELS, disks
from framework.defs import ARTIFACT_DIR, DEFAULT_BINARY_DIR
from framework.microvm import HugePagesConfig, MicroVMFactory, SnapshotType
from framework.properties import global_props
from framework.utils_cpu_templates import get_cpu_template_name
from host_tools.metrics import get_metrics_logger
from host_tools.network import NetNs

# This codebase uses Python features available in Python 3.10 or above
if sys.version_info < (3, 10):
    raise SystemError("This codebase requires Python 3.10 or above.")


# Some tests create system-level resources; ensure we run as root.
if os.geteuid() != 0:
    raise PermissionError("Test session needs to be run as root.")


# Become a child subreaper so that orphaned descendants (Firecracker, after
# its jailer parent exits) reparent to us instead of init. This lets us
# waitpid() on the firecracker PID directly, avoiding the pidfd notification
# race for multi-threaded processes on kernels older than 6.15.
_PR_SET_CHILD_SUBREAPER = 36
_libc = ctypes.CDLL("libc.so.6", use_errno=True)
if _libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER) failed")


def reap_orphaned_children():
    """Reap descendants that have reparented to this subreaper session.

    Non-blocking; safe to call repeatedly. Returns the number reaped.
    """
    reaped = 0
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            break
        reaped += 1
    return reaped


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
    return "\n".join(
        [
            f"EC2 AMI: {global_props.ami}",
            f"EC2 Instance ID: {global_props.instance_id}",
        ]
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
    record_property("description", function_docstring)


@pytest.fixture(scope="function")
def reap_orphans():
    """Reap orphaned descendants after each test.

    Teardown runs after the microVM is killed because `microvm_factory`
    depends on this fixture (fixtures finalize in reverse setup order).
    """
    yield
    reap_orphaned_children()


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
            "host_kernel": "linux-" + global_props.host_linux_version_metrics,
            "phase": report.when,
        },
        # per test
        {
            "test": report.nodeid,
            "instance": global_props.instance,
            "cpu_model": global_props.cpu_model,
            "host_kernel": "linux-" + global_props.host_linux_version_metrics,
        },
        # per coarse-grained test name, dropping parameters and other dimensions to reduce metric count for dashboard
        # Note: noideid is formatted as below
        # - with parameters: "path/to/test.py::test_name[parameter0,parameter1]"
        # - without parameters: "path/to/test.py::test_name"
        {
            "test_name": report.nodeid.split("[")[0],
        },
        # per phase
        {"phase": report.when},
        # per host kernel
        {"host_kernel": "linux-" + global_props.host_linux_version_metrics},
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
def metrics(results_dir, request):
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
    if results_dir:
        metrics_logger.store_data(results_dir)


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
def bin_sysgenid_path(test_fc_session_root_path):
    """Build a simple util for test SysGenID device"""
    sysgenid_helper_bin_path = os.path.join(test_fc_session_root_path, "sysgenid")
    build_tools.gcc_compile("host_tools/sysgenid.c", sysgenid_helper_bin_path)
    yield sysgenid_helper_bin_path


@pytest.fixture(scope="session")
def bin_vmclock_path(test_fc_session_root_path):
    """Build a simple util for test VMclock device"""
    vmclock_helper_bin_path = os.path.join(test_fc_session_root_path, "vmclock")
    build_tools.gcc_compile("host_tools/vmclock.c", vmclock_helper_bin_path)
    yield vmclock_helper_bin_path


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
def devmem_bin(test_fc_session_root_path):
    """Build a minimal /dev/mem read/write tool."""
    bin_path = os.path.join(test_fc_session_root_path, "devmem")
    build_tools.gcc_compile(
        "host_tools/devmem.c",
        bin_path,
        extra_flags="-static",
    )
    yield bin_path


@pytest.fixture(scope="session")
def waitpkg_bin(test_fc_session_root_path):
    """Build a binary that attempts to use WAITPKG (UMONITOR / UMWAIT)"""
    waitpkg_bin_path = os.path.join(test_fc_session_root_path, "waitpkg")
    build_tools.gcc_compile(
        "host_tools/waitpkg.c",
        waitpkg_bin_path,
        extra_flags="-mwaitpkg",
    )
    yield waitpkg_bin_path


@pytest.fixture(scope="session")
def msr_reader_bin(test_fc_session_root_path):
    """Build a binary that reads msrs"""
    msr_reader_bin_path = os.path.join(test_fc_session_root_path, "msr_reader")
    build_tools.gcc_compile(
        "data/msr/msr_reader.c",
        msr_reader_bin_path,
    )
    yield msr_reader_bin_path


@pytest.fixture(scope="session")
def jailer_time_bin(test_fc_session_root_path):
    """Build a binary that fakes fc"""
    jailer_time_bin_path = os.path.join(test_fc_session_root_path, "jailer_time")
    build_tools.gcc_compile(
        "host_tools/jailer_time.c",
        jailer_time_bin_path,
    )
    yield jailer_time_bin_path


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
# pylint: disable=unused-argument
def microvm_factory(request, record_property, results_dir, netns_factory, reap_orphans):
    """Fixture to create microvms simply.

    `reap_orphans` is requested only for teardown ordering (reaping runs
    after the VMs are killed), so it is intentionally not referenced in
    the body.
    """

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
        dump_full = os.environ.get("FC_TEST_DUMP_ON_FAILURE") == "1"
        for uvm in uvm_factory.vms:
            # This is best effort. We want to proceed even if the VM is not responding.
            try:
                uvm.flush_metrics()
            except:  # pylint: disable=bare-except
                pass

            uvm_data = results_dir / uvm.id
            uvm_data.mkdir()
            uvm_data.joinpath("host-dmesg.log").write_text(
                utils.run_cmd(["dmesg", "-dPx"]).stdout
            )
            if Path(uvm.screen_log).exists():
                shutil.copy(uvm.screen_log, uvm_data)

            if not dump_full:
                continue

            try:
                uvm.snapshot_full(
                    mem_path="post_failure.mem", vmstate_path="post_failure.vmstate"
                )
            except:  # pylint: disable=bare-except
                pass

            shutil.copy(ARTIFACT_DIR / "id_rsa", uvm_data)

            uvm_root = Path(uvm.chroot())
            for item in os.listdir(uvm_root):
                src = uvm_root / item
                if not os.path.isfile(src):
                    continue
                dst = uvm_data / item
                shutil.copy(src, dst)

    uvm_factory.kill()


@pytest.fixture
def cpu_template(request, record_property):
    """CPU template applied to the VM in `uvm_configured`. Default: None.

    Override with parametrize("cpu_template", ALL_CPU_TEMPLATES |
    STATIC_CPU_TEMPLATES | CUSTOM_CPU_TEMPLATES | [<dict>], indirect=True),
    or use `@pin_cpu_template(...)`.
    """
    template = getattr(request, "param", None)
    record_property("cpu_template", get_cpu_template_name(template, with_type=True))
    return template


@pytest.fixture(params=["Sync", "Async"])
def io_engine(request):
    """All supported io_engines"""
    return request.param


@pytest.fixture(
    params=[SnapshotType.DIFF, SnapshotType.DIFF_MINCORE, SnapshotType.FULL]
)
def snapshot_type(request):
    """All possible snapshot types"""
    return request.param


secret_free_test_cases = [False]
if (
    global_props.host_linux_version_metrics == "next"
    and global_props.instance != "m6g.metal"
):
    secret_free_test_cases.append(True)


@pytest.fixture(params=secret_free_test_cases)
def secret_free(request):
    """Supported secret hiding configuration, based on hardware"""
    return request.param


@pytest.fixture
def results_dir(request, pytestconfig):
    """
    Fixture yielding the path to a directory into which the test can dump its results

    Directories are unique per test, and their names include test name and test parameters.
    Everything the tests puts into its directory will to be uploaded to S3.
    Directory will be placed inside defs.TEST_RESULTS_DIR.

    For example
    ```py
    @pytest.mark.parametrize("p", ["a", "b"])
    def test_my_file(p, results_dir):
        (results_dir / "output.txt").write_text("Hello World")
    ```
    will result in:
    - `defs.TEST_RESULTS_DIR`/test_my_file/test_my_file[a]/output.txt.
    - `defs.TEST_RESULTS_DIR`/test_my_file/test_my_file[b]/output.txt.

    When this fixture is called with DoctestItem as a request.node
    during doc tests, it will return None.
    """
    try:
        report_file = pytestconfig.getoption("--json-report-file")
        parent = Path(report_file).parent.absolute()
        results_dir = parent / request.node.originalname / request.node.name
    except AttributeError:
        return None
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir


@pytest.fixture
def artifact_dir():
    """Return the location of the CI artifacts"""
    return defs.ARTIFACT_DIR


@pytest.fixture
def vcpu_count(request):
    """Return default vcpu_count. Use indirect parametrization to override."""
    return getattr(request, "param", 2)


@pytest.fixture
def mem_size_mib(request):
    """Return memory size. Use indirect parametrization to override."""
    return getattr(request, "param", 256)


@pytest.fixture(params=[True, False], ids=["PCI_ON", "PCI_OFF"])
def pci_enabled(request):
    """Fixture that allows configuring whether a microVM will have PCI enabled or not"""
    yield request.param


@pytest.fixture
def huge_pages(request):
    """Fixture that allows configuring whether a microVM will have huge pages enabled or not"""
    return getattr(request, "param", HugePagesConfig.NONE)


# =============================================================================
# Composable uvm fixture system
# =============================================================================
#
# Tests get a microVM by requesting one of:
#
#   uvm             — a built (chroot only) microVM
#   uvm_configured  — spawned + basic_config + cpu_template applied
#   uvm_booted      — uvm_configured + add_net_iface + start (ready to ssh)
#   uvm_restored    — uvm_booted, snapshotted, restored from the snapshot
#   uvm_any         — booted or restored, parametrized via `uvm_lifecycle`
#
# Each consumer fixture is composed from independent dimension fixtures with
# defaults baked into their bodies. Override a dim with
# `@pytest.mark.parametrize(<dim>, [...], indirect=True)` or use the helpers
# from `framework.artifacts` (`pin_guest_kernel`, `pin_rootfs_mode`,
# `pin_pci`, `pin_cpu_template`).
#
# Module-level `pytestmark` works for tests that don't override that same
# dim per-test — pytest's parametrize markers do NOT merge: a pytestmark +
# per-test parametrize on the same argname raises "duplicate parametrization".
#
# Dimensions:
#   guest_kernel  Path to a guest kernel artifact              auto-multiplied
#                                                              over ALL_GUEST_KERNELS
#   rootfs_mode   "ro" | "rw"                                  default "ro"
#   rootfs        Path to a rootfs disk, composed from         (composed)
#                 guest_kernel + rootfs_mode (Ubuntu for 5.10, AL2023 otherwise)
#   pci_enabled   True / False                                 auto-multiplied
#   cpu_template  None | static name | custom dict             default None
#   huge_pages    HugePagesConfig                              default NONE
#   vcpu_count    int                                          default 2
#   mem_size_mib  int                                          default 256


@pytest.fixture(params=ALL_GUEST_KERNELS)
def guest_kernel(request, record_property):
    """Path to the guest kernel artifact.

    Default: parametrized over every supported kernel, so every test that
    requests this fixture (directly or via `uvm` etc.) runs once per kernel.

    Override with `@pin_guest_kernel(<Path or catalogue>)` (from
    `framework.artifacts`) to restrict to one kernel or a smaller subset —
    e.g. for tests of Firecracker functionality that don't depend on the
    guest kernel, use `@pin_guest_kernel(GUEST_KERNEL_DEFAULT)`.
    """
    kernel_path = request.param
    if kernel_path is None:
        pytest.fail(f"No kernel artifacts found in {ARTIFACT_DIR}")
    record_property("guest_kernel", kernel_path.stem[2:])
    return kernel_path


@pytest.fixture
def rootfs_mode(request):
    """Rootfs access mode: "ro" (squashfs) or "rw" (ext4). Default: "ro"."""
    mode = getattr(request, "param", "ro")
    if mode not in ("ro", "rw"):
        pytest.fail(f"rootfs_mode must be 'ro' or 'rw'; got {mode!r}")
    return mode


@pytest.fixture
def rootfs(guest_kernel, rootfs_mode):
    """Path to a rootfs disk matching `guest_kernel` and `rootfs_mode`.

    Ubuntu for 5.10, AL2023 otherwise (AL2023 does not officially support 5.10).
    """
    distro = "ubuntu" if guest_kernel.stem[2:] == "linux-5.10" else "amazonlinux"
    suffix = {"ro": "squashfs", "rw": "ext4"}[rootfs_mode]
    disk_list = disks(f"{distro}*.{suffix}")
    if not disk_list:
        pytest.fail(f"No {distro} {suffix} found in {ARTIFACT_DIR}")
    return disk_list[0]


@pytest.fixture
def uvm(microvm_factory, guest_kernel, rootfs, pci_enabled):
    """Built microVM (chroot only). Caller drives spawn/basic_config/start."""
    vm = microvm_factory.build(guest_kernel, rootfs, pci=pci_enabled)
    return vm


@pytest.fixture
def uvm_configured(uvm, vcpu_count, mem_size_mib, huge_pages, cpu_template):
    """Spawned + basic_config + cpu_template applied. Caller adds devices and starts."""
    uvm.spawn()
    uvm.basic_config(
        vcpu_count=vcpu_count,
        mem_size_mib=mem_size_mib,
        huge_pages=huge_pages,
    )
    if cpu_template is not None:
        uvm.set_cpu_template(cpu_template)
    return uvm


@pytest.fixture
def uvm_booted(uvm_configured):
    """Booted microVM with a default net iface. Ready to ssh."""
    uvm_configured.add_net_iface()
    uvm_configured.start()
    return uvm_configured


@pytest.fixture
def uvm_restored(uvm_booted, microvm_factory):
    """Booted microVM, snapshotted, restored from the snapshot."""
    snapshot = uvm_booted.snapshot_full()
    uvm_booted.kill()
    restored = microvm_factory.build_from_snapshot(snapshot)
    restored.cpu_template_name = uvm_booted.cpu_template_name
    return restored


@pytest.fixture(params=["booted", "restored"])
def uvm_lifecycle(request):
    """Parametrized over the two lifecycle end-states a test may want.

    Tests that depend on it (directly, or transitively via `uvm_any`) run
    once per state. Use this as the synchronisation point when a test
    needs to build a secondary VM that matches the same lifecycle as
    `uvm_any` (e.g. an A/B test against a different firecracker revision).
    """
    return request.param


@pytest.fixture
def uvm_any(
    uvm_lifecycle,
    request,
    guest_kernel,
    rootfs,
    pci_enabled,
    cpu_template,
    vcpu_count,
    mem_size_mib,
    huge_pages,
):
    """A microVM in either the booted or restored lifecycle state.

    Parametrized over both states via `uvm_lifecycle` — every test that
    requests `uvm_any` runs twice (booted + restored). Replaces the old
    `uvm_any` fixture which used function refs in `params=`.

    Explicitly declares dependencies on every dim fixture used by the
    underlying `uvm_booted` / `uvm_restored` fixtures so pytest puts them
    all in the test's fixture closure (otherwise indirect parametrize on
    those names would error with "function uses no fixture").
    """
    # pylint: disable=unused-argument
    return request.getfixturevalue(f"uvm_{uvm_lifecycle}")
