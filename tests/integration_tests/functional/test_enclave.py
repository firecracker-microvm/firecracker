# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for Nitro Enclave direct and confidential modes in Firecracker."""

import functools
import json
import os
import signal
import threading
import time
from pathlib import Path

import pytest
from tenacity import Retrying, retry_if_exception_type, stop_after_delay, wait_fixed

import host_tools.drive as drive_tools
from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.defs import ARTIFACT_DIR
from framework.enclave import DEFAULT_DMB_SIZE_MIB
from framework.guest_stats import MeminfoGuest
from framework.utils import CpuMap, get_threads, parse_cpu_list
from framework.utils_vsock import (
    ECHO_SERVER_PORT,
    VSOCK_UDS_PATH,
    start_guest_echo_server,
    vsock_connect_to_guest,
)
from framework.vm_backend import VM_BACKENDS_ENCLAVE, VmBackend, pin_vm_backend

MAX_ENCLAVE_DEVICES = 32

# Attempt-independent part of `Attempt #{n} of NE_CREATE_VM2 returned EINTR`,
# which the retry loop logs for each EINTR it absorbs.
RETRY_LOG_LINE = "NE_CREATE_VM2 returned EINTR"

# Every test here needs a Nitro Enclave, so the pin belongs to the file rather
# than to each test, and the backend decides the memory-isolation mode a test
# runs under. Note that `parametrize` marks do not merge: a per-test
# `pin_vm_backend` below would collide with this rather than override it.
pytestmark = pin_vm_backend(VM_BACKENDS_ENCLAVE)


def _assert_vm_process_is_alive(vm):
    """Assert the Firecracker process is still alive."""
    assert vm.firecracker_pid is not None
    assert os.path.exists(f"/proc/{vm.firecracker_pid}")


# Enclave start flags as module dimensions. Defaults mirror
# `enclave_prepare_start`; override one per test with indirect
# parametrization, the same mechanism as `vcpu_count`/`mem_size_mib`.
@pytest.fixture
def cpu_overcommit(request):
    """Float vCPUs (True) or pin them to dedicated cores (False)."""
    return getattr(request, "param", True)


@pytest.fixture
def cpu_accounting(request):
    """Bind each enclave vCPU to an fc_vcpu host thread."""
    return getattr(request, "param", False)


@pytest.fixture
def hotplug_mode(request):
    """Allow runtime device hotplug."""
    return getattr(request, "param", False)


@pytest.fixture
def mem_size_mib(request):
    """Enclave tests boot with 512 MiB (the guest also holds the EIF image)."""
    return getattr(request, "param", 512)


# Overrides the shared `uvm_booted` stage: every booted enclave in this
# module starts in debug mode with the start-flag dimensions applied.
# Tests exercising non-standard boot paths (initrd-only boot, config-file
# boot, pre-start devices) stay on `uvm`/`uvm_configured` instead.
@pytest.fixture
def uvm_booted(uvm_configured, cpu_overcommit, cpu_accounting, hotplug_mode):
    """Booted enclave with the standard test setup."""
    uvm_configured.add_net_iface()
    uvm_configured.start(
        debug_mode=True,
        cpu_overcommit=cpu_overcommit,
        cpu_accounting=cpu_accounting,
        hotplug_mode=hotplug_mode,
    )
    return uvm_configured


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_enclave_config_api(microvm_factory, guest_kernel):
    """Verify PUT /enclave is accepted pre-boot and returned by GET /enclave."""
    vm = microvm_factory.build(kernel=guest_kernel)
    vm.spawn()
    # The backend already expresses the mode; asserting a second axis over it
    # would repeat the same round-trip under a contradictory test ID.
    direct_mode = vm.backend is VmBackend.ENCLAVE_DIRECT

    vm.api.machine_config.put(
        vcpu_count=2,
        mem_size_mib=256,
    )

    vm.api.enclave.put(
        debug_mode=True,
        direct_mode=direct_mode,
        cpu_overcommit=True,
        cpu_accounting=True,
        hotplug_mode=True,
    )

    response = vm.api.enclave.get()
    config = response.json()
    assert config["debug_mode"] is True
    assert config["direct_mode"] is direct_mode
    assert config["cpu_overcommit"] is True
    assert config["cpu_accounting"] is True
    assert config["hotplug_mode"] is True
    assert vm.api.vm_config.get().json()["enclave"] == config


def test_enclave_boot(uvm):
    """Boot an enclave and verify via serial console output.

    Configures serial_out_path to capture enclave serial output to a file,
    then checks for the Linux kernel boot marker in the serial output.

    The enclave boots with just CPU, memory, and EIF — no virtio devices, so
    no DMBs are allocated even in confidential mode.
    """
    vm = uvm
    vm.initrd_file = ARTIFACT_DIR / "initramfs.cpio"

    vm.spawn()
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
        add_root_device=False,
        boot_args="console=ttyS0 earlyprintk=serial",
        use_initrd=True,
    )
    vm.start(debug_mode=True)

    for attempt in Retrying(
        wait=wait_fixed(0.1),
        stop=stop_after_delay(5),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            _assert_vm_process_is_alive(vm)

    # The serial console reader polls the info page ring buffer every 100ms.
    assert vm.serial_out_path is not None
    serial_data = ""
    for attempt in Retrying(
        wait=wait_fixed(0.1),
        stop=stop_after_delay(30),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            serial_data = vm.serial_out_path.read_text(encoding="utf-8")
            assert "Linux version" in serial_data, (
                "Enclave started but no 'Linux version' found in serial output "
                f"after 30s. Serial output ({len(serial_data)} bytes): "
                + repr(serial_data[:200])
            )


def test_enclave_config_file_boot(uvm):
    """Boot an enclave via --config-file and verify it starts.

    Unlike the API-based test, this exercises the build_microvm_from_json
    code path. Serial verification is skipped because serial_config cannot
    be set via the JSON config file before boot.
    """
    vcpu_count = 2

    vm = uvm
    vm.initrd_file = ARTIFACT_DIR / "initramfs.cpio"

    jailed_kernel = vm.create_jailed_resource(vm.kernel_file)
    jailed_initrd = vm.create_jailed_resource(vm.initrd_file)

    enclave_cfg = {
        "debug_mode": True,
        "direct_mode": vm.backend is VmBackend.ENCLAVE_DIRECT,
        "cpu_overcommit": True,
    }

    config = {
        "boot-source": {
            "kernel_image_path": jailed_kernel,
            "initrd_path": jailed_initrd,
            "boot_args": "console=ttyS0 earlyprintk=serial",
        },
        "machine-config": {
            "vcpu_count": vcpu_count,
            "mem_size_mib": 256,
            "smt": False,
            "track_dirty_pages": False,
            "huge_pages": "None",
        },
        "drives": [],
        "network-interfaces": [],
        "enclave": enclave_cfg,
    }

    config_path = Path(vm.chroot()) / "vm_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    vm.jailer.extra_args["config-file"] = config_path.name

    vm.spawn(serial_out_path=None)

    for attempt in Retrying(
        wait=wait_fixed(0.1),
        stop=stop_after_delay(5),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            _assert_vm_process_is_alive(vm)
            assert vm.state == "Running"


@pytest.mark.parametrize(
    "cpu_overcommit", [True, False], ids=["overcommit", "dedicated"], indirect=True
)
def test_enclave_ssh(uvm_booted):
    """Boot an enclave with block + net devices and verify SSH works.

    This exercises the full NE transport path: NE_ADD_DEVICE for block and net,
    info-event DRIVER_OK detection, device activation, and end-to-end I/O. In
    confidential mode the block and net queues run through per-device DMBs.
    The memory-isolation mode (confidential/direct) comes from the vm_backend
    dimension; CPU overcommit (floating vCPUs) vs dedicated cores is
    parametrized here.
    """
    # uvm_booted's start() waits for SSH — proves block + net devices are
    # activated via info-event.
    vm = uvm_booted

    assert "/dev/vda" in vm.ssh.check_output("mount").stdout
    assert "inet " in vm.ssh.check_output("ip addr show eth0").stdout

    vm.ssh.check_output("echo 'enclave test' > /tmp/test.txt")
    assert "enclave test" in vm.ssh.check_output("cat /tmp/test.txt").stdout


def test_enclave_per_device_dmb_size(uvm_configured):
    """Report mixed explicit sizes and an omitted default before and after boot."""
    vm = uvm_configured
    if vm.backend is not VmBackend.ENCLAVE_CONFIDENTIAL:
        pytest.skip("DMB allocation reporting requires confidential mode")

    vm.add_drive(
        drive_id="rootfs",
        path_on_host=vm.rootfs_file,
        is_root_device=True,
        is_read_only=vm.rootfs_file.suffix == ".squashfs",
        dmb_size_mib=32,
    )
    sized_iface = vm.add_net_iface(dmb_size_mib=64)
    unsized_iface = vm.add_net_iface()
    vm.api.vsock.put(
        vsock_id="vsock0",
        guest_cid=3,
        uds_path="/" + VSOCK_UDS_PATH,
        dmb_size_mib=8,
    )

    preboot_config = vm.api.vm_config.get().json()
    assert preboot_config["drives"][0]["dmb_size_mib"] == 32
    preboot_network_configs = {
        iface["iface_id"]: iface for iface in preboot_config["network-interfaces"]
    }
    assert preboot_network_configs[sized_iface.dev_name]["dmb_size_mib"] == 64
    assert "dmb_size_mib" not in preboot_network_configs[unsized_iface.dev_name]
    assert preboot_config["vsock"]["dmb_size_mib"] == 8

    vm.start(debug_mode=True)

    runtime_config = vm.api.vm_config.get().json()
    assert runtime_config["drives"][0]["dmb_size_mib"] == 32
    runtime_network_configs = {
        iface["iface_id"]: iface for iface in runtime_config["network-interfaces"]
    }
    assert runtime_network_configs[sized_iface.dev_name]["dmb_size_mib"] == 64
    assert (
        runtime_network_configs[unsized_iface.dev_name]["dmb_size_mib"]
        == DEFAULT_DMB_SIZE_MIB
    )
    assert runtime_config["vsock"]["dmb_size_mib"] == 8


def test_enclave_direct_rejects_dmb_size(uvm_configured):
    """Reject an explicit DMB size at direct-mode startup without killing the VMM."""
    vm = uvm_configured
    if vm.backend is not VmBackend.ENCLAVE_DIRECT:
        pytest.skip("This test checks direct-mode rejection")

    vm.add_drive(
        drive_id="rootfs",
        path_on_host=vm.rootfs_file,
        is_root_device=True,
        is_read_only=vm.rootfs_file.suffix == ".squashfs",
        dmb_size_mib=2,
    )
    assert vm.api.vm_config.get().json()["drives"][0]["dmb_size_mib"] == 2
    with pytest.raises(
        RuntimeError,
        match="Failed to attach enclave block device rootfs: .*cannot be set in direct mode",
    ):
        vm.start(debug_mode=True)
    _assert_vm_process_is_alive(vm)


def test_enclave_max_vcpus(uvm):
    """Boot an enclave with as many vCPUs as the host has online CPUs.

    Boots by hand rather than via `uvm_booted`: the vCPU count, memory size and
    node list all follow from the host's online CPUs and nodes, which is only
    known at run time.
    """
    # Our CI guest kernels are built with CONFIG_NR_CPUS=64, so the guest onlines
    # at most 64 vCPUs no matter how many the enclave is given.
    host_cpus = min(CpuMap.len(), 64)

    # An enclave defaults to parent NUMA node 0, whose share of the CPU pool cannot
    # cover every host CPU on a multi-node parent, so spread the vCPUs over all
    # online nodes. On a single-node host this is just the node-0 default written
    # out explicitly. Cap the node count at host_cpus so no node ends up with
    # zero vCPUs, which the config rejects.
    nodes = _get_online_numa_nodes()[:host_cpus]
    per_node_cpus, extra_cpus = divmod(host_cpus, len(nodes))
    per_node_mib = 512
    numa_nodes = [
        {
            "parent_numa": n,
            # Hand the remainder to the last node so the sum matches exactly.
            "vcpu_count": per_node_cpus + (extra_cpus if idx == len(nodes) - 1 else 0),
            "mem_size_mib": per_node_mib,
        }
        for idx, n in enumerate(nodes)
    ]

    vm = uvm
    vm.spawn()
    vm.basic_config(vcpu_count=host_cpus, mem_size_mib=per_node_mib * len(nodes))
    vm.add_net_iface()
    # Overcommit (floating vCPUs, the enclave default) is required so the count
    # is bounded by the parent instance's vCPU count rather than the dedicated
    # NE CPU pool.
    vm.start(debug_mode=True, numa_nodes=numa_nodes, cpu_overcommit=True)

    guest_cpus = int(vm.ssh.check_output("nproc").stdout.strip())
    assert guest_cpus == host_cpus, f"guest saw {guest_cpus} CPUs, expected {host_cpus}"


def _thread_guest_time(pid, tid):
    """Read guest_time (field 43) from /proc/<pid>/task/<tid>/stat in clock ticks.

    Fields are 1-indexed in proc(5). Field 2 is the comm in parentheses and may
    contain spaces, so parse after the last ')': the remainder's first token is
    field 3, making guest_time (field 43) index 40.
    """
    stat = Path(f"/proc/{pid}/task/{tid}/stat").read_text(encoding="utf-8")
    return int(stat[stat.rindex(")") + 1 :].split()[40])


@pytest.mark.parametrize(
    "cpu_overcommit", [True, False], ids=["overcommit", "dedicated"], indirect=True
)
@pytest.mark.parametrize("cpu_accounting", [True], ids=["accounting"], indirect=True)
def test_enclave_cpu_accounting(uvm_booted, vcpu_count):
    """A CPU_ACCOUNTING enclave binds each vCPU to an fc_vcpu host thread.

    Verifies Parent-PID visibility: the VMM has one `fc_vcpu N` thread per
    enclave vCPU, GET /enclave reports cpu_accounting, and each thread's guest
    time (NOT user time, which reads ~0) grows while the guest burns CPU.

    Parametrized over cpu_overcommit to exercise that accounting is independent
    of overcommit (it works both with floating and dedicated vCPUs).
    """
    vm = uvm_booted

    config = vm.api.enclave.get().json()
    assert config["cpu_accounting"] is True

    threads = get_threads(vm.firecracker_pid)
    tids = {}
    for i in range(vcpu_count):
        name = f"fc_vcpu {i}"
        assert name in threads, f"missing accounting thread {name!r}: {list(threads)}"
        tids[name] = threads[name][0]

    # Baseline guest time, then burn CPU in the guest on every vCPU.
    before = {
        name: _thread_guest_time(vm.firecracker_pid, tid) for name, tid in tids.items()
    }
    for _ in range(vcpu_count):
        vm.ssh.run("nohup bash -c 'while true; do :; done' >/dev/null 2>&1 &")
    time.sleep(5)
    after = {
        name: _thread_guest_time(vm.firecracker_pid, tid) for name, tid in tids.items()
    }

    for name in tids:
        assert (
            after[name] > before[name]
        ), f"{name} guest_time did not grow: before={before[name]} after={after[name]}"


@pytest.mark.parametrize("hotplug_mode", [True], ids=["hotplug"], indirect=True)
def test_enclave_hotplug(uvm_booted):
    """Hotplug the device limit with custom/default DMBs and verify guest I/O."""
    # Two slots are used pre-boot: the root block device and the SSH NIC.
    num_hotplug_devices = MAX_ENCLAVE_DEVICES - 2
    vm = uvm_booted
    blocks_before = set(vm.ssh.check_output("ls -1 /sys/block").stdout.split())

    for i in range(num_hotplug_devices):
        host_file = drive_tools.FilesystemFile(
            os.path.join(vm.fsfiles, f"hotplug{i}"), size=4
        )
        if i == 0:
            if vm.backend is VmBackend.ENCLAVE_DIRECT:
                with pytest.raises(
                    RuntimeError, match="cannot be set in direct mode"
                ) as exc_info:
                    vm.add_drive(
                        drive_id="hotplug0",
                        path_on_host=host_file.path,
                        is_root_device=False,
                        is_read_only=False,
                        dmb_size_mib=32,
                    )
                assert exc_info.value.args[2].status_code == 400
            else:
                vm.add_drive(
                    drive_id="hotplug0",
                    path_on_host=host_file.path,
                    is_root_device=False,
                    is_read_only=False,
                    dmb_size_mib=32,
                )
                continue
        vm.add_drive(
            drive_id=f"hotplug{i}",
            path_on_host=host_file.path,
            is_root_device=False,
            is_read_only=False,
        )

    # Wait for the enclave kernel's pciehp driver to enumerate all new devices.
    # No `echo 1 > /sys/bus/pci/rescan` — native PCIe hotplug must surface them.
    new_blocks = set()
    for attempt in Retrying(
        wait=wait_fixed(0.5),
        stop=stop_after_delay(30),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            blocks_after = set(vm.ssh.check_output("ls -1 /sys/block").stdout.split())
            new_blocks = blocks_after - blocks_before
            assert len(new_blocks) == num_hotplug_devices, (
                f"expected {num_hotplug_devices} new block devices, "
                f"got {len(new_blocks)}: {new_blocks}"
            )

    for i, dev_name in enumerate(sorted(new_blocks)):
        dev_path = f"/dev/{dev_name}"
        mnt = f"/tmp/hotplug_mnt_{i}"
        payload = f"enclave_hotplug_{i}"
        vm.ssh.check_output(f"mkdir -p {mnt}")
        vm.ssh.check_output(f"mount {dev_path} {mnt}")
        vm.ssh.check_output(f"echo {payload} > {mnt}/test")
        assert vm.ssh.check_output(f"cat {mnt}/test").stdout.strip() == payload

    runtime_drives = {
        drive["drive_id"]: drive for drive in vm.api.vm_config.get().json()["drives"]
    }
    if vm.backend is VmBackend.ENCLAVE_CONFIDENTIAL:
        assert runtime_drives["hotplug0"]["dmb_size_mib"] == 32
        assert runtime_drives["hotplug1"]["dmb_size_mib"] == DEFAULT_DMB_SIZE_MIB
    else:
        assert "dmb_size_mib" not in runtime_drives["hotplug0"]
        assert "dmb_size_mib" not in runtime_drives["hotplug1"]


def test_enclave_hotplug_disabled(uvm_booted):
    """Runtime device hotplug must be rejected when hotplug_mode is not set."""
    vm = uvm_booted

    host_file = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "hotplug0"), size=4)
    with pytest.raises(RuntimeError, match="hotplug_mode"):
        vm.add_drive(
            drive_id="hotplug0",
            path_on_host=host_file.path,
            is_root_device=False,
            is_read_only=False,
        )


# Guest memory the kernel takes for itself before userspace sees any: its own
# image, the EIF it was booted from, and reserved regions.
KERNEL_OVERHEAD_MIB = 64
# struct page is 64 bytes per 4 KiB page, so the vmemmap costs size/64.
VMEMMAP_OVERHEAD_RATIO = 64 / 4096


@pytest.mark.parametrize(
    "mem_size_mib", [512, 1022, 1024, 1026, 2046, 2048, 2050, 4096], indirect=True
)
def test_enclave_memory_sizes(uvm, mem_size_mib):
    """Boot an enclave at each memory size and check the guest sees it.

    The sizes straddle the PCI MMIO hole, where guest RAM is split into a low
    and a high region: 1024 MiB is the aarch64 boundary, 2048 MiB the x86_64
    one (see EnclaveVm::split_ram_regions). The +2 sizes leave a deliberately
    tiny high region, which is where the region maths has gone wrong before.
    """
    vm = uvm
    vm.spawn()
    # Disable the bounce buffer: Linux reserves 64 MiB of it whenever guest RAM
    # spans past 4 GiB, which every size above the split boundary does, and that
    # would dwarf the overhead this test is trying to bound.
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=mem_size_mib,
        boot_args="reboot=k panic=1 nomodule swiotlb=noforce cryptomgr.notests",
    )
    vm.add_net_iface()
    vm.start(debug_mode=True)

    budget_mib = KERNEL_OVERHEAD_MIB + mem_size_mib * VMEMMAP_OVERHEAD_RATIO
    mem_total_mib = MeminfoGuest(vm).get().mem_total.mib()
    assert mem_total_mib >= mem_size_mib - budget_mib, (
        f"guest reports {mem_total_mib:.0f} MiB of {mem_size_mib} MiB, "
        f"more than {budget_mib:.0f} MiB missing"
    )


def test_enclave_poweroff(uvm_booted):
    """A guest-initiated poweroff shuts the VMM down gracefully.

    The enclave counterpart of `test_shut_down.py::test_reboot`: enclave vCPUs
    produce no KVM_SYSTEM_EVENT, so assert on the VMM exiting cleanly instead.

    Allow 120s for systemd's 90s DefaultTimeoutStopSec, as
    test_send_ctrl_alt_del does.
    """
    vm = uvm_booted

    vm.ssh.run("poweroff")
    vm.mark_killed(timeout=120)

    vm.check_log_message("Vmm is stopping.")
    assert vm.get_exit_code() == 0


def test_enclave_vsock(uvm_configured):
    """Boot an enclave with a default-sized vsock DMB and verify host<->guest echo.

    Exercises the NE transport for virtio-vsock: NE_ADD_DEVICE, info-event
    DRIVER_OK activation, end-to-end I/O, and runtime DMB allocation reporting.
    """
    vm = uvm_configured
    vm.add_net_iface()
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/" + VSOCK_UDS_PATH)
    assert "dmb_size_mib" not in vm.api.vm_config.get().json()["vsock"]
    vm.start(debug_mode=True)
    runtime_vsock = vm.api.vm_config.get().json()["vsock"]
    if vm.backend is VmBackend.ENCLAVE_CONFIDENTIAL:
        assert runtime_vsock["dmb_size_mib"] == DEFAULT_DMB_SIZE_MIB
    else:
        assert "dmb_size_mib" not in runtime_vsock

    host_uds = start_guest_echo_server(vm)
    sock = vsock_connect_to_guest(host_uds, ECHO_SERVER_PORT)
    try:
        payload = b"enclave-vsock-roundtrip"
        sock.sendall(payload)
        received = b""
        while len(received) < len(payload):
            chunk = sock.recv(len(payload) - len(received))
            assert chunk, "vsock connection closed before echo completed"
            received += chunk
        assert received == payload
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Test: block device config update (drive resize)
# ---------------------------------------------------------------------------


def test_enclave_block_config_update(uvm_configured):
    """Patch an enclave block device and verify the guest sees the new size.

    An enclave guest reads its virtio config space from a copy held by the
    VMM, so a drive patch must travel PATCH /drives ->
    NE_UPDATE_DEVICE_CONFIG -> VMM -> config-change interrupt for the
    guest to observe the resized disk.
    """
    vm = uvm_configured

    # Scratch drive that will be patched to a larger backing file.
    fs1 = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "scratch"), size=64)
    vm.add_drive(
        drive_id="scratch",
        path_on_host=fs1.path,
        is_root_device=False,
        is_read_only=False,
    )

    vm.add_net_iface()
    vm.start(debug_mode=True)

    blksize_cmd = "cat /sys/block/vdb/size"
    initial_sectors = int(vm.ssh.check_output(blksize_cmd).stdout.strip())
    assert initial_sectors == 64 * 1024 * 2, f"got {initial_sectors} sectors"

    # Patch to a larger backing file — must reach the guest through
    # NE_UPDATE_DEVICE_CONFIG and the resulting config-change interrupt.
    fs2 = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "otherscratch"), size=128)
    vm.api.drive.patch(
        drive_id="scratch", path_on_host=vm.create_jailed_resource(fs2.path)
    )

    # The guest applies the new capacity on the config-change interrupt;
    # allow a short grace period for the revalidation to land.
    for attempt in Retrying(
        wait=wait_fixed(0.2),
        stop=stop_after_delay(5),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            new_sectors = int(vm.ssh.check_output(blksize_cmd).stdout.strip())
            assert new_sectors == 128 * 1024 * 2, f"got {new_sectors} sectors"


# ---------------------------------------------------------------------------
# Test: NUMA placement
# ---------------------------------------------------------------------------


def _get_online_numa_nodes():
    """Read the online parent NUMA nodes from sysfs.

    Returns a sorted list of node ids (e.g. `[0, 1]`), or `[0]` if the topology
    cannot be read (a machine with NUMA disabled still has node 0).
    """
    try:
        with open("/sys/devices/system/node/online", encoding="ascii") as f:
            content = f.read().strip()
    except (FileNotFoundError, PermissionError):
        return [0]
    nodes = sorted(parse_cpu_list(content))
    return nodes if nodes else [0]


def _numa_maps_node_pages(pid):
    """Return {node_id: total_pages} from /proc/<pid>/numa_maps.

    Each mapping line ends with `N<node>=<pages>` fields, summed over all lines.
    """
    totals = {}
    for line in Path(f"/proc/{pid}/numa_maps").read_text("utf-8").splitlines():
        for field in line.split():
            if field.startswith("N") and "=" in field:
                node_str, _, pages_str = field[1:].partition("=")
                if node_str.isdigit() and pages_str.isdigit():
                    totals[int(node_str)] = totals.get(int(node_str), 0) + int(
                        pages_str
                    )
    return totals


def _guest_numa_topology(vm):
    """Return {guest_node_id: {"cpus": [...], "mem_total_kb": int}} over SSH.

    Reads /sys/devices/system/node/* directly so it needs no numactl in the guest.
    """
    online = vm.ssh.check_output("cat /sys/devices/system/node/online").stdout
    topo = {}
    for n in sorted(parse_cpu_list(online)):
        cpulist = vm.ssh.check_output(
            f"cat /sys/devices/system/node/node{n}/cpulist"
        ).stdout.strip()
        meminfo = vm.ssh.check_output(
            f"cat /sys/devices/system/node/node{n}/meminfo"
        ).stdout
        mem_total_kb = 0
        for line in meminfo.splitlines():
            # Format: "Node 0 MemTotal:    262144 kB"
            if "MemTotal:" in line:
                mem_total_kb = int(line.split()[3])
                break
        topo[n] = {
            "cpus": sorted(parse_cpu_list(cpulist)) if cpulist else [],
            "mem_total_kb": mem_total_kb,
        }
    return topo


def test_enclave_numa_defaults_to_node_zero(uvm_booted, vcpu_count, mem_size_mib):
    """An enclave started without numa_nodes lands entirely on parent node 0.

    GET /enclave reports the placement in effect, so the synthesized default is
    observable rather than an absent field.
    """
    vm = uvm_booted

    config = vm.api.enclave.get().json()
    assert config["numa_nodes"] == [
        {
            "parent_numa": 0,
            "vcpu_count": vcpu_count,
            "mem_size_mib": mem_size_mib,
        }
    ]

    # The enclave's pages must actually be on node 0, not merely reported there.
    node_pages = _numa_maps_node_pages(vm.firecracker_pid)
    assert node_pages.get(0, 0) > 0, f"no pages on parent NUMA node 0: {node_pages}"


@pytest.mark.parametrize(
    "cpu_overcommit,cpu_accounting",
    [
        pytest.param(False, False, id="dedicated"),
        pytest.param(True, True, id="overcommit-accounting"),
    ],
)
@pytest.mark.parametrize("layout", ["node0", "node1", "all-nodes"])
def test_enclave_numa_placement(uvm, layout, cpu_overcommit, cpu_accounting):
    """Place an enclave on requested parent NUMA node(s); verify parent placement and,
    on dedicated cores, the guest vNUMA topology.

    Boots by hand rather than via `uvm_booted`: the vCPU count, memory size and
    node list all follow from the host's online nodes, which is only known at
    run time.

    Layouts: a single node on parent node 0, a single node on parent node 1 (a
    non-zero node), and a spread across every online node. The node1 and
    all-nodes layouts are skipped on single-NUMA hosts.

    A single-node config leaves PCIE_NUMA unset, so the guest gets a default
    single-node SRAT; a multi-node config sets it and the hypervisor compacts
    the requested parent nodes into guest nodes [0..N). Under cpu_overcommit the
    kernel ignores NE_ADD_ANY_VCPU's numa_hint and vCPUs float onto guest node
    0, so the guest-topology check runs only on dedicated cores; memory
    placement is independent of vCPU scheduling and is checked in both modes.
    """
    online = _get_online_numa_nodes()
    if layout == "node0":
        parent_nodes = [0]
    elif layout == "node1":
        if 1 not in online:
            pytest.skip(f"parent NUMA node 1 not online, found {online}")
        parent_nodes = [1]
    else:  # all-nodes
        if len(online) < 2:
            pytest.skip(
                f"spread requires >= 2 online parent NUMA nodes, found {online}"
            )
        parent_nodes = online

    vcpus_per_node = 2
    per_node_mib = 256
    numa_nodes = [
        {"parent_numa": n, "vcpu_count": vcpus_per_node, "mem_size_mib": per_node_mib}
        for n in parent_nodes
    ]
    vcpus = vcpus_per_node * len(parent_nodes)
    total_mib = per_node_mib * len(parent_nodes)
    multi = len(parent_nodes) > 1

    vm = uvm
    vm.spawn()
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=total_mib)
    vm.add_net_iface()
    vm.start(
        debug_mode=True,
        numa_nodes=numa_nodes,
        cpu_overcommit=cpu_overcommit,
        cpu_accounting=cpu_accounting,
    )

    vm.ssh.check_output("echo ok")

    config = vm.api.enclave.get().json()
    assert config["numa_nodes"] == numa_nodes
    assert config["cpu_accounting"] is cpu_accounting

    node_pages = _numa_maps_node_pages(vm.firecracker_pid)
    if multi:
        # Enclave pages must land on every requested parent node.
        for n in parent_nodes:
            assert (
                node_pages.get(n, 0) > 0
            ), f"no pages on parent NUMA node {n}: {node_pages}"
    else:
        # numa_maps spans the whole VMM, so incidental runtime pages land on
        # other nodes; require the requested node to dominate (a misplaced
        # region flips it).
        parent_node = parent_nodes[0]
        req_pages = node_pages.get(parent_node, 0)
        total_pages = sum(node_pages.values())
        assert (
            req_pages > 0
        ), f"no pages on requested parent NUMA node {parent_node}: {node_pages}"
        assert req_pages >= 0.9 * total_pages, (
            f"only {req_pages}/{total_pages} pages on requested parent node "
            f"{parent_node} (<90%); enclave RAM is not placed there: {node_pages}"
        )
        assert req_pages == max(node_pages.values()), (
            f"parent node {parent_node} ({req_pages} pages) is not the dominant "
            f"node: {node_pages}"
        )

    if cpu_overcommit:
        return

    # The hypervisor compacts requested parent nodes into guest nodes [0..N), so
    # only the node COUNT and per-node vCPU/memory split are asserted, not ids.
    guest_topo = _guest_numa_topology(vm)
    assert len(guest_topo) == len(numa_nodes), (
        f"guest reports {len(guest_topo)} NUMA node(s) "
        f"({sorted(guest_topo)}), expected {len(numa_nodes)} "
        f"(one per requested parent node {parent_nodes})"
    )
    total_guest_cpus = sum(len(info["cpus"]) for info in guest_topo.values())
    assert total_guest_cpus == vcpus, (
        f"guest NUMA nodes expose {total_guest_cpus} vCPUs total, expected "
        f"{vcpus}: { {n: info['cpus'] for n, info in guest_topo.items()} }"
    )
    for gnode, info in guest_topo.items():
        assert len(info["cpus"]) == vcpus_per_node, (
            f"guest NUMA node {gnode} has {len(info['cpus'])} vCPUs, "
            f"expected {vcpus_per_node}"
        )
        # Guest reports slightly less than requested (kernel reserves some);
        # >= 50% distinguishes a populated node from an empty placeholder.
        assert info["mem_total_kb"] >= per_node_mib * 1024 * 0.50, (
            f"guest NUMA node {gnode} reports {info['mem_total_kb']} kB, "
            f"expected >= {int(per_node_mib * 1024 * 0.50)} kB "
            f"(50% of {per_node_mib} MiB)"
        )


@pytest.mark.repeat(3)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_enclave_create_vm_pending_signal(uvm):
    """NE_CREATE_VM2 must not fail the boot when a signal is pending.

    The ioctl returns EINTR while a signal is pending.

    SIGSTOP arms it in the kernel alone: the group stop sets TIF_SIGPENDING
    with no userspace handler on the path, so the pending signal is all the
    test introduces. SIGCONT follows so the boot proceeds.

    Signalling stops at the first EINTR the retry absorbs. Without the retry
    that first one already fails InstanceStart, so one hit is the whole test,
    and an open-ended stream would instead out-pace the retry budget.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config(vcpu_count=2, mem_size_mib=512)
    vm.add_net_iface()

    # If FC wedges before replying, fail through pytest rather than hang until
    # the CI runner kills the step. The Session is this VM's own, so the timeout
    # does not leak to other tests.
    vm.api.session.request = functools.partial(vm.api.session.request, timeout=30)

    fc_pid = vm.firecracker_pid
    stop = threading.Event()
    # Set once the log proves the retry took over, so the run can tell coverage
    # apart from a boot that never hit the window.
    retried = threading.Event()

    def signal_firecracker():
        while not stop.is_set():
            if RETRY_LOG_LINE in vm.log_data:
                retried.set()
                return
            try:
                os.kill(fc_pid, signal.SIGSTOP)
                os.kill(fc_pid, signal.SIGCONT)
            except ProcessLookupError:
                return
            time.sleep(0.001)

    signaller = threading.Thread(target=signal_firecracker, daemon=True)
    signaller.start()
    try:
        vm.start(debug_mode=True)
    finally:
        stop.set()
        signaller.join(timeout=5)

    vm.ssh.check_output("true")

    # Landing in the window is timing-dependent. A run that missed it proved
    # less, so say so instead of passing as though it covered the retry.
    if not (retried.is_set() or RETRY_LOG_LINE in vm.log_data):
        pytest.skip("no signal landed in the EINTR window")
