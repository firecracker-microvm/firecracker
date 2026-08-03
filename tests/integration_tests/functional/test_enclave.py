# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for Nitro Enclave direct and confidential modes in Firecracker."""

import json
import os
import time
from pathlib import Path

import pytest
from tenacity import Retrying, retry_if_exception_type, stop_after_delay, wait_fixed

import host_tools.drive as drive_tools
from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.defs import ARTIFACT_DIR
from framework.utils import CpuMap, get_threads
from framework.utils_vsock import (
    ECHO_SERVER_PORT,
    VSOCK_UDS_PATH,
    start_guest_echo_server,
    vsock_connect_to_guest,
)
from framework.vm_backend import VM_BACKENDS_ENCLAVE, VmBackend, pin_vm_backend

MAX_ENCLAVE_DEVICES = 32

# Every test here needs a Nitro Enclave, so the pin belongs to the file rather
# than to each test, and the backend decides the memory-isolation mode a test
# runs under. Note that `parametrize` marks do not merge: a per-test
# `pin_vm_backend` below would collide with this rather than override it.
pytestmark = pin_vm_backend(VM_BACKENDS_ENCLAVE)


def _assert_vm_process_is_alive(vm):
    """Assert the Firecracker process is still alive."""
    assert vm.firecracker_pid is not None
    assert os.path.exists(f"/proc/{vm.firecracker_pid}")


@pytest.fixture
def boot_enclave(uvm):
    """Factory booting `uvm` with the standard enclave test setup.

    Returns a callable so each test can pass its own start flags:

        vm = boot_enclave(hotplug_mode=True)

    Tests exercising non-standard boot paths (initrd-only boot, config-file
    boot, pre-start vsock devices) keep their manual setup instead.
    """

    def boot(*, vcpu_count=2, mem_size_mib=512, net_ifaces=1, **start_flags):
        uvm.spawn()
        uvm.basic_config(vcpu_count=vcpu_count, mem_size_mib=mem_size_mib)
        for _ in range(net_ifaces):
            uvm.add_net_iface()
        uvm.start(debug_mode=True, **start_flags)
        return uvm

    return boot


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
    "cpu_overcommit", [True, False], ids=["overcommit", "dedicated"]
)
def test_enclave_ssh(boot_enclave, cpu_overcommit):
    """Boot an enclave with block + net devices and verify SSH works.

    This exercises the full NE transport path: NE_ADD_DEVICE for block and net,
    info-event DRIVER_OK detection, device activation, and end-to-end I/O. In
    confidential mode the block and net queues run through per-device DMBs.
    The memory-isolation mode (confidential/direct) comes from the vm_backend
    dimension; CPU overcommit (floating vCPUs) vs dedicated cores is
    parametrized here.
    """
    # start() waits for SSH — proves block + net devices are activated via
    # info-event.
    vm = boot_enclave(cpu_overcommit=cpu_overcommit)

    assert "/dev/vda" in vm.ssh.check_output("mount").stdout
    assert "inet " in vm.ssh.check_output("ip addr show eth0").stdout

    vm.ssh.check_output("echo 'enclave test' > /tmp/test.txt")
    assert "enclave test" in vm.ssh.check_output("cat /tmp/test.txt").stdout


def test_enclave_max_vcpus(boot_enclave):
    """Boot an enclave with as many vCPUs as the host has online CPUs."""
    # Our CI guest kernels are built with CONFIG_NR_CPUS=64, so the guest onlines
    # at most 64 vCPUs no matter how many the enclave is given.
    host_cpus = min(CpuMap.len(), 64)

    # Overcommit (floating vCPUs) is required so the count is bounded by the
    # parent instance's vCPU count rather than the dedicated NE CPU pool.
    vm = boot_enclave(vcpu_count=host_cpus, cpu_overcommit=True)

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
    "cpu_overcommit", [True, False], ids=["overcommit", "dedicated"]
)
def test_enclave_cpu_accounting(boot_enclave, cpu_overcommit):
    """A CPU_ACCOUNTING enclave binds each vCPU to an fc_vcpu host thread.

    Verifies Parent-PID visibility: the VMM has one `fc_vcpu N` thread per
    enclave vCPU, GET /enclave reports cpu_accounting, and each thread's guest
    time (NOT user time, which reads ~0) grows while the guest burns CPU.

    Parametrized over cpu_overcommit to exercise that accounting is independent
    of overcommit (it works both with floating and dedicated vCPUs).
    """
    vcpu_count = 2

    vm = boot_enclave(
        vcpu_count=vcpu_count,
        cpu_overcommit=cpu_overcommit,
        cpu_accounting=True,
    )

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


def test_enclave_hotplug(boot_enclave):
    """Hotplug block devices to a running enclave and verify they are usable."""
    # Two slots are used pre-boot: the root block device and the SSH NIC.
    num_hotplug_devices = MAX_ENCLAVE_DEVICES - 2

    vm = boot_enclave(hotplug_mode=True)

    blocks_before = set(vm.ssh.check_output("ls -1 /sys/block").stdout.split())

    for i in range(num_hotplug_devices):
        host_file = drive_tools.FilesystemFile(
            os.path.join(vm.fsfiles, f"hotplug{i}"), size=4
        )
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


def test_enclave_hotplug_disabled(boot_enclave):
    """Runtime device hotplug must be rejected when hotplug_mode is not set."""
    vm = boot_enclave()

    host_file = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "hotplug0"), size=4)
    with pytest.raises(RuntimeError, match="hotplug_mode"):
        vm.add_drive(
            drive_id="hotplug0",
            path_on_host=host_file.path,
            is_root_device=False,
            is_read_only=False,
        )


def test_enclave_vsock(uvm):
    """Boot an enclave with a vsock device and verify host<->guest echo.

    Exercises the NE transport for virtio-vsock: NE_ADD_DEVICE, info-event
    DRIVER_OK activation, and an end-to-end vsock round-trip.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config(vcpu_count=2, mem_size_mib=512)
    vm.add_net_iface()
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/" + VSOCK_UDS_PATH)
    vm.start(debug_mode=True)

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


def test_enclave_many_devices(boot_enclave):
    """Boot an enclave with many devices and verify they all activate.

    Attaches a root block device plus NICs up to the per-enclave device ceiling
    and verifies every NIC activates in the guest.
    """
    # One slot is taken by the root block device. First NIC is used for SSH;
    # the rest stress the device count.
    num_net_devices = MAX_ENCLAVE_DEVICES - 1

    vm = boot_enclave(mem_size_mib=1024, net_ifaces=num_net_devices)

    out = vm.ssh.check_output("ls -1 /sys/class/net | grep -c eth").stdout.strip()
    assert int(out) == num_net_devices, f"expected {num_net_devices} NICs, found {out}"


# ---------------------------------------------------------------------------
# Test: block device config update (drive resize)
# ---------------------------------------------------------------------------


def test_enclave_block_config_update(uvm):
    """Patch an enclave block device and verify the guest sees the new size.

    An enclave guest reads its virtio config space from a copy held by the
    VMM, so a drive patch must travel PATCH /drives ->
    NE_UPDATE_DEVICE_CONFIG -> VMM -> config-change interrupt for the
    guest to observe the resized disk.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config(vcpu_count=2, mem_size_mib=512)

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
