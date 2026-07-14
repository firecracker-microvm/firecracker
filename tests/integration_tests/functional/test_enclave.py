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
from framework.ne_host import _find_initrd, _find_kernel, _find_rootfs, requires_enclave
from framework.utils import get_threads
from framework.utils_vsock import (
    ECHO_SERVER_PORT,
    VSOCK_UDS_PATH,
    start_guest_echo_server,
    vsock_connect_to_guest,
)

# Run enclave tests in both memory-isolation modes: confidential (the default,
# per-device DMB-backed memory) and direct (enclave RAM shared with the parent).
enclave_modes = pytest.mark.parametrize(
    "direct_mode", [False, True], ids=["confidential", "direct"]
)

# Maximum number of virtio devices an enclave can have attached.
MAX_ENCLAVE_DEVICES = 32

# ---------------------------------------------------------------------------
# Test: enclave config API (no NE hardware needed)
# ---------------------------------------------------------------------------


@enclave_modes
def test_enclave_config_api(microvm_factory, direct_mode):
    """Verify PUT /enclave is accepted pre-boot and returned by GET /enclave."""
    kernel_path = _find_kernel()
    if not kernel_path:
        pytest.skip("Kernel not found in artifacts")

    vm = microvm_factory.build(kernel=kernel_path)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    vm.api.machine_config.put(
        vcpu_count=2,
        mem_size_mib=256,
    )

    # PUT /enclave
    vm.api.enclave.put(
        debug_mode=True,
        direct_mode=direct_mode,
        cpu_overcommit=True,
        cpu_accounting=True,
        hotplug_mode=True,
    )

    # GET /enclave should reflect the config
    response = vm.api.enclave.get()
    config = response.json()
    assert config["debug_mode"] is True
    assert config["direct_mode"] is direct_mode
    assert config["cpu_overcommit"] is True
    assert config["cpu_accounting"] is True
    assert config["hotplug_mode"] is True


# ---------------------------------------------------------------------------
# Test: direct (non-confidential) enclave boot with serial console
# ---------------------------------------------------------------------------


@requires_enclave
@enclave_modes
def test_enclave_boot(microvm_factory, tmp_path, direct_mode):
    """Boot an enclave and verify via serial console output.

    Configures serial_out_path to capture enclave serial output to a file,
    then checks for the Linux kernel boot marker in the serial output.

    The enclave boots with just CPU, memory, and EIF — no virtio devices, so
    no DMBs are allocated even in confidential mode.
    """
    kernel = _find_kernel()
    initrd = _find_initrd()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not initrd:
        pytest.skip("No initramfs found in artifacts (needed for EIF build)")

    # Enclave tests assume the NE CPU pool is in dynamic mode, so the kernel
    # auto-selects the enclave's vCPUs (no explicit cpu_ids).
    vcpu_count = 2

    vm = microvm_factory.build(kernel=kernel)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    # The EIF built from bzImage (~9 MiB) + initramfs needs modest memory.
    # NE loads the EIF at an 8 MiB offset; 256 MiB is plenty.
    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        mem_size_mib=256,
    )

    # Configure serial output to a temp file so we can read it.
    serial_file = tmp_path / "serial.log"
    serial_file.touch()
    serial_path = vm.create_jailed_resource(str(serial_file))
    vm.api.serial.put(serial_out_path=serial_path)

    vm.api.boot.put(
        kernel_image_path=vm.create_jailed_resource(kernel),
        initrd_path=vm.create_jailed_resource(initrd),
        boot_args="console=ttyS0 earlyprintk=serial",
    )

    enclave_kwargs = {
        "debug_mode": True,
        "direct_mode": direct_mode,
        "cpu_overcommit": True,
    }
    vm.api.enclave.put(**enclave_kwargs)
    vm.api.actions.put(action_type="InstanceStart")

    # The enclave should boot. Verify process is alive.
    for attempt in Retrying(
        wait=wait_fixed(0.1),
        stop=stop_after_delay(5),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            assert vm.firecracker_pid is not None
            assert os.path.exists(f"/proc/{vm.firecracker_pid}")

    # Check serial output file for kernel boot markers.
    # The serial console reader polls the info page ring buffer every 100ms.
    serial_data = ""
    for attempt in Retrying(
        wait=wait_fixed(0.1),
        stop=stop_after_delay(30),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            serial_data = serial_file.read_text(encoding="utf-8")
            assert "Linux version" in serial_data, (
                "Enclave started but no 'Linux version' found in serial output "
                f"after 30s. Serial output ({len(serial_data)} bytes): "
                + repr(serial_data[:200])
            )


# ---------------------------------------------------------------------------
# Test: enclave boot via --config-file
# ---------------------------------------------------------------------------


@requires_enclave
@enclave_modes
def test_enclave_config_file_boot(microvm_factory, direct_mode):
    """Boot an enclave via --config-file and verify it starts.

    Unlike the API-based test, this exercises the build_microvm_from_json
    code path. Serial verification is skipped because serial_config cannot
    be set via the JSON config file before boot.
    """
    kernel = _find_kernel()
    initrd = _find_initrd()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not initrd:
        pytest.skip("No initramfs found in artifacts (needed for EIF build)")

    vcpu_count = 2

    vm = microvm_factory.build(kernel=kernel)

    jailed_kernel = vm.create_jailed_resource(kernel)
    jailed_initrd = vm.create_jailed_resource(initrd)

    enclave_cfg = {
        "debug_mode": True,
        "direct_mode": direct_mode,
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
    config_path.write_text(json.dumps(config))
    vm.jailer.extra_args = {"config-file": config_path.name}

    vm.spawn(serial_out_path=None)

    for attempt in Retrying(
        wait=wait_fixed(0.1),
        stop=stop_after_delay(5),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            assert vm.firecracker_pid is not None
            assert os.path.exists(f"/proc/{vm.firecracker_pid}")
            assert vm.state == "Running"


# ---------------------------------------------------------------------------
# Test: enclave with block + network devices (SSH verification)
# ---------------------------------------------------------------------------


@requires_enclave
@enclave_modes
@pytest.mark.parametrize(
    "cpu_overcommit", [True, False], ids=["overcommit", "dedicated"]
)
def test_enclave_ssh(microvm_factory, direct_mode, cpu_overcommit):
    """Boot an enclave with block + net devices and verify SSH works.

    This exercises the full NE transport path: NE_ADD_DEVICE for block and net,
    info-event DRIVER_OK detection, device activation, and end-to-end I/O. In
    confidential mode the block and net queues run through per-device DMBs.
    Parametrized over both memory-isolation mode (confidential/direct) and CPU
    overcommit (floating vCPUs) vs dedicated cores.
    """
    kernel = _find_kernel()
    rootfs = _find_rootfs()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not rootfs:
        pytest.skip("No rootfs found in artifacts")

    vcpu_count = 2

    vm = microvm_factory.build(kernel=kernel, rootfs=rootfs)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        mem_size_mib=512,
    )

    # Add root block device.
    jailed_rootfs = vm.create_jailed_resource(vm.rootfs_file)
    vm.api.drive.put(
        drive_id="rootfs",
        path_on_host=jailed_rootfs,
        is_root_device=True,
        is_read_only=False,
    )

    # Add network interface for SSH access.
    vm.add_net_iface()

    # Boot source — kernel only. The enclave builder automatically adds
    # root=/dev/vda from the root block device and console=ttyS0 in debug mode.
    vm.api.boot.put(
        kernel_image_path=vm.create_jailed_resource(kernel),
    )

    # Configure enclave mode.
    enclave_kwargs = {
        "debug_mode": True,
        "direct_mode": direct_mode,
        "cpu_overcommit": cpu_overcommit,
    }
    vm.api.enclave.put(**enclave_kwargs)

    # Start the enclave.
    vm.api.actions.put(action_type="InstanceStart")

    # Wait for SSH — proves block + net devices are activated via info-event.
    vm.wait_for_ssh_up()

    # Verify block device is mounted.
    assert "/dev/vda" in vm.ssh.check_output("mount").stdout

    # Verify network is up.
    assert "inet " in vm.ssh.check_output("ip addr show eth0").stdout

    # Basic I/O test — write and read back.
    vm.ssh.check_output("echo 'enclave test' > /tmp/test.txt")
    assert "enclave test" in vm.ssh.check_output("cat /tmp/test.txt").stdout


# ---------------------------------------------------------------------------
# Test: CPU accounting (Parent-PID visibility)
# ---------------------------------------------------------------------------


def _thread_guest_time(pid, tid):
    """Read guest_time (field 43) from /proc/<pid>/task/<tid>/stat in clock ticks.

    Fields are 1-indexed in proc(5). Field 2 is the comm in parentheses and may
    contain spaces, so parse after the last ')': the remainder's first token is
    field 3, making guest_time (field 43) index 40.
    """
    stat = Path(f"/proc/{pid}/task/{tid}/stat").read_text(encoding="utf-8")
    return int(stat[stat.rindex(")") + 1 :].split()[40])


@requires_enclave
@pytest.mark.parametrize(
    "cpu_overcommit", [True, False], ids=["overcommit", "dedicated"]
)
def test_enclave_cpu_accounting(microvm_factory, cpu_overcommit):
    """A CPU_ACCOUNTING enclave binds each vCPU to an fc_vcpu host thread.

    Verifies Parent-PID visibility: the VMM has one `fc_vcpu N` thread per
    enclave vCPU, GET /enclave reports cpu_accounting, and each thread's guest
    time (NOT user time, which reads ~0) grows while the guest burns CPU.

    Parametrized over cpu_overcommit to exercise that accounting is independent
    of overcommit (it works both with floating and dedicated vCPUs).
    """
    kernel = _find_kernel()
    rootfs = _find_rootfs()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not rootfs:
        pytest.skip("No rootfs found in artifacts")

    vcpu_count = 2

    vm = microvm_factory.build(kernel=kernel, rootfs=rootfs)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    vm.api.machine_config.put(vcpu_count=vcpu_count, mem_size_mib=512)

    jailed_rootfs = vm.create_jailed_resource(vm.rootfs_file)
    vm.api.drive.put(
        drive_id="rootfs",
        path_on_host=jailed_rootfs,
        is_root_device=True,
        is_read_only=False,
    )
    vm.add_net_iface()
    vm.api.boot.put(kernel_image_path=vm.create_jailed_resource(kernel))

    enclave_kwargs = {
        "debug_mode": True,
        "cpu_overcommit": cpu_overcommit,
        "cpu_accounting": True,
    }
    vm.api.enclave.put(**enclave_kwargs)

    vm.api.actions.put(action_type="InstanceStart")
    vm.wait_for_ssh_up()

    # GET /enclave must reflect the accounting flag.
    config = vm.api.enclave.get().json()
    assert config["cpu_accounting"] is True

    # One `fc_vcpu N` accounting thread per vCPU must exist on the VMM process.
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


@requires_enclave
@enclave_modes
def test_enclave_hotplug(microvm_factory, direct_mode):
    """
    Hotplug block devices to a running enclave and verify the guest sees them and are usable.
    """
    # Two slots are used pre-boot: the root block device and the SSH NIC.
    num_hotplug_devices = MAX_ENCLAVE_DEVICES - 2

    kernel = _find_kernel()
    rootfs = _find_rootfs()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not rootfs:
        pytest.skip("No rootfs found in artifacts")

    vcpu_count = 2

    vm = microvm_factory.build(kernel=kernel, rootfs=rootfs)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    vm.api.machine_config.put(vcpu_count=vcpu_count, mem_size_mib=512)

    # Root block device + net iface so we can reach the guest over SSH.
    jailed_rootfs = vm.create_jailed_resource(vm.rootfs_file)
    vm.api.drive.put(
        drive_id="rootfs",
        path_on_host=jailed_rootfs,
        is_root_device=True,
        is_read_only=False,
    )
    vm.add_net_iface()

    vm.api.boot.put(kernel_image_path=vm.create_jailed_resource(kernel))

    vm.api.enclave.put(
        debug_mode=True,
        direct_mode=direct_mode,
        hotplug_mode=True,
    )

    vm.api.actions.put(action_type="InstanceStart")
    vm.wait_for_ssh_up()

    # Snapshot the guest's block devices before hotplugging.
    blocks_before = set(vm.ssh.check_output("ls -1 /sys/block").stdout.split())

    # Hotplug block devices up to the enclave's device ceiling
    for i in range(num_hotplug_devices):
        host_file = drive_tools.FilesystemFile(
            os.path.join(vm.fsfiles, f"hotplug{i}"), size=4
        )
        vm.api.drive.put(
            drive_id=f"hotplug{i}",
            path_on_host=vm.create_jailed_resource(host_file.path),
            is_root_device=False,
            is_read_only=False,
        )

    # Wait for the guest kernel's pciehp driver to enumerate all new devices.
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

    # Every hotplugged device must be usable: mount it, write a file, read it
    # back. A distinct payload per device guards against mount aliasing.
    for i, dev_name in enumerate(sorted(new_blocks)):
        dev_path = f"/dev/{dev_name}"
        mnt = f"/tmp/hotplug_mnt_{i}"
        payload = f"enclave_hotplug_{i}"
        vm.ssh.check_output(f"mkdir -p {mnt}")
        vm.ssh.check_output(f"mount {dev_path} {mnt}")
        vm.ssh.check_output(f"echo {payload} > {mnt}/test")
        assert vm.ssh.check_output(f"cat {mnt}/test").stdout.strip() == payload


@requires_enclave
@enclave_modes
def test_enclave_hotplug_disabled(microvm_factory, direct_mode):
    """Runtime device hotplug must be rejected when hotplug_mode is not set."""
    kernel = _find_kernel()
    rootfs = _find_rootfs()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not rootfs:
        pytest.skip("No rootfs found in artifacts")

    vcpu_count = 2

    vm = microvm_factory.build(kernel=kernel, rootfs=rootfs)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    vm.api.machine_config.put(vcpu_count=vcpu_count, mem_size_mib=512)

    jailed_rootfs = vm.create_jailed_resource(vm.rootfs_file)
    vm.api.drive.put(
        drive_id="rootfs",
        path_on_host=jailed_rootfs,
        is_root_device=True,
        is_read_only=False,
    )
    vm.add_net_iface()

    vm.api.boot.put(kernel_image_path=vm.create_jailed_resource(kernel))

    # hotplug_mode omitted (defaults to False)
    vm.api.enclave.put(
        debug_mode=True,
        direct_mode=direct_mode,
    )

    vm.api.actions.put(action_type="InstanceStart")
    vm.wait_for_ssh_up()

    host_file = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "hotplug0"), size=4)
    with pytest.raises(RuntimeError, match="hotplug_mode"):
        vm.api.drive.put(
            drive_id="hotplug0",
            path_on_host=vm.create_jailed_resource(host_file.path),
            is_root_device=False,
            is_read_only=False,
        )


@requires_enclave
@enclave_modes
def test_enclave_vsock(microvm_factory, direct_mode):
    """Boot an enclave with a vsock device and verify host<->guest echo.

    Exercises the NE transport for virtio-vsock: NE_ADD_DEVICE, info-event
    DRIVER_OK activation, and an end-to-end vsock round-trip.
    """
    kernel = _find_kernel()
    rootfs = _find_rootfs()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not rootfs:
        pytest.skip("No rootfs found in artifacts")

    vcpu_count = 2

    vm = microvm_factory.build(kernel=kernel, rootfs=rootfs)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    vm.api.machine_config.put(vcpu_count=vcpu_count, mem_size_mib=512)

    jailed_rootfs = vm.create_jailed_resource(vm.rootfs_file)
    vm.api.drive.put(
        drive_id="rootfs",
        path_on_host=jailed_rootfs,
        is_root_device=True,
        is_read_only=False,
    )

    # Net iface for SSH, plus the vsock device under test.
    vm.add_net_iface()
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/" + VSOCK_UDS_PATH)

    vm.api.boot.put(kernel_image_path=vm.create_jailed_resource(kernel))

    enclave_kwargs = {
        "debug_mode": True,
        "direct_mode": direct_mode,
        "cpu_overcommit": True,
    }
    vm.api.enclave.put(**enclave_kwargs)

    vm.api.actions.put(action_type="InstanceStart")
    vm.wait_for_ssh_up()

    # Run a guest-side vsock echo server and round-trip a payload from the host.
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


@requires_enclave
@enclave_modes
def test_enclave_many_devices(microvm_factory, direct_mode):
    """Boot an enclave with many devices and verify they all activate.

    Attaches a root block device plus NICs up to the per-enclave device ceiling
    and verifies every NIC activates in the guest.
    """
    # One slot is taken by the root block device.
    num_net_devices = MAX_ENCLAVE_DEVICES - 1

    kernel = _find_kernel()
    rootfs = _find_rootfs()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not rootfs:
        pytest.skip("No rootfs found in artifacts")

    vcpu_count = 2

    vm = microvm_factory.build(kernel=kernel, rootfs=rootfs)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    vm.api.machine_config.put(vcpu_count=vcpu_count, mem_size_mib=1024)

    jailed_rootfs = vm.create_jailed_resource(vm.rootfs_file)
    vm.api.drive.put(
        drive_id="rootfs",
        path_on_host=jailed_rootfs,
        is_root_device=True,
        is_read_only=False,
    )

    # First NIC is used for SSH; the rest stress the device count.
    for _ in range(num_net_devices):
        vm.add_net_iface()

    vm.api.boot.put(kernel_image_path=vm.create_jailed_resource(kernel))

    enclave_kwargs = {
        "debug_mode": True,
        "direct_mode": direct_mode,
        "cpu_overcommit": True,
    }
    vm.api.enclave.put(**enclave_kwargs)

    vm.api.actions.put(action_type="InstanceStart")
    vm.wait_for_ssh_up()

    # Count ethernet interfaces in the guest; expect one per attached NIC.
    out = vm.ssh.check_output("ls -1 /sys/class/net | grep -c eth").stdout.strip()
    assert int(out) == num_net_devices, f"expected {num_net_devices} NICs, found {out}"


# ---------------------------------------------------------------------------
# Test: block device config update (drive resize)
# ---------------------------------------------------------------------------


@requires_enclave
@enclave_modes
def test_enclave_block_config_update(microvm_factory, direct_mode):
    """Patch an enclave block device and verify the guest sees the new size.

    An enclave guest reads its virtio config space from a copy held by the
    VMM, so a drive patch must travel PATCH /drives ->
    NE_UPDATE_DEVICE_CONFIG -> VMM -> config-change interrupt for the
    guest to observe the resized disk.
    """
    kernel = _find_kernel()
    rootfs = _find_rootfs()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not rootfs:
        pytest.skip("No rootfs found in artifacts")

    vm = microvm_factory.build(kernel=kernel, rootfs=rootfs)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    vm.api.machine_config.put(vcpu_count=2, mem_size_mib=512)

    jailed_rootfs = vm.create_jailed_resource(vm.rootfs_file)
    vm.api.drive.put(
        drive_id="rootfs",
        path_on_host=jailed_rootfs,
        is_root_device=True,
        is_read_only=False,
    )

    # Scratch drive that will be patched to a larger backing file.
    fs1 = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "scratch"), size=64)
    vm.api.drive.put(
        drive_id="scratch",
        path_on_host=vm.create_jailed_resource(fs1.path),
        is_root_device=False,
        is_read_only=False,
    )

    vm.add_net_iface()
    vm.api.boot.put(kernel_image_path=vm.create_jailed_resource(kernel))
    vm.api.enclave.put(
        debug_mode=True,
        direct_mode=direct_mode,
        cpu_overcommit=True,
    )
    vm.api.actions.put(action_type="InstanceStart")
    vm.wait_for_ssh_up()

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
