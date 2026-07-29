# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the PCI devices"""

import host_tools.drive as drive_tools
from framework.artifacts import (
    ACPI_GUEST_KERNELS,
    GUEST_KERNEL_DEFAULT,
    pin_guest_kernel,
    pin_pci,
)
from framework.utils_cpu_templates import ALL_CPU_TEMPLATES, pin_cpu_template

# Virtio PCI common config register offsets
# https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1420003
COMMON_CFG_NUM_QUEUES = 0x12  # u16 (read-only)
COMMON_CFG_QUEUE_SELECT = 0x16  # u16
COMMON_CFG_QUEUE_SIZE = 0x18  # u16
COMMON_CFG_QUEUE_ENABLE = 0x1C  # u16
COMMON_CFG_QUEUE_DESC_LO = 0x20  # u32
COMMON_CFG_QUEUE_DESC_HI = 0x24  # u32
COMMON_CFG_QUEUE_AVAIL_LO = 0x28  # u32
COMMON_CFG_QUEUE_AVAIL_HI = 0x2C  # u32
COMMON_CFG_QUEUE_USED_LO = 0x30  # u32
COMMON_CFG_QUEUE_USED_HI = 0x34  # u32

# The virtio-pci capability BAR size
CAPABILITY_BAR_SIZE = 0x80000

# Offset of the notification area within the capability BAR
NOTIFICATION_BAR_OFFSET = 0x6000

# Guest path the devmem tool is copied to
DEVMEM_PATH = "/tmp/devmem"


@pin_pci(True)
@pin_cpu_template(ALL_CPU_TEMPLATES)
@pin_guest_kernel(ACPI_GUEST_KERNELS)
def test_pci_root_present(uvm_any):
    """
    Test that a guest with PCI enabled has a PCI root device.
    """

    vm = uvm_any
    devices = vm.ssh.run("lspci").stdout.strip().split("\n")
    print(devices)
    assert devices[0].startswith(
        "00:00.0 Host bridge: Intel Corporation Device"
    ), "PCI root not found in guest"


@pin_pci(False)
@pin_cpu_template(ALL_CPU_TEMPLATES)
def test_pci_disabled(uvm_any):
    """
    Test that a guest with PCI disabled does not have a PCI root device but still works.
    """

    vm = uvm_any
    _, stdout, _ = vm.ssh.run("lspci")
    assert (
        "00:00.0 Host bridge: Intel Corporation Device" not in stdout
    ), "PCI root not found in guest"


def _find_virtio_blk_bar(vm):
    """Find the BAR0 physical address of the first virtio-blk PCI device.

    virtio-blk has PCI device ID 0x1042 (0x1040 + type 2).

    Example::

        # lspci -n
        00:00.0 0600: 8086:0d57
        00:01.0 0180: 1af4:1042 (rev 01)

    The resource file has one line per BAR.  Each line contains three
    space-separated hex values: start, end, flags.

    Example (BAR0 line)::

        # cat /sys/bus/pci/devices/0000:00:01.0/resource | head -1
        0x0000004000000000 0x000000400007ffff 0x0000000000140204
    """
    stdout = vm.ssh.check_output("lspci -n").stdout.strip()
    slot = None
    for line in stdout.split("\n"):
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "1af4:1042":
            slot = f"0000:{parts[0]}"
            break
    assert slot is not None, "No virtio-blk PCI device found"

    cmd = f"cat /sys/bus/pci/devices/{slot}/resource | head -1"
    stdout = vm.ssh.check_output(cmd).stdout.strip()
    addr = int(stdout.split()[0], 16)
    assert addr != 0, f"BAR0 address is 0 for {slot}"
    return addr


def _devmem_read(vm, tool_path, addr, width):
    """Read a physical address via /dev/mem."""
    cmd = f"{tool_path} read 0x{addr:x} {width}"
    stdout = vm.ssh.check_output(cmd).stdout.strip()
    return int(stdout, 16)


def _devmem_write(vm, tool_path, addr, width, value):
    """Write a physical address via /dev/mem and return the read-back value."""
    cmd = f"{tool_path} write 0x{addr:x} {width} 0x{value:x}"
    stdout = vm.ssh.check_output(cmd).stdout.strip()
    return int(stdout, 16)


@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pin_pci(True)
@pin_cpu_template(ALL_CPU_TEMPLATES)
def test_queue_config_immutable(uvm_any, devmem_bin):
    """
    Test that queue configuration fields cannot be modified by the guest
    after the device has been activated (DRIVER_OK is set).

    All PCI common config queue fields are read-write, so we can verify
    immutability by writing a poison value and checking the readback still
    equals the original.

    MMIO queue config immutability is covered by the Rust unit test
    test_queue_config_immutable_after_activation in transport/mmio.rs.
    MMIO queue fields are write-only (reads return 0), so integration-level
    readback verification via /dev/mem is not possible.
    """
    vm = uvm_any

    rmt_path = "/tmp/devmem"
    vm.ssh.scp_put(devmem_bin, rmt_path)
    vm.ssh.check_output(f"chmod +x {rmt_path}")

    bar_addr = _find_virtio_blk_bar(vm)

    # Select queue 0
    _devmem_write(vm, rmt_path, bar_addr + COMMON_CFG_QUEUE_SELECT, 2, 0)

    # (name, offset, width, poison_value)
    queue_fields = [
        ("queue_size", COMMON_CFG_QUEUE_SIZE, 2, 0),
        ("queue_enable", COMMON_CFG_QUEUE_ENABLE, 2, 0),
        ("queue_desc_lo", COMMON_CFG_QUEUE_DESC_LO, 4, 0xDEADBEEF),
        ("queue_desc_hi", COMMON_CFG_QUEUE_DESC_HI, 4, 0xDEADBEEF),
        ("queue_avail_lo", COMMON_CFG_QUEUE_AVAIL_LO, 4, 0xDEADBEEF),
        ("queue_avail_hi", COMMON_CFG_QUEUE_AVAIL_HI, 4, 0xDEADBEEF),
        ("queue_used_lo", COMMON_CFG_QUEUE_USED_LO, 4, 0xDEADBEEF),
        ("queue_used_hi", COMMON_CFG_QUEUE_USED_HI, 4, 0xDEADBEEF),
    ]
    for name, offset, width, poison in queue_fields:
        addr = bar_addr + offset
        orig = _devmem_read(vm, rmt_path, addr, width)
        readback = _devmem_write(vm, rmt_path, addr, width, poison)
        assert (
            readback == orig
        ), f"{name} should remain {orig:#x} after DRIVER_OK, got {readback:#x}"


def _setup_scratch_blk_vm(vm, devmem_bin):
    """
    Boot `vm` with a scratch virtio-blk device whose BAR can be relocated.

    Returns the PCI slot of the scratch device, its BAR0 base address and its
    num_queues value.
    """
    vm.add_net_iface()
    # Add a scratch virtio-blk device whose BAR we are going to relocate
    vm.scratch_drive = drive_tools.FilesystemFile(size=16)
    vm.add_drive("scratch", vm.scratch_drive.path)
    vm.start()

    vm.ssh.scp_put(devmem_bin, DEVMEM_PATH)
    vm.ssh.check_output(f"chmod +x {DEVMEM_PATH}")

    # The scratch device is the second block device exposed as vdb.
    slot = vm.ssh.check_output(
        "readlink -f /sys/block/vdb | grep -oE "
        "'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}.[0-9]' | tail -1"
    ).stdout.strip()
    resource = vm.ssh.check_output(
        f"cat /sys/bus/pci/devices/{slot}/resource | head -1"
    ).stdout.strip()
    base = int(resource.split()[0], 16)
    assert base != 0

    # The device's num_queues field (read-only) is a stable, non-zero value we
    # can use as a witness that config reads resolve to the device.
    num_queues = _devmem_read(vm, DEVMEM_PATH, base + COMMON_CFG_NUM_QUEUES, 2)
    assert num_queues not in (0, 0xFFFF), f"unexpected num_queues {num_queues:#x}"

    return slot, base, num_queues


def _reprogram_bar(vm, slot, base):
    """
    Reprogram the 64-bit BAR0 of `slot` to `base` with setpci.

    Memory-space decoding (COMMAND bit 1) is disabled before touching the BAR
    registers because a 64-bit BAR cannot be updated atomically. Re-enabling
    decoding is what makes Firecracker apply the relocation.
    """
    vm.ssh.check_output(f"setpci -s {slot} COMMAND=0:2")
    vm.ssh.check_output(f"setpci -s {slot} BASE_ADDRESS_0=0x{base & 0xFFFFFFFF:08x}")
    vm.ssh.check_output(f"setpci -s {slot} BASE_ADDRESS_1=0x{base >> 32:08x}")
    vm.ssh.check_output(f"setpci -s {slot} COMMAND=2:2")


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_bar_relocation(uvm_configured, devmem_bin):
    """
    Test that reprogramming a virtio-pci BAR relocates the device's mmio
    mapping and its notification ioeventfds.

    The BAR is rewritten with setpci, behind the guest driver's back, so the
    driver keeps its stale mapping and no guest I/O through the device is
    exercised. All checks go through /dev/mem.
    """
    vm = uvm_configured
    slot, old_base, num_queues = _setup_scratch_blk_vm(vm, devmem_bin)

    # Relocate the BAR 4 GiB higher. This stays inside the 64-bit MMIO aperture
    # ([256 GiB, 512 GiB)) and is naturally aligned to the BAR size, so it does
    # not collide with any other device.
    new_base = old_base + 0x1_0000_0000
    assert new_base % CAPABILITY_BAR_SIZE == 0

    # Nothing is mapped at the new base yet: an unmapped MMIO read returns 0.
    empty = _devmem_read(vm, DEVMEM_PATH, new_base + COMMON_CFG_NUM_QUEUES, 2)
    assert empty == 0, f"expected nothing mapped at {new_base:#x}, read {empty:#x}"

    _reprogram_bar(vm, slot, new_base)

    # The device now answers at the new base with the same num_queues value...
    relocated = _devmem_read(vm, DEVMEM_PATH, new_base + COMMON_CFG_NUM_QUEUES, 2)
    assert (
        relocated == num_queues
    ), f"device not reachable at relocated BAR {new_base:#x}: read {relocated:#x}"

    # ...and no longer at the old base (unmapped MMIO reads back as 0).
    stale = _devmem_read(vm, DEVMEM_PATH, old_base + COMMON_CFG_NUM_QUEUES, 2)
    assert stale == 0, f"device still mapped at old BAR {old_base:#x}: read {stale:#x}"

    # Verify the notification ioeventfds followed the BAR as well. A write to
    # queue 0's notify address at the new base must be absorbed by the
    # relocated ioeventfd; had the ioeventfd move failed, the write would fall
    # through to the device's BAR handler and log a warning.
    _devmem_write(vm, DEVMEM_PATH, new_base + NOTIFICATION_BAR_OFFSET, 2, 0)
    assert (
        "unexpected write to notification BAR" not in vm.log_data
    ), "notification ioeventfd did not follow the BAR to the new base"
    assert (
        "notification ioeventfds" not in vm.log_data
    ), "BAR relocation logged a notification ioeventfd error"


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_bar_relocation_refused(uvm_configured, devmem_bin):
    """
    Test that Firecracker refuses to relocate a BAR outside the 64-bit MMIO
    aperture and leaves the device where it is.
    """
    vm = uvm_configured
    slot, base, num_queues = _setup_scratch_blk_vm(vm, devmem_bin)

    # The 64-bit MMIO aperture is [256 GiB, 512 GiB), so the resource
    # allocator has no range to give us at 1 TiB.
    invalid_base = 0x100_0000_0000  # 1 TiB
    assert invalid_base % CAPABILITY_BAR_SIZE == 0

    _reprogram_bar(vm, slot, invalid_base)

    assert (
        f"Cannot reserve relocated BAR range at {invalid_base:#x}" in vm.log_data
    ), "Firecracker did not reject the out-of-aperture BAR relocation"
    still_there = _devmem_read(vm, DEVMEM_PATH, base + COMMON_CFG_NUM_QUEUES, 2)
    assert (
        still_there == num_queues
    ), f"device disturbed by a rejected relocation: read {still_there:#x}"


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_bar_relocation_snapshot(uvm_configured, microvm_factory, devmem_bin):
    """
    Test that a relocated BAR survives a snapshot/restore cycle.

    The restored VM must map the device at the relocated base, which is the
    address the snapshot carries, and not at the one Firecracker picked when
    the device was first attached.
    """
    vm = uvm_configured
    slot, old_base, num_queues = _setup_scratch_blk_vm(vm, devmem_bin)

    new_base = old_base + 0x1_0000_0000
    assert new_base % CAPABILITY_BAR_SIZE == 0
    _reprogram_bar(vm, slot, new_base)

    relocated = _devmem_read(vm, DEVMEM_PATH, new_base + COMMON_CFG_NUM_QUEUES, 2)
    assert (
        relocated == num_queues
    ), f"device not reachable at relocated BAR {new_base:#x}: read {relocated:#x}"

    snapshot = vm.snapshot_full()
    vm.kill()
    vm2 = microvm_factory.build_from_snapshot(snapshot)
    vm2.ssh.scp_put(devmem_bin, DEVMEM_PATH)
    vm2.ssh.check_output(f"chmod +x {DEVMEM_PATH}")

    restored = _devmem_read(vm2, DEVMEM_PATH, new_base + COMMON_CFG_NUM_QUEUES, 2)
    assert (
        restored == num_queues
    ), f"restored device not reachable at {new_base:#x}: read {restored:#x}"
    stale = _devmem_read(vm2, DEVMEM_PATH, old_base + COMMON_CFG_NUM_QUEUES, 2)
    assert (
        stale == 0
    ), f"restored device mapped at the pre-relocation BAR {old_base:#x}: read {stale:#x}"
