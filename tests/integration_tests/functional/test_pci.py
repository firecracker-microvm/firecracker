# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the PCI devices"""

# Virtio PCI common config register offsets
# https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1420003
COMMON_CFG_QUEUE_SELECT = 0x16  # u16
COMMON_CFG_QUEUE_SIZE = 0x18  # u16
COMMON_CFG_QUEUE_ENABLE = 0x1C  # u16
COMMON_CFG_QUEUE_DESC_LO = 0x20  # u32
COMMON_CFG_QUEUE_DESC_HI = 0x24  # u32
COMMON_CFG_QUEUE_AVAIL_LO = 0x28  # u32
COMMON_CFG_QUEUE_AVAIL_HI = 0x2C  # u32
COMMON_CFG_QUEUE_USED_LO = 0x30  # u32
COMMON_CFG_QUEUE_USED_HI = 0x34  # u32


def test_pci_root_present(uvm_any_with_pci):
    """
    Test that a guest with PCI enabled has a PCI root device.
    """

    vm = uvm_any_with_pci
    devices = vm.ssh.run("lspci").stdout.strip().split("\n")
    print(devices)
    assert devices[0].startswith(
        "00:00.0 Host bridge: Intel Corporation Device"
    ), "PCI root not found in guest"


def test_pci_disabled(uvm_any_without_pci):
    """
    Test that a guest with PCI disabled does not have a PCI root device but still works.
    """

    vm = uvm_any_without_pci
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


def test_queue_config_immutable(uvm_any_with_pci, devmem_bin):
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
    vm = uvm_any_with_pci

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
