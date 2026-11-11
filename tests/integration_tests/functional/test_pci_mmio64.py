# Copyright 2026 CoreWeave, Inc.
# SPDX-License-Identifier: Apache-2.0
"""PCI MMIO64 configuration and snapshot tests."""

import fcntl
import platform
import struct

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel, pin_pci


def _kvm_address_bits():
    """Read KVM's physical address width."""
    with open("/dev/kvm", "rb") as kvm:
        if platform.machine() == "aarch64":
            # KVM_CHECK_EXTENSION(KVM_CAP_ARM_VM_IPA_SIZE); absent means 40 bits.
            return fcntl.ioctl(kvm, 0xAE03, 165) or 40

        # KVM_GET_SUPPORTED_CPUID: 8-byte header, then 40-byte entries.
        entries = 256
        cpuid = bytearray(8 + entries * 40)
        struct.pack_into("=I", cpuid, 0, entries)
        fcntl.ioctl(kvm, 0xC008AE05, cpuid, True)
        count = struct.unpack_from("=I", cpuid)[0]
        for offset in range(8, 8 + count * 40, 40):
            leaf, index, _, eax = struct.unpack_from("=4I", cpuid, offset)
            if leaf == 0x80000008 and index == 0:
                return eax & 0xFF
    return 0


def _require_address_width(aperture):
    """Skip apertures exceeding KVM's address width."""
    if aperture is None:
        return
    # Include the following pmem/hotplug pool.
    end = (aperture["base_gib"] + aperture["size_gib"] + 512) << 30
    required_bits = (end - 1).bit_length()
    bits = _kvm_address_bits()
    if bits < required_bits:
        pytest.skip(
            f"MMIO64 case requires {required_bits} address bits; KVM supports {bits}"
        )


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
@pytest.mark.parametrize(
    "aperture",
    [None, {"base_gib": 16, "size_gib": 8}, {"base_gib": 2048, "size_gib": 2048}],
    ids=["default", "small", "large"],
)
def test_pci_mmio64_boot_and_restore(uvm_configured, microvm_factory, aperture):
    """Restore each aperture and verify guest access."""
    _require_address_width(aperture)
    vm = uvm_configured
    if aperture is not None:
        vm.api.machine_config.patch(pci_mmio64=aperture)
    vm.add_net_iface()
    vm.start()
    vm.ssh.check_output("true")
    assert vm.api.machine_config.get().json().get("pci_mmio64") == aperture
    base = (aperture or {"base_gib": 256})["base_gib"] << 30
    size = (aperture or {"size_gib": 256})["size_gib"] << 30
    expected_range = f"mem64 area: [{base:#x}-{base + size - 1:#x}]"
    assert expected_range in vm.log_data

    with pytest.raises(RuntimeError, match="not supported after starting"):
        vm.api.machine_config.patch(pci_mmio64={"base_gib": 16, "size_gib": 1})

    snapshot = vm.snapshot_full()
    restored_vm = microvm_factory.build(pci=True)
    restored_vm.spawn()
    restored_vm.restore_from_snapshot(snapshot, resume=True)
    assert restored_vm.api.machine_config.get().json().get("pci_mmio64") == aperture
    assert expected_range in restored_vm.log_data
    restored_vm.ssh.check_output("true")


@pin_pci(True)
@pytest.mark.parametrize(
    "aperture",
    [
        {"base_gib": 3, "size_gib": 1},
        {"base_gib": 4, "size_gib": 0},
        {"base_gib": 4, "size_gib": 1 << 63},
        {"base_gib": -1, "size_gib": 1},
        {"base_gib": 4},
    ],
)
def test_pci_mmio64_invalid_config(uvm, aperture):
    """Reject invalid ranges without changing configuration."""
    vm = uvm
    vm.spawn()
    with pytest.raises(RuntimeError):
        vm.api.machine_config.patch(pci_mmio64=aperture)
    assert "pci_mmio64" not in vm.api.machine_config.get().json()
