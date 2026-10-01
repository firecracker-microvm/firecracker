# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the PCI bus topology"""

import os

import pytest

import host_tools.drive as drive_tools
from framework.artifacts import (
    ACPI_GUEST_KERNELS,
    GUEST_KERNEL_DEFAULT,
    pin_guest_kernel,
)

# What a root port looks like in lspci: a PCI-to-PCI bridge
PCI_BRIDGE_CLASS = "0604:"

MAX_HOTPLUG_PORTS = 31


@pin_guest_kernel(ACPI_GUEST_KERNELS)
def test_hotplug_ports_config(microvm_factory, guest_kernel, rootfs):
    """
    pcie_hotplug_ports is validated, and needs PCI.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=False)
    vm.spawn()
    with pytest.raises(
        RuntimeError, match="PCIe hot-plug ports require `--enable-pci`"
    ):
        vm.basic_config(pcie_hotplug_ports=1)
    vm.kill()

    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.spawn()
    with pytest.raises(RuntimeError, match=f"must be at most {MAX_HOTPLUG_PORTS}"):
        vm.basic_config(pcie_hotplug_ports=MAX_HOTPLUG_PORTS + 1)

    # The maximum is accepted, and reported back.
    vm.basic_config(pcie_hotplug_ports=MAX_HOTPLUG_PORTS)
    config = vm.api.machine_config.get().json()
    assert config["pcie_hotplug_ports"] == MAX_HOTPLUG_PORTS


@pin_guest_kernel(ACPI_GUEST_KERNELS)
def test_no_root_ports(microvm_factory, guest_kernel, rootfs):
    """
    Without hot-plug ports there are no root ports, and nothing brings up a
    secondary bus.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    vm.start()

    # Assert there are no root ports, and no device on a secondary bus
    _, lspci, _ = vm.ssh.check_output("lspci -n")
    assert not [l for l in lspci.splitlines() if l.split()[1] == PCI_BRIDGE_CLASS]
    assert {l.split(":")[0] for l in lspci.splitlines()} == {"00"}

    # Assert there are no secondary buses
    _, sysfs, _ = vm.ssh.check_output("ls /sys/class/pci_bus")
    assert sysfs.split() == ["0000:00"]


@pin_guest_kernel(ACPI_GUEST_KERNELS)
def test_root_ports_start_empty(microvm_factory, guest_kernel, rootfs):
    """
    Root ports show up as empty bridges, each with a secondary bus of its own,
    and the boot devices stay on the root bus.
    """
    num_hotplug_ports = 4

    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.spawn()
    vm.basic_config(pcie_hotplug_ports=num_hotplug_ports)
    vm.add_net_iface()
    vm.start()

    _, lspci, _ = vm.ssh.check_output("lspci -n")
    bridges = [l for l in lspci.splitlines() if l.split()[1] == PCI_BRIDGE_CLASS]
    assert len(bridges) == num_hotplug_ports, lspci

    # Nothing sits behind a port yet, so the host bridge, the rootfs, the
    # network interface and the ports themselves are all on the root bus.
    assert {l.split(":")[0] for l in lspci.splitlines()} == {"00"}

    # Each port brings up its secondary bus all the same.
    _, sysfs, _ = vm.ssh.check_output("ls /sys/class/pci_bus")
    assert sysfs.split() == [f"0000:{bus:02x}" for bus in range(num_hotplug_ports + 1)]

    # The secondary bus numbers start from 1 and are contiguous
    paths = " ".join(
        f"/sys/bus/pci/devices/0000:{bridge.split()[0]}/secondary_bus_number"
        for bridge in bridges
    )
    _, secondary, _ = vm.ssh.check_output(f"cat {paths}")
    assert [int(bus) for bus in secondary.split()] == list(
        range(1, num_hotplug_ports + 1)
    )


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_root_ports_exhaust_slots(microvm_factory, guest_kernel, rootfs):
    """
    Root ports take up root bus slots, so asking for every port leaves the
    boot devices nowhere to go and the VM refuses to start.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.spawn()
    vm.basic_config(pcie_hotplug_ports=MAX_HOTPLUG_PORTS)

    with pytest.raises(
        RuntimeError, match="Could not find an available device slot on the PCI bus"
    ):
        vm.start()


@pin_guest_kernel(ACPI_GUEST_KERNELS)
def test_removable_boot_device(microvm_factory, guest_kernel, rootfs):
    """
    A boot device marked removable is present from boot and sits behind a root
    port. A non-removable one stays on the root bus and cannot be removed.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.spawn()
    vm.basic_config(pcie_hotplug_ports=2)
    vm.add_net_iface()

    # The guest sees two identical virtio-blk devices and does not know our
    # drive IDs, so give them different sizes to tell them apart by.
    plain_mib = 4
    removable_mib = 8
    plain = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "plain"), size=plain_mib
    )
    vm.add_drive("plain", plain.path)
    removable = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "removable"), size=removable_mib
    )
    vm.add_drive("removable", removable.path, removable=True)
    vm.start()

    # The flag is reported back.
    drives = {d["drive_id"]: d for d in vm.api.vm_config.get().json()["drives"]}
    assert drives["removable"]["removable"] is True
    assert drives["plain"]["removable"] is False

    # Ask the guest for the size and the sysfs path of every disk it has. A
    # disk links to the virtio device backing it, whose parent is the PCI
    # device, so the address before the trailing virtio node is the one we are
    # after: .../0000:00:04.0/0000:01:00.0/virtio3 is a disk behind the port at
    # 00:04.0, while .../0000:00:02.0/virtio1 sits on the root bus.
    _, sysfs, _ = vm.ssh.check_output(
        "for d in /sys/block/vd*; do echo $(cat $d/size) $(readlink -f $d/device); done"
    )

    def pci_address(size_mib):
        for line in sysfs.splitlines():
            # Sizes are reported in 512 byte sectors.
            sectors, path = line.split()
            if int(sectors) == size_mib * 2048:
                return path.split("/")[-2]
        raise AssertionError(f"no {size_mib} MiB disk in:\n{sysfs}")

    # The removable device sits on a secondary bus, whereas the plain on sits
    # on the primary bus.
    assert pci_address(removable_mib) == "0000:01:00.0", sysfs
    assert pci_address(plain_mib).startswith("0000:00:"), sysfs

    # A device on the root bus has no way of being taken away.
    with pytest.raises(RuntimeError, match="not removable"):
        vm.api.drive.delete("plain")


@pin_guest_kernel(ACPI_GUEST_KERNELS)
def test_max_root_ports_with_removable_boot_devices(
    microvm_factory, guest_kernel, rootfs
):
    """
    Test that MAX_HOTPLUG_PORTS can be attached.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.spawn()
    vm.basic_config(pcie_hotplug_ports=MAX_HOTPLUG_PORTS, add_root_device=False)
    vm.add_drive(
        "rootfs",
        vm.rootfs_file,
        is_root_device=True,
        is_read_only=vm.rootfs_file.suffix == ".squashfs",
        removable=True,
    )
    vm.add_net_iface(removable=True)
    vm.start()

    # The root bus is full: the host bridge and a port in every other slot.
    _, lspci, _ = vm.ssh.check_output("lspci -n")
    root_bus = [line for line in lspci.splitlines() if line.startswith("00:")]
    bridges = [line for line in root_bus if line.split()[1] == PCI_BRIDGE_CLASS]
    assert len(bridges) == MAX_HOTPLUG_PORTS, lspci
    assert len(root_bus) == MAX_HOTPLUG_PORTS + 1, lspci
