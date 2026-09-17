# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the PCI bus topology"""

import pytest

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
