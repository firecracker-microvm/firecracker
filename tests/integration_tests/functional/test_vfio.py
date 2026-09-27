# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for VFIO based PCIe device passthrough.

Assigning a device needs a host PCI function bound to the ``vfio-pci`` driver,
which the CI fleet does not have. The tests that assign a device are therefore
gated behind the ``FC_TEST_VFIO_DEVICE`` environment variable (the host sysfs
path of a function bound to ``vfio-pci``, e.g.
``/sys/bus/pci/devices/0000:01:00.0``) and skip otherwise. The configuration
checks do not need any passthrough hardware and always run.
"""

import os
import platform
from pathlib import Path

import pytest

from framework.artifacts import pin_pci

VFIO_DEVICE = os.environ.get("FC_TEST_VFIO_DEVICE")
# A PCI address that does not exist on any host (bus 0xff, device 0x1f,
# function 7 of segment 0xffff).
MISSING_DEVICE = "/sys/bus/pci/devices/ffff:ff:1f.7"
# Linux IORESOURCE_MEM flag in the sysfs "resource" file.
IORESOURCE_MEM = 0x200
# PCI Command register Memory Space Enable bit.
PCI_COMMAND_MEMORY = 0x2
# PCI base class of display controllers.
PCI_BASE_CLASS_DISPLAY = 0x03
# Offset of the Interrupt Pin register in the configuration space.
PCI_INTERRUPT_PIN = 0x3D


def _vfio_available():
    """Whether a real VFIO passthrough device is available to test against."""
    return (
        VFIO_DEVICE is not None
        and Path(VFIO_DEVICE).exists()
        and Path("/dev/vfio/vfio").exists()
    )


needs_vfio = pytest.mark.skipif(
    not _vfio_available(),
    reason=(
        "no VFIO device available; set FC_TEST_VFIO_DEVICE to the sysfs path of "
        "a host PCI function bound to vfio-pci"
    ),
)


def _memory_bar_sizes(resource):
    """Sizes of the six BARs in a sysfs "resource" file, 0 for non-memory BARs."""
    sizes = []
    for line in resource.splitlines()[:6]:
        start, end, flags = (int(field, 16) for field in line.split())
        sizes.append(end - start + 1 if flags & IORESOURCE_MEM and end else 0)
    return sizes


def _assign(vm, devices=(VFIO_DEVICE,), mem_size_mib=256):
    """Configure `vm` with the given host devices, jailed as in production."""
    vm.jailer.vfio_devices = list(devices)
    # VFIO pins all guest memory, which the jailed process must be allowed to
    # lock.
    vm.jailer.resource_limits = [f"memlock={mem_size_mib << 20}"]
    vm.spawn()
    vm.basic_config(mem_size_mib=mem_size_mib)
    vm.add_net_iface()
    for index, device in enumerate(devices):
        vm.api.vfio.put(id=f"passthrough{index}", path=device)


def _group_functions():
    """The functions of the IOMMU group of the device under test that are bound
    to vfio-pci, the device under test first."""
    group = Path(VFIO_DEVICE) / "iommu_group" / "devices"
    functions = [VFIO_DEVICE]
    for function in sorted(group.iterdir()):
        path = f"/sys/bus/pci/devices/{function.name}"
        driver = function / "driver"
        if (
            path != VFIO_DEVICE
            and driver.exists()
            and driver.resolve().name == "vfio-pci"
        ):
            functions.append(path)
    return functions


@pin_pci(True)
def test_vfio_request_validation(uvm):
    """The /vfio endpoint rejects an invalid request body."""
    vm = uvm
    vm.spawn()
    vm.basic_config()

    # The `path` field is required.
    with pytest.raises(RuntimeError):
        vm.api.vfio.put(id="dev0")
    # Unknown fields are rejected.
    with pytest.raises(RuntimeError):
        vm.api.vfio.put(id="dev0", path=MISSING_DEVICE, foo="bar")


@pin_pci(False)
def test_vfio_requires_pci(uvm):
    """A microVM with a VFIO device does not start without PCI."""
    vm = uvm
    vm.spawn()
    vm.basic_config()
    vm.api.vfio.put(id="dev0", path=MISSING_DEVICE)
    with pytest.raises(RuntimeError, match="requires the PCIe transport"):
        vm.start()


@pin_pci(True)
def test_vfio_rejects_balloon(uvm):
    """A microVM with a VFIO device and a balloon device does not start."""
    vm = uvm
    vm.spawn()
    vm.basic_config()
    vm.api.balloon.put(amount_mib=0, deflate_on_oom=False)
    vm.api.vfio.put(id="dev0", path=MISSING_DEVICE)
    with pytest.raises(RuntimeError, match="cannot be combined with a balloon device"):
        vm.start()


@pin_pci(True)
def test_vfio_rejects_memory_hotplug(uvm):
    """A microVM with a VFIO device and hotpluggable memory does not start."""
    vm = uvm
    vm.spawn()
    vm.basic_config()
    vm.api.memory_hotplug.put(total_size_mib=1024)
    vm.api.vfio.put(id="dev0", path=MISSING_DEVICE)
    with pytest.raises(RuntimeError, match="cannot be combined with memory hotplug"):
        vm.start()


@pin_pci(True)
def test_vfio_missing_device(uvm):
    """Assigning a PCI function that does not exist fails at start."""
    vm = uvm
    vm.spawn()
    vm.basic_config()
    vm.api.vfio.put(id="dev0", path=MISSING_DEVICE)
    with pytest.raises(RuntimeError, match="Cannot determine the IOMMU group"):
        vm.start()


@needs_vfio
@pin_pci(True)
def test_vfio_passthrough(uvm):
    """Assign a host PCI function to a jailed microVM and use it from the guest."""
    vm = uvm
    host = Path(VFIO_DEVICE)
    vendor = (host / "vendor").read_text().strip().removeprefix("0x")
    device = (host / "device").read_text().strip().removeprefix("0x")
    pci_class = int((host / "class").read_text(), 16)
    host_bars = _memory_bar_sizes((host / "resource").read_text())

    _assign(vm)
    vm.start()

    # The function shows up once on the guest PCI bus.
    guest_bdfs = vm.ssh.check_output(f"lspci -Dn -d {vendor}:{device}").stdout
    guest_bdfs = [line.split()[0] for line in guest_bdfs.strip().splitlines()]
    assert len(guest_bdfs) == 1, guest_bdfs
    bdf = guest_bdfs[0]
    guest_sysfs = f"/sys/bus/pci/devices/{bdf}"

    # The guest sees every memory BAR, at its host size, and no I/O BAR.
    guest_resource = vm.ssh.check_output(f"cat {guest_sysfs}/resource").stdout
    assert _memory_bar_sizes(guest_resource) == host_bars

    # It is a single-function device.
    header_type = vm.ssh.check_output(f"setpci -s {bdf} HEADER_TYPE").stdout
    assert int(header_type, 16) & 0x80 == 0

    # A function with an interrupt pin has INTA, routed level-triggered to an
    # interrupt controller input. Enabling the device makes the guest route
    # it (ACPI _PRT or MP table on x86, device tree on aarch64).
    pin = int(vm.ssh.check_output(f"setpci -s {bdf} INTERRUPT_PIN").stdout, 16)
    if (host / "config").read_bytes()[PCI_INTERRUPT_PIN] and not (
        host / "physfn"
    ).exists():
        assert pin == 1
        vm.ssh.check_output(f"echo 1 > {guest_sysfs}/enable")
        irq = int(vm.ssh.check_output(f"cat {guest_sysfs}/irq").stdout)
        assert irq != 0
        irq_info = {
            name: vm.ssh.check_output(
                f"cat /sys/kernel/irq/{irq}/{name}"
            ).stdout.strip()
            for name in ("chip_name", "hwirq", "type")
        }
        assert irq_info["type"] == "level", irq_info
        if platform.machine() == "x86_64":
            # An IOAPIC input from 16 up.
            assert irq_info["chip_name"] == "IO-APIC", irq_info
            assert 16 <= int(irq_info["hwirq"]) <= 23, irq_info
        else:
            # A GIC SPI.
            assert "GIC" in irq_info["chip_name"], irq_info
            assert int(irq_info["hwirq"]) >= 32, irq_info
        vm.ssh.check_output(f"echo 0 > {guest_sysfs}/enable")
    else:
        assert pin == 0

    # It signals interrupts with MSI or MSI-X.
    capabilities = vm.ssh.check_output(f"lspci -vvv -s {bdf}").stdout
    assert "MSI: " in capabilities or "MSI-X: " in capabilities, capabilities

    # BAR accesses reach the device, and read all ones while memory decoding is
    # disabled, as on bare metal.
    bar_index = next(index for index, size in enumerate(host_bars) if size)
    read_bar = (
        "python3 -c 'import mmap, struct; "
        f'f = open("{guest_sysfs}/resource{bar_index}", "rb"); '
        "m = mmap.mmap(f.fileno(), mmap.PAGESIZE, prot=mmap.PROT_READ); "
        'print(hex(struct.unpack("<I", m[:4])[0]))\''
    )
    command = int(vm.ssh.check_output(f"setpci -s {bdf} COMMAND").stdout, 16)
    vm.ssh.check_output(f"setpci -s {bdf} COMMAND={command | PCI_COMMAND_MEMORY:x}")
    decoded = int(vm.ssh.check_output(read_bar).stdout, 16)
    vm.ssh.check_output(f"setpci -s {bdf} COMMAND={command & ~PCI_COMMAND_MEMORY:x}")
    assert int(vm.ssh.check_output(read_bar).stdout, 16) == 0xFFFFFFFF
    vm.ssh.check_output(f"setpci -s {bdf} COMMAND={command | PCI_COMMAND_MEMORY:x}")
    assert int(vm.ssh.check_output(read_bar).stdout, 16) == decoded
    if vendor == "10de" and pci_class >> 16 == PCI_BASE_CLASS_DISPLAY:
        # BAR0 of NVIDIA GPUs starts with the PMC_BOOT_0 register, which
        # identifies the chip and is never 0 or all ones on a working GPU.
        assert bar_index == 0 and decoded not in (0, 0xFFFFFFFF), hex(decoded)

    # The guest reboot tears the device down without a seccomp fault.
    vm.memory_monitor = None
    vm.ssh.run("reboot")
    vm.mark_killed()
    datapoints = vm.get_all_metrics()
    assert datapoints[-1]["seccomp"]["num_faults"] == 0


@needs_vfio
@pin_pci(True)
def test_vfio_blocks_snapshot(uvm):
    """A microVM with a passthrough device cannot be snapshotted."""
    vm = uvm
    _assign(vm)
    vm.start()

    vm.pause()
    with pytest.raises(RuntimeError, match="VFIO"):
        vm.api.snapshot_create.put(
            mem_file_path="/mem.snap",
            snapshot_path="/state.snap",
        )


@needs_vfio
@pin_pci(True)
def test_vfio_iommu_group(uvm):
    """Assign every function of an IOMMU group to one microVM."""
    functions = _group_functions()
    if len(functions) < 2:
        pytest.skip("the IOMMU group of the device under test has one function")
    ids = [
        ":".join(
            (Path(function) / name).read_text().strip().removeprefix("0x")
            for name in ("vendor", "device")
        )
        for function in functions
    ]

    vm = uvm
    _assign(vm, functions)
    vm.start()

    # Every function shows up on the guest PCI bus.
    for pci_id in ids:
        lines = vm.ssh.check_output(f"lspci -Dn -d {pci_id}").stdout.splitlines()
        assert len(lines) == ids.count(pci_id), (pci_id, lines)

    vm.memory_monitor = None
    vm.ssh.run("reboot")
    vm.mark_killed()
    datapoints = vm.get_all_metrics()
    assert datapoints[-1]["seccomp"]["num_faults"] == 0
