# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for PCI device hotplug"""

import os

import pytest

import host_tools.drive as drive_tools
import host_tools.network as net_tools
from framework.artifacts import ACPI_GUEST_KERNELS, pin_guest_kernel, pin_pci
from framework.utils_cpu_templates import ALL_CPU_TEMPLATES, pin_cpu_template
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend
from integration_tests.functional.test_max_devices import max_devices

VIRTIO_PCI_VENDOR_ID = 0x1AF4
VIRTIO_PCI_DEVICE_ID_NET = 0x1041
VIRTIO_PCI_DEVICE_ID_BLOCK = 0x1042
VIRTIO_PCI_DEVICE_ID_PMEM = 0x105B
# Nitro Security Module. Provided by the hypervisor to confidential enclaves,
# so it is not one of the device slots the VMM gets to fill.
VIRTIO_PCI_DEVICE_ID_NSM = 0x1061


def count_vmm_virtio_devices(vm):
    """Count virtio devices the VMM attached, as seen by the guest.

    Not the same as counting `lspci` lines: those also include host and PCI
    bridges, and an enclave guest has dozens of PCIe root ports.
    """
    _, lspci, _ = vm.ssh.check_output("lspci -n")
    return sum(
        f"{VIRTIO_PCI_VENDOR_ID:04x}:" in line
        and f"{VIRTIO_PCI_DEVICE_ID_NSM:04x}" not in line
        for line in lspci.splitlines()
    )


# Not pinned as a module: hot-plugging works on enclaves, so tests that can run
# there do, skipping only their hot-unplug half. The rest carry their own pin.


# Shadows the shared stage: enclaves reject runtime hotplug unless started with
# `hotplug_mode`, which the shared stage does not pass. `uvm_restored` resolves
# `uvm_booted` by name, so `uvm_any` picks this up for both lifecycle states.
@pytest.fixture
def uvm_booted(uvm_configured):
    """Booted microVM that accepts hotplugged devices."""
    start_kwargs = {"hotplug_mode": True} if uvm_configured.backend.is_enclave else {}
    uvm_configured.add_net_iface()
    uvm_configured.start(**start_kwargs)
    return uvm_configured


@pin_pci(True)
@pin_cpu_template(ALL_CPU_TEMPLATES)
@pin_guest_kernel(ACPI_GUEST_KERNELS)
def test_hotplug_block(uvm_any):
    """
    Test hotplugging a block device after VM start.
    Test that the device appears in lspci and is usable.
    Test that invalid hotplug request are rejected.
    Test hot-unplugging the device, on backends that support it.
    """
    vm = uvm_any

    # Snapshot lspci output before hotplug
    _, lspci_before, _ = vm.ssh.check_output("lspci -n")

    # Hotplug a block device
    host_file = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "block0"), size=4)
    vm.api.drive.put(
        drive_id="block0",
        path_on_host=vm.create_jailed_resource(host_file.path),
        is_root_device=False,
        is_read_only=False,
        rate_limiter={
            "ops": {"size": 100, "refill_time": 100},
        },
    )

    # Rescan PCI bus since no hotplug notification mechanism exists yet
    vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")

    # Verify a new virtio-block device entry appeared in lspci
    _, lspci_after, _ = vm.ssh.check_output("lspci -n")
    new_entries = set(lspci_after.splitlines()) - set(lspci_before.splitlines())
    assert len(new_entries) == 1
    entry = new_entries.pop()
    assert f"{VIRTIO_PCI_VENDOR_ID:04x}:{VIRTIO_PCI_DEVICE_ID_BLOCK:04x}" in entry

    # Discover the block device node from the PCI BDF via sysfs
    bdf = entry.split()[0]
    _, dev_name, _ = vm.ssh.check_output(
        f"ls /sys/bus/pci/devices/0000:{bdf}/virtio*/block/"
    )
    dev_path = f"/dev/{dev_name.strip()}"

    # Ensure the device is usable by writing a file to it and reading it back
    vm.ssh.check_output("mkdir -p /tmp/block0_mnt")
    vm.ssh.check_output(f"mount {dev_path} /tmp/block0_mnt")
    vm.ssh.check_output("echo hotplug_test > /tmp/block0_mnt/test")
    _, stdout, _ = vm.ssh.check_output("cat /tmp/block0_mnt/test")
    assert stdout.strip() == "hotplug_test"

    # Hotplugging a device with a duplicate ID must be rejected
    with pytest.raises(RuntimeError, match="Device ID in use"):
        vm.api.drive.put(
            drive_id="block0",
            path_on_host=vm.create_jailed_resource(host_file.path),
            is_root_device=False,
            is_read_only=False,
        )

    # Hotplugging a root device must be rejected
    with pytest.raises(RuntimeError, match="A root block device already exists"):
        vm.api.drive.put(
            drive_id="block_root",
            path_on_host=vm.create_jailed_resource(host_file.path),
            is_root_device=True,
            is_read_only=False,
        )

    # Hotplugging with a non-existent backing file must be rejected
    with pytest.raises(RuntimeError, match="No such file or directory"):
        vm.api.drive.put(
            drive_id="block_bad",
            path_on_host="/nonexistent",
            is_root_device=False,
            is_read_only=False,
        )

    # Verify no further devices appeared after the rejected requests
    vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")
    _, lspci_final, _ = vm.ssh.check_output("lspci -n")
    assert lspci_final == lspci_after

    if not vm.backend.supports_hot_unplug:
        return

    # Unplugging a non-existent device must be rejected
    with pytest.raises(RuntimeError, match="Device not found"):
        vm.api.drive.delete("nonexistent")

    # Unplugging the root block device must be rejected
    with pytest.raises(RuntimeError, match="Cannot unplug root device"):
        vm.api.drive.delete("rootfs")

    # No unplug notification mechanism exists yet, so the guest needs to
    # gracefully prepare for the detach before the host issues the unplug.
    vm.ssh.check_output("umount /tmp/block0_mnt")
    vm.ssh.check_output(f"echo 1 > /sys/bus/pci/devices/0000:{bdf}/remove")

    # Unplug the block device
    vm.api.drive.delete("block0")

    # Verify the device is gone
    _, lspci_after_unplug, _ = vm.ssh.check_output("lspci -n")
    assert lspci_after_unplug == lspci_before

    # Unplugging the same device again must be rejected
    with pytest.raises(RuntimeError, match="Device not found"):
        vm.api.drive.delete("block0")


# KVM-only: virtio-pmem has no Nitro Enclave transport.
@pin_vm_backend(VM_BACKEND_KVM)
@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pin_pci(True)
@pin_cpu_template(ALL_CPU_TEMPLATES)
def test_hotplug_pmem(uvm_any):
    """
    Test hotplugging a pmem device after VM start.
    Test that the device appears in lspci and is usable.
    Test that invalid hotplug request are rejected.
    Test hot-unplugging the device.
    """
    vm = uvm_any

    # Snapshot lspci output before hotplug
    _, lspci_before, _ = vm.ssh.check_output("lspci -n")

    # Hotplug a pmem device
    host_file = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "pmem0"), size=4)
    vm.api.pmem.put(
        id="pmem0",
        path_on_host=vm.create_jailed_resource(host_file.path),
        root_device=False,
        read_only=False,
    )

    # Rescan PCI bus since no hotplug notification mechanism exists yet
    vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")

    # Verify a new virtio-pmem device entry appeared in lspci
    _, lspci_after, _ = vm.ssh.check_output("lspci -n")
    new_entries = set(lspci_after.splitlines()) - set(lspci_before.splitlines())
    assert len(new_entries) == 1
    entry = new_entries.pop()
    assert f"{VIRTIO_PCI_VENDOR_ID:04x}:{VIRTIO_PCI_DEVICE_ID_PMEM:04x}" in entry

    # Discover the pmem device node from the PCI BDF via sysfs.
    # The NVDIMM subsystem in the guest creates the ndbus/region/namespace/block
    # hierarchy asynchronously after driver probe, so we need to wait for it.
    vm.ssh.check_output("sleep 1")
    bdf = entry.split()[0]
    _, dev_name, _ = vm.ssh.check_output(
        f"ls /sys/bus/pci/devices/0000:{bdf}/virtio*/ndbus*/region*/namespace*/block/"
    )
    dev_path = f"/dev/{dev_name.strip()}"

    # Ensure the device is usable by writing a file to it and reading it back
    vm.ssh.check_output("mkdir -p /tmp/pmem0_mnt")
    vm.ssh.check_output(f"mount {dev_path} /tmp/pmem0_mnt")
    vm.ssh.check_output("echo hotplug_test > /tmp/pmem0_mnt/test")
    _, stdout, _ = vm.ssh.check_output("cat /tmp/pmem0_mnt/test")
    assert stdout.strip() == "hotplug_test"

    # Hotplugging a root pmem device must be rejected
    with pytest.raises(RuntimeError, match="Attempt to add pmem as a root device"):
        vm.api.pmem.put(
            id="pmem_root",
            path_on_host=vm.create_jailed_resource(host_file.path),
            root_device=True,
            read_only=False,
        )

    # Hotplugging a device with a duplicate ID must be rejected
    with pytest.raises(RuntimeError, match="Device ID in use"):
        vm.api.pmem.put(
            id="pmem0",
            path_on_host=vm.create_jailed_resource(host_file.path),
            root_device=False,
            read_only=False,
        )

    # Hotplugging with a non-existent backing file must be rejected
    with pytest.raises(RuntimeError, match="No such file or directory"):
        vm.api.pmem.put(
            id="pmem_bad",
            path_on_host="/nonexistent",
            root_device=False,
            read_only=False,
        )

    # Verify no further devices appeared after the rejected requests
    vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")
    _, lspci_final, _ = vm.ssh.check_output("lspci -n")
    assert lspci_final == lspci_after

    # Unplugging a non-existent device must be rejected
    with pytest.raises(RuntimeError, match="Device not found"):
        vm.api.pmem.delete("nonexistent")

    # No unplug notification mechanism exists yet, so the guest needs to
    # gracefully prepare for the detach before the host issues the unplug.
    vm.ssh.check_output("umount /tmp/pmem0_mnt")
    vm.ssh.check_output(f"echo 1 > /sys/bus/pci/devices/0000:{bdf}/remove")

    # Unplug the pmem device
    vm.api.pmem.delete("pmem0")

    # Verify the device is gone
    _, lspci_after_unplug, _ = vm.ssh.check_output("lspci -n")
    assert lspci_after_unplug == lspci_before

    # Unplugging the same device again must be rejected
    with pytest.raises(RuntimeError, match="Device not found"):
        vm.api.pmem.delete("pmem0")


@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pin_pci(True)
@pin_cpu_template(ALL_CPU_TEMPLATES)
def test_hotplug_net(uvm_any):
    """
    Test hotplugging a net device after VM start.
    Test that the device appears in lspci and is usable.
    Test that invalid hotplug request are rejected.
    Test hot-unplugging the device, on backends that support it.
    """
    vm = uvm_any

    # Snapshot lspci output before hotplug
    _, lspci_before, _ = vm.ssh.check_output("lspci -n")

    # Hotplug a network device
    iface1 = net_tools.NetIfaceConfig.with_id(1)
    vm.netns.add_tap(iface1.tap_name, ip=f"{iface1.host_ip}/{iface1.netmask_len}")
    vm.api.network.put(
        iface_id=iface1.dev_name,
        host_dev_name=iface1.tap_name,
        guest_mac=iface1.guest_mac,
    )

    # Rescan PCI bus since no hotplug notification mechanism exists yet
    vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")

    # Verify a new net device entry appeared in lspci
    _, lspci_after, _ = vm.ssh.check_output("lspci -n")
    new_entries = set(lspci_after.splitlines()) - set(lspci_before.splitlines())
    assert len(new_entries) == 1
    entry = new_entries.pop()
    assert f"{VIRTIO_PCI_VENDOR_ID:04x}:{VIRTIO_PCI_DEVICE_ID_NET:04x}" in entry

    # Discover the net interface name from the PCI BDF via sysfs
    bdf = entry.split()[0]
    _, iface_name, _ = vm.ssh.check_output(
        f"ls /sys/bus/pci/devices/0000:{bdf}/virtio*/net/"
    )
    iface_name = iface_name.strip()

    # Verify the hotplugged interface is usable
    vm.ssh.check_output(f"ip link show {iface_name}")
    vm.ssh.check_output(
        f"ip addr add {iface1.guest_ip}/{iface1.netmask_len} dev {iface_name}"
    )
    vm.ssh.check_output(f"ip link set {iface_name} up")

    # Ping the host from the guest through the hotplugged interface
    _, stdout, _ = vm.ssh.check_output(f"ping -c 3 -W 3 {iface1.host_ip}")
    assert "3 packets transmitted, 3 received" in stdout

    # Hotplugging a device with a duplicate ID must be rejected
    iface2 = net_tools.NetIfaceConfig.with_id(2)
    with pytest.raises(RuntimeError, match="Device ID in use"):
        vm.api.network.put(
            iface_id=iface1.dev_name,
            host_dev_name=iface2.tap_name,
            guest_mac=iface2.guest_mac,
        )

    # Hotplugging a device with a duplicate MAC must be rejected
    with pytest.raises(RuntimeError, match="The MAC address is already in use"):
        vm.api.network.put(
            iface_id=iface2.dev_name,
            host_dev_name=iface2.tap_name,
            guest_mac=iface1.guest_mac,
        )

    # Hotplugging a device that reuses the same TAP must be rejected
    with pytest.raises(RuntimeError, match="Resource busy"):
        vm.api.network.put(
            iface_id=iface2.dev_name,
            host_dev_name=iface1.tap_name,
            guest_mac=iface2.guest_mac,
        )

    # Hotplugging with a non-existent tap device must be rejected
    with pytest.raises(RuntimeError, match="Open tap device failed"):
        vm.api.network.put(
            iface_id="eth_bad",
            host_dev_name="nonexistent_tap",
        )

    # Verify no further devices appeared after the rejected requests
    vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")
    _, lspci_final, _ = vm.ssh.check_output("lspci -n")
    assert lspci_final == lspci_after

    if not vm.backend.supports_hot_unplug:
        return

    # Unplugging a non-existent device must be rejected
    with pytest.raises(RuntimeError, match="Device not found"):
        vm.api.network.delete("nonexistent")

    # No unplug notification mechanism exists yet, so the guest needs to
    # gracefully prepare for the detach before the host issues the unplug.
    vm.ssh.check_output(f"ip link set {iface_name} down")
    vm.ssh.check_output(f"echo 1 > /sys/bus/pci/devices/0000:{bdf}/remove")

    # Unplug the net device
    vm.api.network.delete(iface1.dev_name)

    # Verify the device is gone
    _, lspci_after_unplug, _ = vm.ssh.check_output("lspci -n")
    assert lspci_after_unplug == lspci_before

    # Unplugging the same device again must be rejected
    with pytest.raises(RuntimeError, match="Device not found"):
        vm.api.network.delete(iface1.dev_name)


# KVM-only: virtio-pmem has no Nitro Enclave transport.
@pin_vm_backend(VM_BACKEND_KVM)
@pin_guest_kernel(ACPI_GUEST_KERNELS)
def test_unplug_root_pmem(microvm_factory, vm_backend, guest_kernel, rootfs):
    """
    Unplugging the root pmem device must be rejected.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True, backend=vm_backend)
    vm.memory_monitor = None
    vm.monitors = []
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_pmem("pmem_root", rootfs, root_device=True)
    vm.add_net_iface()
    vm.start()

    with pytest.raises(RuntimeError, match="Cannot unplug root device"):
        vm.api.pmem.delete("pmem_root")


# KVM-only: pinned to MMIO, and hotplugs virtio-pmem. Enclaves have neither.
@pin_vm_backend(VM_BACKEND_KVM)
@pin_pci(False)
@pin_cpu_template(ALL_CPU_TEMPLATES)
def test_hotplug_no_pci(uvm_any):
    """
    Hotplugging and unplugging any device type must be rejected when PCI is not
    enabled.
    """
    vm = uvm_any

    host_file = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "disk"), size=4)

    with pytest.raises(RuntimeError, match="PCI is not enabled"):
        vm.api.drive.put(
            drive_id="block0",
            path_on_host=vm.create_jailed_resource(host_file.path),
            is_root_device=False,
            is_read_only=False,
        )

    with pytest.raises(RuntimeError, match="PCI is not enabled"):
        vm.api.pmem.put(
            id="pmem0",
            path_on_host=vm.create_jailed_resource(host_file.path),
            root_device=False,
            read_only=False,
        )

    iface1 = net_tools.NetIfaceConfig.with_id(1)
    vm.netns.add_tap(iface1.tap_name, ip=f"{iface1.host_ip}/{iface1.netmask_len}")
    with pytest.raises(RuntimeError, match="PCI is not enabled"):
        vm.api.network.put(
            iface_id=iface1.dev_name,
            host_dev_name=iface1.tap_name,
            guest_mac=iface1.guest_mac,
        )

    with pytest.raises(RuntimeError, match="PCI is not enabled"):
        vm.api.drive.delete("block0")

    with pytest.raises(RuntimeError, match="PCI is not enabled"):
        vm.api.pmem.delete("pmem0")

    with pytest.raises(RuntimeError, match="PCI is not enabled"):
        vm.api.network.delete("eth0")


# KVM-only: snapshot/restore is not available on enclave VMs.
@pin_vm_backend(VM_BACKEND_KVM)
@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pin_pci(True)
@pin_cpu_template(ALL_CPU_TEMPLATES)
def test_hotplug_preserved_after_snapshot(uvm_any, microvm_factory):
    """
    Test that a hotplugged device survives a full snapshot/restore cycle.
    """
    vm = uvm_any

    # Snapshot lspci output before hotplug
    _, lspci_before, _ = vm.ssh.check_output("lspci -n")

    # Hotplug a block device
    host_file = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "block0"), size=4)
    vm.api.drive.put(
        drive_id="block0",
        path_on_host=vm.create_jailed_resource(host_file.path),
        is_root_device=False,
        is_read_only=False,
    )
    vm.disks["block0"] = host_file.path

    # Take a full snapshot and restore
    snapshot = vm.snapshot_full()
    restored_vm = microvm_factory.build_from_snapshot(snapshot)
    restored_vm.resume()

    # Rescan PCI bus since no hotplug notification mechanism exists yet
    restored_vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")

    # Verify a new virtio-block device entry appeared in lspci
    _, lspci_after, _ = restored_vm.ssh.check_output("lspci -n")
    new_entries = set(lspci_after.splitlines()) - set(lspci_before.splitlines())
    assert len(new_entries) == 1
    entry = new_entries.pop()
    assert f"{VIRTIO_PCI_VENDOR_ID:04x}:{VIRTIO_PCI_DEVICE_ID_BLOCK:04x}" in entry

    # Discover the block device node from the PCI BDF via sysfs
    bdf = entry.split()[0]
    _, dev_name, _ = restored_vm.ssh.check_output(
        f"ls /sys/bus/pci/devices/0000:{bdf}/virtio*/block/"
    )
    dev_path = f"/dev/{dev_name.strip()}"

    # Ensure the device is usable by writing a file to it and reading it back
    restored_vm.ssh.check_output("mkdir -p /tmp/block0_mnt")
    restored_vm.ssh.check_output(f"mount {dev_path} /tmp/block0_mnt")
    restored_vm.ssh.check_output("echo hotplug_test > /tmp/block0_mnt/test")
    _, stdout, _ = restored_vm.ssh.check_output("cat /tmp/block0_mnt/test")
    assert stdout.strip() == "hotplug_test"


@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pin_pci(True)
@pin_cpu_template(ALL_CPU_TEMPLATES)
def test_hotplug_max_devices(uvm_any):
    """
    Test that hotplugging past the backend's device ceiling is rejected.

    The ceiling and the resulting error are backend-specific: KVM runs out of
    slots on its single PCI bus, an enclave runs out of NE device slots.
    """
    vm = uvm_any
    device_ceiling = max_devices(vm)

    _, lspci_initial, _ = vm.ssh.check_output("lspci -n")
    used = count_vmm_virtio_devices(vm)
    free_slots = device_ceiling - used

    for i in range(free_slots):
        host_file = drive_tools.FilesystemFile(
            os.path.join(vm.fsfiles, f"block{i}"), size=1
        )
        vm.api.drive.put(
            drive_id=f"block{i}",
            path_on_host=vm.create_jailed_resource(host_file.path),
            is_root_device=False,
            is_read_only=False,
        )

    # Verify every slot is now taken
    vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")
    _, lspci_full, _ = vm.ssh.check_output("lspci -n")
    assert count_vmm_virtio_devices(vm) == device_ceiling

    # The next hotplug must fail — no slots left. KVM reports the exhausted PCI
    # bus; the enclave fails in the NE_ADD_DEVICE ioctl.
    expected_error = (
        "NE_ADD_DEVICE"
        if vm.backend.is_enclave
        else "Could not find an available device slot on the PCI bus"
    )
    host_file = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "block_overflow"), size=1
    )
    with pytest.raises(RuntimeError, match=expected_error):
        vm.api.drive.put(
            drive_id="block_overflow",
            path_on_host=vm.create_jailed_resource(host_file.path),
            is_root_device=False,
            is_read_only=False,
        )

    if not vm.backend.supports_hot_unplug:
        return

    # Remove the devices from the guest first
    new_bdfs = [
        l.split()[0]
        for l in set(lspci_full.strip().splitlines())
        - set(lspci_initial.strip().splitlines())
    ]
    for bdf in new_bdfs:
        vm.ssh.check_output(f"echo 1 > /sys/bus/pci/devices/0000:{bdf}/remove")

    # Then unplug all hotplugged devices via the API
    for i in range(free_slots):
        vm.api.drive.delete(f"block{i}")

    # Verify we're back to the initial number of devices
    assert count_vmm_virtio_devices(vm) == used

    # Re-plug all devices to verify the slots were truly freed
    for i in range(free_slots):
        host_file = drive_tools.FilesystemFile(
            os.path.join(vm.fsfiles, f"block_re{i}"), size=1
        )
        vm.api.drive.put(
            drive_id=f"block_re{i}",
            path_on_host=vm.create_jailed_resource(host_file.path),
            is_root_device=False,
            is_read_only=False,
        )

    # Verify every slot is occupied again
    vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")
    assert count_vmm_virtio_devices(vm) == device_ceiling
