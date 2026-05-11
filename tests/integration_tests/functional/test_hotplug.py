# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for PCI device hotplug"""

import os

import pytest

import host_tools.drive as drive_tools
import host_tools.network as net_tools

VIRTIO_PCI_VENDOR_ID = 0x1AF4
VIRTIO_PCI_DEVICE_ID_NET = 0x1041
VIRTIO_PCI_DEVICE_ID_BLOCK = 0x1042
VIRTIO_PCI_DEVICE_ID_PMEM = 0x105B


def test_hotplug_block(uvm_any_with_pci):
    """
    Test hotplugging a block device after VM start.
    Test that the device appears in lspci and is usable.
    Test that invalid hotplug request are rejected.
    Test hot-unplugging the device.
    """
    vm = uvm_any_with_pci

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


def test_hotplug_pmem(uvm_any_with_pci):
    """
    Test hotplugging a pmem device after VM start.
    Test that the device appears in lspci and is usable.
    Test that invalid hotplug request are rejected.
    Test hot-unplugging the device.
    """
    vm = uvm_any_with_pci

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


def test_hotplug_net(uvm_any_with_pci):
    """
    Test hotplugging a net device after VM start.
    Test that the device appears in lspci and is usable.
    Test that invalid hotplug request are rejected.
    Test hot-unplugging the device.
    """
    vm = uvm_any_with_pci

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


def test_unplug_root_pmem(microvm_factory, guest_kernel_acpi, rootfs):
    """
    Unplugging the root pmem device must be rejected.
    """
    vm = microvm_factory.build(guest_kernel_acpi, rootfs, pci=True)
    vm.memory_monitor = None
    vm.monitors = []
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_pmem("pmem_root", rootfs, root_device=True)
    vm.add_net_iface()
    vm.start()

    with pytest.raises(RuntimeError, match="Cannot unplug root device"):
        vm.api.pmem.delete("pmem_root")


def test_hotplug_no_pci(uvm_any_without_pci):
    """
    Hotplugging and unplugging any device type must be rejected when PCI is not
    enabled.
    """
    vm = uvm_any_without_pci

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


def test_hotplug_preserved_after_snapshot(uvm_any_with_pci, microvm_factory):
    """
    Test that a hotplugged device survives a full snapshot/restore cycle.
    """
    vm = uvm_any_with_pci

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


def test_hotplug_max_devices(uvm_any_with_pci):
    """
    Test that hotplugging more devices than available PCI slots is rejected.
    """
    pci_max_slots = 32
    vm = uvm_any_with_pci

    # Count how many PCI slots are already in use
    _, lspci_initial, _ = vm.ssh.check_output("lspci -n")
    used_slots = len(lspci_initial.strip().splitlines())
    free_slots = pci_max_slots - used_slots

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

    # Verify all PCI slots are occupied
    vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")
    _, lspci_full, _ = vm.ssh.check_output("lspci -n")
    assert len(lspci_full.strip().splitlines()) == pci_max_slots

    # The next hotplug must fail — no PCI slots left
    host_file = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "block_overflow"), size=1
    )
    with pytest.raises(
        RuntimeError, match="Could not find an available device slot on the PCI bus"
    ):
        vm.api.drive.put(
            drive_id="block_overflow",
            path_on_host=vm.create_jailed_resource(host_file.path),
            is_root_device=False,
            is_read_only=False,
        )

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
    _, lspci, _ = vm.ssh.check_output("lspci -n")
    assert len(lspci.strip().splitlines()) == used_slots

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

    # Verify all PCI slots are occupied again
    vm.ssh.check_output("echo 1 > /sys/bus/pci/rescan")
    _, lspci, _ = vm.ssh.check_output("lspci -n")
    assert len(lspci.strip().splitlines()) == pci_max_slots
