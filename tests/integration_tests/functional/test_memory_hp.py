# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for verifying the virtio-mem is working correctly"""

import time

import pytest


def test_virtio_mem_detected(uvm_plain_6_1):
    """
    Check that the guest kernel has enabled PV steal time.
    """
    uvm = uvm_plain_6_1
    uvm.spawn()
    uvm.memory_monitor = None
    uvm.basic_config(
        boot_args="console=ttyS0 reboot=k panic=1 memhp_default_state=online_movable"
    )
    uvm.add_net_iface()
    uvm.api.memory_hp.put(total_size_mib=1024)
    uvm.start()

    _, stdout, _ = uvm.ssh.check_output("dmesg | grep 'virtio_mem'")
    for line in stdout.splitlines():
        _, key, value = line.strip().split(":")
        key = key.strip()
        value = int(value.strip(), base=0)
        match key:
            case "start address":
                assert value == (512 << 30), "start address doesn't match"
            case "region size":
                assert value == 1024 << 20, "region size doesn't match"
            case "device block size":
                assert value == 2 << 20, "block size doesn't match"
            case "plugged size":
                assert value == 0, "plugged size doesn't match"
            case "requested size":
                assert value == 0, "requested size doesn't match"
            case _:
                continue


def wait_memory_hp(uvm, size, timeout=10):
    """
    Wait for the memory hotplug to complete.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if uvm.api.memory_hp.get().json()["plugged_size_mib"] == size:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("Hotplug timeout")


def get_mem_total(uvm):
    """
    Get the total memory of the guest.
    """
    _, stdout, _ = uvm.ssh.check_output("cat /proc/meminfo | grep MemTotal")
    return int(stdout.strip().split()[1])


def get_mem_available(uvm):
    """
    Get the total memory of the guest.
    """
    _, stdout, _ = uvm.ssh.check_output("cat /proc/meminfo | grep MemAvailable")
    return int(stdout.strip().split()[1])


@pytest.mark.parametrize("restored", ["NO", "BEFORE", "AFTER"])
def test_virtio_mem_works(microvm_factory, uvm_plain_6_1, restored):
    """
    Check that the guest kernel has enabled PV steal time.
    """
    uvm = uvm_plain_6_1
    uvm.help.enable_console()
    uvm.spawn()
    uvm.memory_monitor = None
    uvm.basic_config(
        boot_args="console=ttyS0 reboot=k panic=1 memhp_default_state=online_movable"
    )
    uvm.add_net_iface()
    uvm.api.memory_hp.put(total_size_mib=1024)
    uvm.start()

    if restored == "BEFORE":
        snapshot = uvm.snapshot_full()
        restored_vm = microvm_factory.build()
        restored_vm.help.enable_console()
        restored_vm.spawn()
        restored_vm.restore_from_snapshot(snapshot, resume=True)
        uvm = restored_vm

    mem_total_before = get_mem_total(uvm)
    uvm.api.memory_hp.patch(requested_size_mib=1024)
    wait_memory_hp(uvm, 1024)
    _, stdout, _ = uvm.ssh.check_output(
        "dmesg | grep 'virtio_mem' | grep 'requested size' | tail -1"
    )
    assert int(stdout.strip().split(":")[-1].strip(), base=0) == 1024 << 20

    mem_total_after = get_mem_total(uvm)
    assert mem_total_after == mem_total_before + 1024 * 1024

    if restored == "AFTER":
        snapshot = uvm.snapshot_full()
        restored_vm = microvm_factory.build()
        restored_vm.help.enable_console()
        restored_vm.spawn()
        restored_vm.restore_from_snapshot(snapshot, resume=True)
        uvm = restored_vm

    mem_available = get_mem_available(uvm)
    dd_count = mem_available * 95 // 100 // 1024
    _, stdout, _ = uvm.ssh.check_output(
        f"dd if=/dev/urandom bs=1M count={dd_count} | wc -c"
    )
    assert int(stdout.strip()) == dd_count * 1024 * 1024

    uvm.api.memory_hp.patch(requested_size_mib=0)
    wait_memory_hp(uvm, 0)
    _, stdout, _ = uvm.ssh.check_output(
        "dmesg | grep 'virtio_mem' | grep 'requested size' | tail -1"
    )
    assert int(stdout.strip().split(":")[-1].strip(), base=0) == 0

    mem_total_after = get_mem_total(uvm)
    assert mem_total_after == mem_total_before

    uvm.api.memory_hp.patch(requested_size_mib=1024)
    wait_memory_hp(uvm, 1024)
    _, stdout, _ = uvm.ssh.check_output(
        "dmesg | grep 'virtio_mem' | grep 'requested size' | tail -1"
    )
    assert int(stdout.strip().split(":")[-1].strip(), base=0) == 1024 << 20

    mem_total_after = get_mem_total(uvm)
    assert mem_total_after == mem_total_before + 1024 * 1024
