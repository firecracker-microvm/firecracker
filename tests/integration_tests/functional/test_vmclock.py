# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test VMclock device emulation"""

import platform

import pytest


@pytest.fixture(scope="function")
def vm_with_vmclock(uvm_plain_acpi, bin_vmclock_path):
    """Create a VM with VMclock support and the `vmclock` test binary under `/tmp/vmclock`"""
    basevm = uvm_plain_acpi
    basevm.spawn()

    basevm.basic_config()
    basevm.add_net_iface()
    basevm.start()
    basevm.ssh.scp_put(bin_vmclock_path, "/tmp/vmclock")

    yield basevm


def parse_vmclock(vm, use_mmap=False):
    """Parse the VMclock struct inside the guest and return a dictionary with its fields"""

    cmd = "/tmp/vmclock -m" if use_mmap else "/tmp/vmclock -r"
    _, stdout, _ = vm.ssh.check_output(cmd)
    fields = stdout.strip().split("\n")
    if use_mmap:
        assert fields[0] == "Reading VMClock with mmap()"
    else:
        assert fields[0] == "Reading VMClock with read()"

    return dict(item.split(": ") for item in fields if item.startswith("VMCLOCK"))


def parse_vmclock_from_poll(vm, expected_notifications):
    """Parse the output of the 'vmclock -p' command in the guest"""

    _, stdout, _ = vm.ssh.check_output("cat /tmp/vmclock.out")
    fields = stdout.strip().split("\n")

    nr_notifications = 0
    for line in fields:
        if line == "Got VMClock notification":
            nr_notifications += 1

    assert nr_notifications == expected_notifications
    return dict(item.split(": ") for item in fields if item.startswith("VMCLOCK"))


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="VMClock device is currently supported only on x86 systems",
)
@pytest.mark.parametrize("use_mmap", [False, True], ids=["read()", "mmap()"])
def test_vmclock_read_fields(vm_with_vmclock, use_mmap):
    """Make sure that we expose the expected values in the VMclock struct"""
    vm = vm_with_vmclock
    vmclock = parse_vmclock(vm, use_mmap)

    assert vmclock["VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT"] == "true"
    assert vmclock["VMCLOCK_FLAG_NOTIFICATION_PRESENT"] == "true"
    assert vmclock["VMCLOCK_MAGIC"] == "0x4b4c4356"
    assert vmclock["VMCLOCK_SIZE"] == "0x1000"
    assert vmclock["VMCLOCK_VERSION"] == "1"
    assert vmclock["VMCLOCK_CLOCK_STATUS"] == "0"
    assert vmclock["VMCLOCK_COUNTER_ID"] == "255"
    assert vmclock["VMCLOCK_DISRUPTION_MARKER"] == "0"
    assert vmclock["VMCLOCK_VM_GENERATION_COUNTER"] == "0"


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="VMClock device is currently supported only on x86 systems",
)
@pytest.mark.parametrize("use_mmap", [False, True], ids=["read()", "mmap()"])
def test_snapshot_update(vm_with_vmclock, microvm_factory, snapshot_type, use_mmap):
    """Test that `disruption_marker` and `vm_generation_counter` are updated
    upon snapshot resume"""
    basevm = vm_with_vmclock

    vmclock = parse_vmclock(basevm, use_mmap)
    assert vmclock["VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT"] == "true"
    assert vmclock["VMCLOCK_FLAG_NOTIFICATION_PRESENT"] == "true"
    assert vmclock["VMCLOCK_DISRUPTION_MARKER"] == "0"
    assert vmclock["VMCLOCK_VM_GENERATION_COUNTER"] == "0"

    snapshot = basevm.make_snapshot(snapshot_type)
    basevm.kill()

    for i, vm in enumerate(
        microvm_factory.build_n_from_snapshot(snapshot, 5, incremental=True)
    ):
        vmclock = parse_vmclock(vm, use_mmap)
        assert vmclock["VMCLOCK_DISRUPTION_MARKER"] == f"{i+1}"
        assert vmclock["VMCLOCK_VM_GENERATION_COUNTER"] == f"{i+1}"


# TODO: remove this skip when we backport VMClock snapshot safety patches to 5.10 and 6.1
@pytest.mark.skip(
    reason="Skip until we get guest microVM kernels with support for the notification mechanism",
)
def test_vmclock_notifications(vm_with_vmclock, microvm_factory, snapshot_type):
    """Test that Firecracker will send a notification on snapshot load"""
    basevm = vm_with_vmclock

    # Launch vmclock utility in polling mode
    basevm.ssh.check_output("/tmp/vmclock -p > /tmp/vmclock.out 2>&1 &")

    # We should not have received any notification yet
    vmclock = parse_vmclock_from_poll(basevm, 0)
    assert vmclock["VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT"] == "true"
    assert vmclock["VMCLOCK_FLAG_NOTIFICATION_PRESENT"] == "true"
    assert vmclock["VMCLOCK_DISRUPTION_MARKER"] == "0"
    assert vmclock["VMCLOCK_VM_GENERATION_COUNTER"] == "0"

    snapshot = basevm.make_snapshot(snapshot_type)
    basevm.kill()

    for i, vm in enumerate(
        microvm_factory.build_n_from_snapshot(snapshot, 5, incremental=True)
    ):
        vmclock = parse_vmclock_from_poll(vm, i + 1)
        assert vmclock["VMCLOCK_DISRUPTION_MARKER"] == f"{i+1}"
        assert vmclock["VMCLOCK_VM_GENERATION_COUNTER"] == f"{i+1}"
