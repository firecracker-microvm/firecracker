# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test VMclock device emulation"""

import pytest

from framework.artifacts import ACPI_GUEST_KERNELS, pin_guest_kernel

pytestmark = pin_guest_kernel(ACPI_GUEST_KERNELS)


# Decorates the shared `uvm_booted` stage via same-name chaining: every booted
# VM in this module carries the vmclock test binary under /tmp/vmclock.
@pytest.fixture
def uvm_booted(uvm_booted, bin_vmclock_path):
    """Booted microVM with the vmclock test binary installed."""
    uvm_booted.ssh.scp_put(bin_vmclock_path, "/tmp/vmclock")
    return uvm_booted


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


@pytest.mark.parametrize("use_mmap", [False, True], ids=["read()", "mmap()"])
def test_vmclock_read_fields(uvm_booted, use_mmap):
    """Make sure that we expose the expected values in the VMclock struct"""
    vm = uvm_booted
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


@pytest.mark.parametrize("use_mmap", [False, True], ids=["read()", "mmap()"])
def test_snapshot_update(uvm_booted, microvm_factory, snapshot_type, use_mmap):
    """Test that `disruption_marker` and `vm_generation_counter` are updated
    upon snapshot resume"""
    basevm = uvm_booted

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


def test_vmclock_notifications(uvm_booted, microvm_factory, snapshot_type):
    """Test that Firecracker will send a notification on snapshot load"""
    basevm = uvm_booted

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
