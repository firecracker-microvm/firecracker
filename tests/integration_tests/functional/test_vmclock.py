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


def parse_vmclock(vm):
    """Parse the VMclock struct inside the guest and return a dictionary with its fields"""
    _, stdout, _ = vm.ssh.check_output("/tmp/vmclock")
    fields = stdout.strip().split("\n")
    return dict(item.split(": ") for item in fields)


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="VMClock device is currently supported only on x86 systems",
)
def test_vmclock_fields(vm_with_vmclock):
    """Make sure that we expose the expected values in the VMclock struct"""
    vm = vm_with_vmclock
    vmclock = parse_vmclock(vm)

    assert vmclock["VMCLOCK_MAGIC"] == "0x4b4c4356"
    assert vmclock["VMCLOCK_SIZE"] == "0x1000"
    assert vmclock["VMCLOCK_VERSION"] == "1"
    assert vmclock["VMCLOCK_CLOCK_STATUS"] == "0"
    assert vmclock["VMCLOCK_COUNTER_ID"] == "255"
    assert vmclock["VMCLOCK_DISRUPTION_MARKER"] == "0"


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="VMClock device is currently supported only on x86 systems",
)
def test_snapshot_update(vm_with_vmclock, microvm_factory, snapshot_type):
    """Test that `disruption_marker` is updated upon snapshot resume"""
    basevm = vm_with_vmclock

    vmclock = parse_vmclock(basevm)
    assert vmclock["VMCLOCK_DISRUPTION_MARKER"] == "0"

    snapshot = basevm.make_snapshot(snapshot_type)
    basevm.kill()

    for i, vm in enumerate(
        microvm_factory.build_n_from_snapshot(snapshot, 5, incremental=True)
    ):
        vmclock = parse_vmclock(vm)
        assert vmclock["VMCLOCK_DISRUPTION_MARKER"] == f"{i+1}"
