# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for verifying the steal time behavior under contention and across snapshots."""

import time


def get_steal_time_ms(vm):
    """Returns total steal time of vCPUs in VM in milliseconds"""
    _, out, _ = vm.ssh.run("grep -w '^cpu' /proc/stat")
    steal_time_tck = int(out.strip().split()[8])
    clk_tck = int(vm.ssh.run("getconf CLK_TCK").stdout)
    return steal_time_tck / clk_tck * 1000


def test_pvtime_steal_time_increases(uvm_plain):
    """
    Test that PVTime steal time increases when both vCPUs are contended on the same pCPU.
    """
    vm = uvm_plain
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    vm.start()

    # Pin both vCPUs to the same physical CPU to induce contention
    vm.pin_vcpu(0, 0)
    vm.pin_vcpu(1, 0)

    # Start two infinite loops to hog CPU time
    hog_cmd = "nohup bash -c 'while true; do :; done' >/dev/null 2>&1 &"
    vm.ssh.run(hog_cmd)
    vm.ssh.run(hog_cmd)

    # Measure before and after steal time
    steal_before = get_steal_time_ms(vm)
    time.sleep(2)
    steal_after = get_steal_time_ms(vm)

    # Require increase in steal time
    assert (
        steal_after > steal_before
    ), f"Steal time did not increase as expected. Before: {steal_before}, After: {steal_after}"


def test_pvtime_snapshot(uvm_plain, microvm_factory):
    """
    Test that PVTime steal time is preserved across snapshot/restore
    and continues increasing post-resume.
    """
    vm = uvm_plain
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    vm.start()

    vm.pin_vcpu(0, 0)
    vm.pin_vcpu(1, 0)

    hog_cmd = "nohup bash -c 'while true; do :; done' >/dev/null 2>&1 &"
    vm.ssh.run(hog_cmd)
    vm.ssh.run(hog_cmd)

    # Snapshot pre-steal time
    steal_before = get_steal_time_ms(vm)

    snapshot = vm.snapshot_full()
    vm.kill()

    # Restore microVM from snapshot and resume
    restored_vm = microvm_factory.build()
    restored_vm.spawn()
    restored_vm.restore_from_snapshot(snapshot, resume=False)
    snapshot.delete()

    restored_vm.pin_vcpu(0, 0)
    restored_vm.pin_vcpu(1, 0)
    restored_vm.resume()

    # Steal time just after restoring
    steal_after_snap = get_steal_time_ms(restored_vm)

    # Ensure steal time persisted
    tolerance = 10000  # 10.0 seconds tolerance for persistence check
    persisted = (
        steal_before < steal_after_snap and steal_after_snap - steal_before < tolerance
    )
    assert persisted, "Steal time did not persist through snapshot"

    time.sleep(2)

    # Steal time after running resumed VM
    steal_after_resume = get_steal_time_ms(restored_vm)

    # Ensure steal time continued increasing
    assert (
        steal_after_resume > steal_after_snap
    ), "Steal time failed to increase after resume"
