# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for verifying the PVTime device behavior under contention and across snapshots."""

import re
import time


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
    vm.pin_vmm(1)
    vm.pin_api(2)

    # Start two infinite loops to hog CPU time
    hog_cmd = "nohup bash -c 'while true; do :; done' >/dev/null 2>&1 &"
    vm.ssh.run(hog_cmd)
    vm.ssh.run(hog_cmd)

    time.sleep(2)

    # Measure steal time before
    _, out_before, _ = vm.ssh.run("grep '^cpu[0-9]' /proc/stat")
    steal_before = sum(
        int(re.split(r"\s+", line.strip())[8])
        for line in out_before.strip().splitlines()
    )

    time.sleep(2)

    # Measure steal time after
    _, out_after, _ = vm.ssh.run("grep '^cpu[0-9]' /proc/stat")
    steal_after = sum(
        int(re.split(r"\s+", line.strip())[8])
        for line in out_after.strip().splitlines()
    )

    # Require increase in steal time
    assert (
        steal_after - steal_before >= 200
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
    vm.pin_vmm(1)
    vm.pin_api(2)

    hog_cmd = "nohup bash -c 'while true; do :; done' >/dev/null 2>&1 &"
    vm.ssh.run(hog_cmd)
    vm.ssh.run(hog_cmd)

    time.sleep(1)

    # Snapshot pre-steal time
    _, out_before_snap, _ = vm.ssh.run("grep '^cpu[0-9]' /proc/stat")
    steal_before = [
        int(re.split(r"\s+", line.strip())[8])
        for line in out_before_snap.strip().splitlines()
    ]

    snapshot = vm.snapshot_full()
    vm.kill()

    # Restore microVM from snapshot and resume
    restored_vm = microvm_factory.build()
    restored_vm.spawn()
    restored_vm.restore_from_snapshot(snapshot, resume=False)
    snapshot.delete()

    restored_vm.pin_vcpu(0, 0)
    restored_vm.pin_vcpu(1, 0)
    restored_vm.pin_vmm(1)
    restored_vm.pin_api(2)
    restored_vm.resume()

    time.sleep(1)

    # Steal time just after restoring
    _, out_after_snap, _ = restored_vm.ssh.run("grep '^cpu[0-9]' /proc/stat")
    steal_after_snap = [
        int(re.split(r"\s+", line.strip())[8])
        for line in out_after_snap.strip().splitlines()
    ]

    time.sleep(2)

    # Steal time after running resumed VM
    _, out_after_resume, _ = restored_vm.ssh.run("grep '^cpu[0-9]' /proc/stat")
    steal_after_resume = [
        int(re.split(r"\s+", line.strip())[8])
        for line in out_after_resume.strip().splitlines()
    ]

    # Ensure steal time persisted and continued increasing
    persisted = sum(steal_before) + 100 <= sum(steal_after_snap)
    increased = sum(steal_after_resume) > sum(steal_after_snap)

    assert (
        persisted and increased
    ), "Steal time did not persist through snapshot or failed to increase after resume"
