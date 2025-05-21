# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for Firecracker's huge pages support"""
import signal
import time

import pytest

from framework import utils
from framework.microvm import HugePagesConfig
from framework.properties import global_props
from framework.utils_ftrace import ftrace_events


def check_hugetlbfs_in_use(pid: int, allocation_name: str):
    """Asserts that the process with the given `pid` is using hugetlbfs pages somewhere.

    `allocation_name` should be the name of the smaps entry for which we want to verify that huge pages are used.
    For memfd-backed guest memory, this would be "memfd:guest_mem" (the `guest_mem` part originating from the name
    we give the memfd in memory.rs), for anonymous memory this would be "/anon_hugepage".
    Note: in our testing, we do not currently configure vhost-user-blk devices, so we only exercise
    the "/anon_hugepage" case.
    """

    # Format of a sample smaps entry:
    #   7fc2bc400000-7fc2cc400000 rw-s 00000000 00:10 25488401                   /anon_hugepage
    #   Size:             262144 kB
    #   KernelPageSize:     2048 kB
    #   MMUPageSize:        2048 kB
    #   Rss:                   0 kB
    #   Pss:                   0 kB
    #   Pss_Dirty:             0 kB
    #   Shared_Clean:          0 kB
    #   Shared_Dirty:          0 kB
    #   Private_Clean:         0 kB
    #   Private_Dirty:         0 kB
    #   Referenced:            0 kB
    #   Anonymous:             0 kB
    #   LazyFree:              0 kB
    #   AnonHugePages:         0 kB
    #   ShmemPmdMapped:        0 kB
    #   FilePmdMapped:         0 kB
    #   Shared_Hugetlb:        0 kB
    #   Private_Hugetlb:   92160 kB
    #   Swap:                  0 kB
    #   SwapPss:               0 kB
    #   Locked:                0 kB
    #   THPeligible:           0
    #   ProtectionKey:         0
    cmd = f"cat /proc/{pid}/smaps | grep {allocation_name} -A 23 | grep KernelPageSize"
    _, stdout, _ = utils.check_output(cmd)

    kernel_page_size_kib = int(stdout.split()[1])
    assert kernel_page_size_kib > 4


def test_hugetlbfs_boot(uvm_plain):
    """Tests booting a microvm with guest memory backed by 2MB hugetlbfs pages"""

    uvm_plain.spawn()
    uvm_plain.basic_config(huge_pages=HugePagesConfig.HUGETLBFS_2MB, mem_size_mib=128)
    uvm_plain.add_net_iface()
    uvm_plain.start()

    check_hugetlbfs_in_use(
        uvm_plain.firecracker_pid,
        "/anon_hugepage",
    )


def test_hugetlbfs_snapshot(microvm_factory, guest_kernel_linux_5_10, rootfs):
    """
    Test hugetlbfs snapshot restore via uffd
    """

    ### Create Snapshot ###
    vm = microvm_factory.build(guest_kernel_linux_5_10, rootfs)
    vm.memory_monitor = None
    vm.spawn()
    vm.basic_config(huge_pages=HugePagesConfig.HUGETLBFS_2MB, mem_size_mib=128)
    vm.add_net_iface()
    vm.start()

    check_hugetlbfs_in_use(vm.firecracker_pid, "/anon_hugepage")

    snapshot = vm.snapshot_full()

    vm.kill()

    ### Restore Snapshot ###
    vm = microvm_factory.build()
    vm.spawn()
    vm.restore_from_snapshot(snapshot, resume=True, uffd_handler_name="on_demand")

    check_hugetlbfs_in_use(vm.firecracker_pid, "/anon_hugepage")


def test_hugetlbfs_diff_snapshot(microvm_factory, uvm_plain):
    """
    Test hugetlbfs differential snapshot support.

    Despite guest memory being backed by huge pages, differential snapshots still work at 4K granularity.
    """

    ### Create Snapshot ###
    uvm_plain.memory_monitor = None
    uvm_plain.spawn()
    uvm_plain.basic_config(
        huge_pages=HugePagesConfig.HUGETLBFS_2MB,
        mem_size_mib=128,
        track_dirty_pages=True,
    )
    uvm_plain.add_net_iface()
    uvm_plain.start()

    # Wait for microvm to boot

    base_snapshot = uvm_plain.snapshot_diff()
    uvm_plain.resume()

    # Run command to dirty some pages
    uvm_plain.ssh.check_output("sync")

    snapshot_diff = uvm_plain.snapshot_diff()
    snapshot_merged = snapshot_diff.rebase_snapshot(base_snapshot)

    uvm_plain.kill()

    vm = microvm_factory.build()
    vm.spawn()
    vm.restore_from_snapshot(
        snapshot_merged, resume=True, uffd_handler_name="on_demand"
    )

    # Verify if the restored microvm works.


@pytest.mark.parametrize("huge_pages", HugePagesConfig)
def test_ept_violation_count(
    microvm_factory,
    guest_kernel_linux_5_10,
    rootfs,
    metrics,
    huge_pages,
):
    """
    Tests hugetlbfs snapshot restore with a UFFD handler that pre-faults the entire guest memory
    on the first page fault. Records metrics about the number of EPT_VIOLATIONS encountered by KVM.
    """

    ### Create Snapshot ###
    vm = microvm_factory.build(guest_kernel_linux_5_10, rootfs)
    vm.memory_monitor = None
    vm.spawn()
    vm.basic_config(huge_pages=huge_pages, mem_size_mib=256)
    vm.add_net_iface()
    vm.start()

    metrics.set_dimensions(
        {
            "performance_test": "test_hugetlbfs_snapshot",
            "huge_pages_config": str(huge_pages),
            **vm.dimensions,
        }
    )

    # Wait for microvm to boot. Then spawn fast_page_fault_helper to setup an environment where we can trigger
    # a lot of fast_page_faults after restoring the snapshot.
    vm.ssh.check_output(
        "nohup /usr/local/bin/fast_page_fault_helper >/dev/null 2>&1 </dev/null &"
    )

    _, pid, _ = vm.ssh.check_output("pidof fast_page_fault_helper")

    # Give the helper time to initialize
    time.sleep(5)

    snapshot = vm.snapshot_full()

    vm.kill()

    ### Restore Snapshot ###
    vm = microvm_factory.build()
    vm.jailer.daemonize = False
    vm.jailer.extra_args.update({"no-seccomp": None})
    vm.spawn()

    with ftrace_events("kvm:*"):
        vm.restore_from_snapshot(snapshot, resume=True, uffd_handler_name="fault_all")

        # Verify if guest can run commands, and also wake up the fast page fault helper to trigger page faults.
        vm.ssh.check_output(f"kill -s {signal.SIGUSR1} {pid}")

        # Give the helper time to touch all its pages
        time.sleep(5)

        if global_props.cpu_architecture == "x86_64":
            trace_entry = "reason EPT_VIOLATION"
            metric = "ept_violations"
        else:
            # On ARM, KVM does not differentiate why it got a guest page fault.
            # However, even in this slightly more general metric, we see a significant
            # difference between 4K and 2M pages.
            trace_entry = "kvm_guest_fault"
            metric = "guest_page_faults"

        _, metric_value, _ = utils.check_output(
            f"cat /sys/kernel/tracing/trace | grep '{trace_entry}' | wc -l"
        )

    metrics.put_metric(metric, int(metric_value), "Count")


def test_negative_huge_pages_plus_balloon(uvm_plain):
    """Tests that huge pages and memory ballooning cannot be used together"""
    uvm_plain.memory_monitor = None
    uvm_plain.spawn()

    # Ensure setting huge pages and then adding a balloon device doesn't work
    uvm_plain.basic_config(huge_pages=HugePagesConfig.HUGETLBFS_2MB)
    with pytest.raises(
        RuntimeError,
        match="Firecracker's huge pages support is incompatible with memory ballooning.",
    ):
        uvm_plain.api.balloon.put(amount_mib=0, deflate_on_oom=False)

    # Ensure adding a balloon device and then setting huge pages doesn't work
    uvm_plain.basic_config(huge_pages=HugePagesConfig.NONE)
    uvm_plain.api.balloon.put(amount_mib=0, deflate_on_oom=False)
    with pytest.raises(
        RuntimeError,
        match="Machine config error: Firecracker's huge pages support is incompatible with memory ballooning.",
    ):
        uvm_plain.basic_config(huge_pages=HugePagesConfig.HUGETLBFS_2MB)
