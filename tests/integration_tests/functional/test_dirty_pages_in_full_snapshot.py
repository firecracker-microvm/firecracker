# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test scenario for reseting dirty pages after making a full snapshot."""


def test_dirty_pages_after_full_snapshot(uvm_plain):
    """
    Test if dirty pages are erased after making a full snapshot of a VM
    """

    vm_mem_size = 128
    uvm = uvm_plain
    uvm.spawn()
    uvm.basic_config(mem_size_mib=vm_mem_size, track_dirty_pages=True)
    uvm.add_net_iface()
    uvm.start()

    snap_full = uvm.snapshot_full(vmstate_path="vmstate_full", mem_path="mem_full")
    snap_diff = uvm.snapshot_diff(vmstate_path="vmstate_diff", mem_path="mem_diff")
    snap_diff2 = uvm.snapshot_diff(vmstate_path="vmstate_diff2", mem_path="mem_diff2")

    # file size is the same, but the `diff` snapshot is actually a sparse file
    assert snap_full.mem.stat().st_size == snap_diff.mem.stat().st_size

    # full -> diff: full should have more things in it
    # Diff snapshots will contain some pages, because we always mark
    # pages used for virt queues as dirty.
    assert snap_diff.mem.stat().st_blocks < snap_full.mem.stat().st_blocks
    assert snap_diff2.mem.stat().st_blocks < snap_full.mem.stat().st_blocks

    # diff -> diff: there should be no differences
    assert snap_diff.mem.stat().st_blocks == snap_diff2.mem.stat().st_blocks
