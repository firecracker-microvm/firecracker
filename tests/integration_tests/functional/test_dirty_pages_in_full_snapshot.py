# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test scenario for reseting dirty pages after making a full snapshot."""

import platform

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_dirty_pages_after_full_snapshot(uvm):
    """
    Test if dirty pages are erased after making a full snapshot of a VM
    """

    vm_mem_size = 128
    uvm.spawn()
    uvm.basic_config(mem_size_mib=vm_mem_size, track_dirty_pages=True)
    uvm.add_net_iface()
    uvm.start()

    snap_full = uvm.snapshot_full(vmstate_path="vmstate_full", mem_path="mem_full")
    snap_diff = uvm.snapshot_diff(vmstate_path="vmstate_diff", mem_path="mem_diff")
    snap_diff2 = uvm.snapshot_diff(vmstate_path="vmstate_diff2", mem_path="mem_diff2")

    # file size is the same, but the `diff` snapshot is actually a sparse file
    assert snap_full.mem.stat().st_size == snap_diff.mem.stat().st_size

    # The full snapshot reset the dirty bitmap, the VM stays paused across the snapshots and the
    # devices only mark what they write, so the diff snapshots hold only what taking a snapshot
    # itself dirties: nothing on x86_64; on aarch64, saving the GIC state has KVM write the LPI
    # pending tables (and the ITS tables, with PCI) into guest memory, the same few pages each
    # time.
    assert snap_full.mem.stat().st_blocks > 0
    assert snap_diff.mem.stat().st_blocks < snap_full.mem.stat().st_blocks
    assert snap_diff.mem.stat().st_blocks == snap_diff2.mem.stat().st_blocks
    if platform.machine() == "x86_64":
        assert snap_diff.mem.stat().st_blocks == 0
    else:
        # At most the 4 pages of the GIC tables, in 512-byte blocks.
        assert snap_diff.mem.stat().st_blocks <= 4 * 4096 // 512
