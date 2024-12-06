# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test that the no dirty pages lost in case of error during snapshot creation."""

import subprocess
from pathlib import Path

import psutil
import pytest


@pytest.fixture
def mount_tmpfs_small(worker_id):
    """Mount a small tmpfs and return its path"""
    mnt_path = Path(f"/mnt/{worker_id}")
    mnt_path.mkdir(parents=True)
    subprocess.check_call(
        ["mount", "-o", "size=512M", "-t", "tmpfs", "none", str(mnt_path)]
    )
    try:
        yield mnt_path
    finally:
        subprocess.check_call(["umount", mnt_path])
        mnt_path.rmdir()


def test_diff_snapshot_works_after_error(
    microvm_factory, guest_kernel_linux_5_10, rootfs, mount_tmpfs_small
):
    """
    Test that if a partial snapshot errors it will work after and not lose data
    """
    uvm = microvm_factory.build(
        guest_kernel_linux_5_10,
        rootfs,
        jailer_kwargs={"chroot_base": mount_tmpfs_small},
    )

    vm_mem_size = 128
    uvm.spawn()
    uvm.basic_config(mem_size_mib=vm_mem_size, track_dirty_pages=True)
    uvm.add_net_iface()
    uvm.start()

    chroot = Path(uvm.chroot())

    # Create a large file dynamically based on available space
    fill = chroot / "fill"
    disk_usage = psutil.disk_usage(chroot)
    target_size = round(disk_usage.free * 0.9)  # Attempt to fill 90% of free space

    subprocess.check_call(f"fallocate -l {target_size} {fill}", shell=True)

    try:
        uvm.snapshot_diff()
    except RuntimeError:
        msg = "No space left on device"
        uvm.check_log_message(msg)
    else:
        assert False, "This should fail"

    fill.unlink()

    # Now there is enough space for it to work
    snap2 = uvm.snapshot_diff()
    uvm.kill()

    _vm2 = microvm_factory.build_from_snapshot(snap2)
