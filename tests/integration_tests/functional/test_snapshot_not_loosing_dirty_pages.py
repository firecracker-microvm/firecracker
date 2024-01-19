# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test that the no dirty pages lost in case of error during snapshot creation."""

import subprocess
from pathlib import Path


def test_not_loosing_dirty_pages_on_snapshot_failure(uvm_plain, microvm_factory):
    """
    Test that in case of error during snapshot creation no dirty pages were lost.
    """
    vm_mem_size = 128
    uvm = uvm_plain
    uvm.spawn()
    uvm.basic_config(mem_size_mib=vm_mem_size, track_dirty_pages=True)
    uvm.add_net_iface()
    uvm.start()
    uvm.ssh.run("true")

    chroot = Path(uvm.chroot())

    # Create a large file, so we run out of space (ENOSPC) during the snapshot
    # Assumes a Docker /srv tmpfs of 1G, derived by trial and error
    fudge = chroot / "fudge"
    subprocess.check_call(f"fallocate -l 550M {fudge}", shell=True)

    try:
        uvm.snapshot_diff()
    except RuntimeError:
        msg = "No space left on device"
        uvm.check_log_message(msg)
    else:
        assert False, "This should fail"

    fudge.unlink()

    # Now there is enough space for it to work
    snap2 = uvm.snapshot_diff()

    vm2 = microvm_factory.build()
    vm2.spawn()
    vm2.restore_from_snapshot(snap2, resume=True)
    vm2.ssh.run("true")
