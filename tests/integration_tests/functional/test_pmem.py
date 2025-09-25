# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the virtio-pmem device."""

import json
import os

import host_tools.drive as drive_tools

ALIGNMENT = 2 << 20


def align(size: int) -> int:
    """
    Align the value to ALIGNMENT
    """
    return (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1)


def check_pmem_exist(vm, index, root, read_only, size, extension):
    """
    Check the pmem exist with correct parameters
    """
    vm.ssh.check_output(f"ls /dev/pmem{index}")

    if root:
        _, stdout, _ = vm.ssh.check_output("mount")
        if read_only:
            assert f"/dev/pmem0 on / type {extension} (ro" in stdout
        else:
            assert f"/dev/pmem0 on / type {extension} (rw" in stdout

    _, stdout, _ = vm.ssh.check_output("lsblk -J")

    j = json.loads(stdout)
    blocks = j["blockdevices"]
    for block in blocks:
        if block["name"] == f"pmem{index}":
            assert block["size"][-1] == "M"
            block_size_mb = int(block["size"][:-1])
            assert int(block_size_mb << 20) == size
            if root:
                assert "/" in block["mountpoints"]
            return
    assert False


def test_pmem_add(uvm_plain_any, microvm_factory):
    """
    Test addition of pmem devices to the VM and
    writes persistance
    """

    vm = uvm_plain_any
    vm.spawn()
    vm.basic_config(add_root_device=True)
    vm.add_net_iface()

    # Pmem should work with non 2MB aligned files as well
    pmem_size_mb_1 = 1
    fs_1 = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "scratch_1"), size=pmem_size_mb_1
    )
    pmem_size_mb_2 = 2
    fs_2 = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "scratch_2"), size=pmem_size_mb_2
    )
    vm.add_pmem("pmem_1", fs_1.path, False, False)
    vm.add_pmem("pmem_2", fs_2.path, False, True)
    vm.start()

    # Both 1MB and 2MB block will show as 2MB because of
    # the aligment
    check_pmem_exist(vm, 0, False, False, align(pmem_size_mb_1 << 20), "ext4")
    check_pmem_exist(vm, 1, False, True, align(pmem_size_mb_2 << 20), "ext4")

    # Write something to the pmem0 to see that it is indeed saved to
    # underlying file when VM shots down
    test_string = "testing pmem persistance"
    vm.ssh.check_output("mkdir /tmp/mnt")
    vm.ssh.check_output("mount /dev/pmem0 -o dax=always /tmp/mnt")
    vm.ssh.check_output(f'echo "{test_string}" > /tmp/mnt/test')

    snapshot = vm.snapshot_full()
    # Killing or rebooting an old VM will make OS to flush writes to the underlying file
    vm.kill()

    restored_vm = microvm_factory.build_from_snapshot(snapshot)
    check_pmem_exist(restored_vm, 0, False, False, align(pmem_size_mb_1 << 20), "ext4")
    check_pmem_exist(restored_vm, 1, False, True, align(pmem_size_mb_2 << 20), "ext4")

    # The /tmp/mnt and the mount still persist after snapshot restore.
    # Since we used `dax=always` during mounting there is no data in guest page
    # cache, so the read happens directly from pmem device
    _, stdout, _ = restored_vm.ssh.check_output("cat /tmp/mnt/test")
    assert stdout.strip() == test_string


def test_pmem_add_as_root_rw(uvm_plain_any, rootfs_rw, microvm_factory):
    """
    Test addition of a single root pmem device in read-write mode
    """

    vm = uvm_plain_any
    vm.memory_monitor = None
    vm.monitors = []
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_net_iface()

    rootfs_size = os.path.getsize(rootfs_rw)
    vm.add_pmem("pmem", rootfs_rw, True, False)
    vm.start()

    check_pmem_exist(vm, 0, True, False, align(rootfs_size), "ext4")

    snapshot = vm.snapshot_full()
    restored_vm = microvm_factory.build_from_snapshot(snapshot)
    check_pmem_exist(restored_vm, 0, True, False, align(rootfs_size), "ext4")


def test_pmem_add_as_root_ro(uvm_plain_any, rootfs, microvm_factory):
    """
    Test addition of a single root pmem device in read-only mode
    """

    vm = uvm_plain_any
    vm.memory_monitor = None
    vm.monitors = []
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_net_iface()

    rootfs_size = os.path.getsize(rootfs)
    vm.add_pmem("pmem", rootfs, True, True)
    vm.start()

    check_pmem_exist(vm, 0, True, True, align(rootfs_size), "squashfs")

    snapshot = vm.snapshot_full()
    restored_vm = microvm_factory.build_from_snapshot(snapshot)
    check_pmem_exist(restored_vm, 0, True, True, align(rootfs_size), "squashfs")
