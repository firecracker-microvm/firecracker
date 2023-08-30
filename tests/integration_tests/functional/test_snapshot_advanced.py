# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Advanced tests scenarios for snapshot save/restore."""

import platform
import tempfile

import pytest
from test_balloon import _test_rss_memory_lower

import host_tools.drive as drive_tools
from framework.microvm import SnapshotType
from framework.properties import global_props

# Define 4 scratch drives.
scratch_drives = ["vdb", "vdc", "vdd", "vde"]


def test_restore_old_to_current(
    microvm_factory, guest_kernel, rootfs_ubuntu_22, firecracker_release
):
    """
    Restore snapshots from previous supported versions of Firecracker.

    For each firecracker release:
    1. Snapshot with the past release
    2. Restore with the current build
    """

    # due to bug fixed in commit 8dab78b
    firecracker_version = firecracker_release.version_tuple
    if global_props.instance == "m6a.metal" and firecracker_version < (1, 3, 3):
        pytest.skip("incompatible with AMD and Firecracker <1.3.3")

    # Microvm: 2vCPU 256MB RAM, balloon, 4 disks and 4 net devices.
    diff_snapshots = True
    vm = microvm_factory.build(
        guest_kernel,
        rootfs_ubuntu_22,
        fc_binary_path=firecracker_release.path,
        jailer_binary_path=firecracker_release.jailer,
    )
    vm.spawn()
    vm.basic_config(track_dirty_pages=True)
    snapshot = create_snapshot_helper(
        vm,
        drives=scratch_drives,
        diff_snapshots=diff_snapshots,
        balloon=diff_snapshots,
    )
    vm = microvm_factory.build()
    vm.spawn()
    vm.restore_from_snapshot(snapshot, resume=True)
    validate_all_devices(vm, diff_snapshots)
    print(vm.log_data)


def test_restore_current_to_old(microvm_factory, uvm_plain, firecracker_release):
    """
    Restore current snapshot with previous versions of Firecracker.

    For each firecracker release:
    1. Snapshot with the current build
    2. Restore with the past release
    """

    # Microvm: 2vCPU 256MB RAM, balloon, 4 disks and 4 net devices.
    vm = uvm_plain
    vm.spawn()
    vm.basic_config(track_dirty_pages=True)

    # Create a snapshot with current FC version targeting the old version.
    snapshot = create_snapshot_helper(
        vm,
        target_version=firecracker_release.snapshot_version,
        drives=scratch_drives,
        balloon=True,
        diff_snapshots=True,
    )

    # Resume microvm using FC/Jailer binary artifacts.
    vm = microvm_factory.build(
        fc_binary_path=firecracker_release.path,
        jailer_binary_path=firecracker_release.jailer,
    )
    vm.spawn()
    vm.restore_from_snapshot(snapshot, resume=True)
    validate_all_devices(vm, True)
    print("========== Firecracker restore snapshot log ==========")
    print(vm.log_data)


@pytest.mark.skipif(platform.machine() != "x86_64", reason="TSC is x86_64 specific.")
def test_save_tsc_old_version(uvm_nano):
    """
    Test TSC warning message when saving old snapshot.
    """
    uvm_nano.start()
    uvm_nano.snapshot_full(target_version="0.24.0")
    uvm_nano.check_log_message("Saving to older snapshot version, TSC freq")


def validate_all_devices(microvm, balloon):
    """Perform a basic validation for all devices of a microvm."""
    # Test that net devices have connectivity after restore.
    for iface in microvm.iface.values():
        print("Testing net device", iface["iface"].dev_name)
        microvm.guest_ip = iface["iface"].guest_ip
        exit_code, _, _ = microvm.ssh.run("sync")

    # Drop page cache.
    # Ensure further reads are going to be served from emulation layer.
    cmd = "sync; echo 1 > /proc/sys/vm/drop_caches"
    exit_code, _, _ = microvm.ssh.run(cmd)
    assert exit_code == 0

    # Validate checksum of /dev/vdX/test.
    # Should be ab893875d697a3145af5eed5309bee26 for 10 pages
    # of zeroes.
    for drive in list(microvm.disks)[1:]:
        # Mount block device.
        print("Testing drive ", drive)
        cmd = f"mkdir -p /tmp/{drive} ; mount /dev/{drive} /tmp/{drive}"
        exit_code, _, _ = microvm.ssh.run(cmd)
        assert exit_code == 0

        # Validate checksum.
        cmd = f"md5sum /tmp/{drive}/test | cut -d ' ' -f 1"
        exit_code, stdout, _ = microvm.ssh.run(cmd)
        assert exit_code == 0
        assert stdout.strip() == "ab893875d697a3145af5eed5309bee26"
        print("* checksum OK.")

    if balloon is True:
        print("Testing balloon memory reclaim.")
        # Call helper fn from balloon integration tests.
        _test_rss_memory_lower(microvm)


def create_snapshot_helper(
    vm,
    target_version=None,
    drives=None,
    balloon=False,
    diff_snapshots=False,
):
    """Create a snapshot with many devices."""
    if diff_snapshots is False:
        snapshot_type = SnapshotType.FULL
    else:
        # Version 0.24 and greater has Diff and balloon support.
        snapshot_type = SnapshotType.DIFF

    if balloon:
        # Add a memory balloon with stats enabled.
        vm.api.balloon.put(
            amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
        )

    test_drives = [] if drives is None else drives

    # Add disks.
    for scratch in test_drives:
        # Add a scratch 64MB RW non-root block device.
        scratchdisk = drive_tools.FilesystemFile(tempfile.mktemp(), size=64)
        vm.add_drive(scratch, scratchdisk.path)

        # Workaround FilesystemFile destructor removal of file.
        scratchdisk.path = None

    for _ in range(4):
        vm.add_net_iface()

    vm.start()

    # Iterate and validate connectivity on all ifaces after boot.
    for i in range(4):
        exit_code, _, _ = vm.ssh_iface(i).run("sync")
        assert exit_code == 0

    # Mount scratch drives in guest.
    for blk in test_drives:
        # Create mount point and mount each device.
        cmd = f"mkdir -p /tmp/mnt/{blk} && mount /dev/{blk} /tmp/mnt/{blk}"
        exit_code, _, _ = vm.ssh.run(cmd)
        assert exit_code == 0

        # Create file using dd using O_DIRECT.
        # After resume we will compute md5sum on these files.
        dd = f"dd if=/dev/zero of=/tmp/mnt/{blk}/test bs=4096 count=10 oflag=direct"
        exit_code, _, _ = vm.ssh.run(dd)
        assert exit_code == 0

        # Unmount the device.
        cmd = f"umount /dev/{blk}"
        exit_code, _, _ = vm.ssh.run(cmd)
        assert exit_code == 0

    snapshot = vm.make_snapshot(snapshot_type, target_version=target_version)
    print("========== Firecracker create snapshot log ==========")
    print(vm.log_data)
    vm.kill()
    return snapshot
