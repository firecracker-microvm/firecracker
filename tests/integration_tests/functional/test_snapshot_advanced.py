# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Advanced tests scenarios for snapshot save/restore."""

import logging
import platform
import tempfile
import pytest
from test_balloon import _test_rss_memory_lower
from framework.artifacts import create_net_devices_configuration
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
import host_tools.drive as drive_tools


# Define 4 net device configurations.
net_ifaces = create_net_devices_configuration(4)
# Define 4 scratch drives.
scratch_drives = ["vdb", "vdc", "vdd", "vde", "vdf"]


def test_restore_old_to_current(bin_cloner_path, firecracker_release):
    """
    Restore snapshots from previous supported versions of Firecracker.

    For each firecracker release:
    1. Snapshot with the past release
    2. Restore with the current build

    @type: functional
    """

    # due to ARM bug fixed in commit 822009ce
    if platform.machine() == "aarch64" and firecracker_release.version_tuple < (
        1,
        1,
        4,
    ):
        pytest.skip("incompatible with aarch64 and Firecracker <1.1.4")

    # Microvm: 2vCPU 256MB RAM, balloon, 4 disks and 4 net devices.
    logger = logging.getLogger("old_snapshot_to_current")
    builder = MicrovmBuilder(bin_cloner_path)

    jailer = firecracker_release.jailer()
    logger.info("Using Firecracker: %s", firecracker_release.local_path())
    logger.info("Using Jailer: %s", jailer.local_path())
    diff_snapshots = True
    logger.info("Create snapshot")
    snapshot = create_snapshot_helper(
        builder,
        logger,
        drives=scratch_drives,
        ifaces=net_ifaces,
        fc_binary=firecracker_release.local_path(),
        jailer_binary=jailer.local_path(),
        diff_snapshots=diff_snapshots,
        balloon=diff_snapshots,
    )

    logger.info("Resume microvm using current build of FC/Jailer")
    microvm, _ = builder.build_from_snapshot(
        snapshot, resume=True, diff_snapshots=False
    )
    logger.info("Validate all devices")
    validate_all_devices(logger, microvm, net_ifaces, scratch_drives, diff_snapshots)
    logger.debug("========== Firecracker restore snapshot log ==========")
    logger.debug(microvm.log_data)


def test_restore_current_to_old(bin_cloner_path, firecracker_release):
    """
    Restore current snapshot with previous versions of Firecracker.

    For each firecracker release:
    1. Snapshot with the current build
    2. Restore with the past release

    @type: functional
    """

    # Current snapshot (i.e a machine snapshotted with current build) is
    # incompatible with any past release due to notification suppression.
    if firecracker_release.version_tuple < (1, 2, 0):
        pytest.skip("incompatible with Firecracker <1.2.0")

    # Microvm: 2vCPU 256MB RAM, balloon, 4 disks and 4 net devices.
    logger = logging.getLogger("current_snapshot_to_old")
    builder = MicrovmBuilder(bin_cloner_path)
    jailer = firecracker_release.jailer()
    logger.info("Creating snapshot with local build")
    target_version = firecracker_release.snapshot_version

    # Create a snapshot with current FC version targeting the old version.
    snapshot = create_snapshot_helper(
        builder,
        logger,
        target_version=target_version,
        drives=scratch_drives,
        ifaces=net_ifaces,
        balloon=True,
        diff_snapshots=True,
    )

    logger.info(
        "Restoring snapshot with Firecracker: %s", firecracker_release.local_path()
    )
    logger.info("Using Jailer: %s", jailer.local_path())

    # Resume microvm using FC/Jailer binary artifacts.
    vm, _ = builder.build_from_snapshot(
        snapshot,
        resume=True,
        diff_snapshots=False,
        fc_binary=firecracker_release.local_path(),
        jailer_binary=jailer.local_path(),
    )
    validate_all_devices(logger, vm, net_ifaces, scratch_drives, True)
    logger.debug("========== Firecracker restore snapshot log ==========")
    logger.debug(vm.log_data)


@pytest.mark.skipif(platform.machine() != "x86_64", reason="TSC is x86_64 specific.")
def test_save_tsc_old_version(bin_cloner_path):
    """
    Test TSC warning message when saving old snapshot.

    @type: functional
    """
    vm_builder = MicrovmBuilder(bin_cloner_path)
    vm_instance = vm_builder.build_vm_nano()
    vm = vm_instance.vm

    vm.start()

    vm.pause_to_snapshot(
        mem_file_path="memfile", snapshot_path="statefile", diff=False, version="0.24.0"
    )

    vm.check_log_message("Saving to older snapshot version, TSC freq")
    vm.kill()


def validate_all_devices(logger, microvm, ifaces, drives, balloon):
    """Perform a basic validation for all devices of a microvm."""
    # Test that net devices have connectivity after restore.
    for iface in ifaces:
        logger.info("Testing net device %s", iface.dev_name)
        microvm.ssh_config["hostname"] = iface.guest_ip
        exit_code, _, _ = microvm.ssh.execute_command("sync")

    # Drop page cache.
    # Ensure further reads are going to be served from emulation layer.
    cmd = "sync; echo 1 > /proc/sys/vm/drop_caches"
    exit_code, _, _ = microvm.ssh.execute_command(cmd)
    assert exit_code == 0

    # Validate checksum of /dev/vdX/test.
    # Should be ab893875d697a3145af5eed5309bee26 for 10 pages
    # of zeroes.
    for drive in drives:
        # Mount block device.
        logger.info("Testing drive %s", drive)
        cmd = "mount /dev/{drive} /mnt/{drive}".format(drive=drive)
        exit_code, _, _ = microvm.ssh.execute_command(cmd)
        assert exit_code == 0

        # Validate checksum.
        cmd = "md5sum /mnt/{}/test | cut -d ' ' -f 1".format(drive)
        exit_code, stdout, _ = microvm.ssh.execute_command(cmd)
        assert exit_code == 0
        assert stdout.read().strip() == "ab893875d697a3145af5eed5309bee26"
        logger.info("* checksum OK.")

    if balloon is True:
        logger.info("Testing balloon memory reclaim.")
        # Call helper fn from balloon integration tests.
        _test_rss_memory_lower(microvm)


def create_snapshot_helper(
    builder,
    logger,
    target_version=None,
    drives=None,
    ifaces=None,
    balloon=False,
    diff_snapshots=False,
    fc_binary=None,
    jailer_binary=None,
):
    """Create a snapshot with many devices."""
    vm_instance = builder.build_vm_nano(
        net_ifaces=ifaces,
        diff_snapshots=diff_snapshots,
        fc_binary=fc_binary,
        jailer_binary=jailer_binary,
    )
    vm = vm_instance.vm

    if diff_snapshots is False:
        snapshot_type = SnapshotType.FULL
    else:
        # Version 0.24 and greater has Diff and balloon support.
        snapshot_type = SnapshotType.DIFF

    if balloon:
        # Add a memory balloon with stats enabled.
        response = vm.balloon.put(
            amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
        )
        assert vm.api_session.is_status_no_content(response.status_code)

    # Disk path array needed when creating the snapshot later.
    disks = [vm_instance.disks[0].local_path()]
    test_drives = [] if drives is None else drives

    # Add disks.
    for scratch in test_drives:
        # Add a scratch 64MB RW non-root block device.
        scratchdisk = drive_tools.FilesystemFile(tempfile.mktemp(), size=64)
        vm.add_drive(scratch, scratchdisk.path)
        disks.append(scratchdisk.path)

        # Workaround FilesystemFile destructor removal of file.
        scratchdisk.path = None

    vm.start()

    # Iterate and validate connectivity on all ifaces after boot.
    for iface in ifaces:
        vm.ssh_config["hostname"] = iface.guest_ip
        exit_code, _, _ = vm.ssh.execute_command("sync")
        assert exit_code == 0

    # Mount scratch drives in guest.
    for blk in test_drives:
        # Create mount point and mount each device.
        cmd = "mkdir -p /mnt/{blk} && mount /dev/{blk} /mnt/{blk}".format(blk=blk)
        exit_code, _, _ = vm.ssh.execute_command(cmd)
        assert exit_code == 0

        # Create file using dd using O_DIRECT.
        # After resume we will compute md5sum on these files.
        dd = "dd if=/dev/zero of=/mnt/{}/test bs=4096 count=10 oflag=direct"
        exit_code, _, _ = vm.ssh.execute_command(dd.format(blk))
        assert exit_code == 0

        # Unmount the device.
        cmd = "umount /dev/{}".format(blk)
        exit_code, _, _ = vm.ssh.execute_command(cmd)
        assert exit_code == 0

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(vm)

    snapshot = snapshot_builder.create(
        disks,
        vm_instance.ssh_key,
        target_version=target_version,
        snapshot_type=snapshot_type,
        net_ifaces=ifaces,
    )
    logger.debug("========== Firecracker create snapshot log ==========")
    logger.debug(vm.log_data)
    vm.kill()
    return snapshot
