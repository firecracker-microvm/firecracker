# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Advanced tests scenarios for snapshot save/restore."""

import logging
import platform
import tempfile
import pytest
from test_balloon import _test_rss_memory_lower, copy_util_to_rootfs
from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, NetIfaceConfig
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.microvms import VMNano
from framework.utils import get_firecracker_version_from_toml
import host_tools.network as net_tools  # pylint: disable=import-error
import host_tools.drive as drive_tools


# Define 4 net device configurations.
net_ifaces = [NetIfaceConfig(),
              NetIfaceConfig(host_ip="192.168.1.1",
                             guest_ip="192.168.1.2",
                             tap_name="tap1",
                             dev_name="eth1"),
              NetIfaceConfig(host_ip="192.168.2.1",
                             guest_ip="192.168.2.2",
                             tap_name="tap2",
                             dev_name="eth2"),
              NetIfaceConfig(host_ip="192.168.3.1",
                             guest_ip="192.168.3.2",
                             tap_name="tap3",
                             dev_name="eth3")]
# Define 4 scratch drives.
scratch_drives = ["vdb", "vdc", "vdd", "vde", "vdf"]


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_restore_old_snapshot_all_devices(bin_cloner_path):
    """Test scenario: restore previous version snapshots in current version."""
    # Microvm: 2vCPU 256MB RAM, baloon, 4 disks and 4 netdevices.
    logger = logging.getLogger("snapshot_many_devices")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Fetch all firecracker binaries.
    # With each binary create a snapshot and try to restore in current
    # version.
    firecracker_artifacts = artifacts.firecrackers(
        older_than=get_firecracker_version_from_toml())
    for firecracker in firecracker_artifacts:
        firecracker.download()
        jailer = firecracker.jailer()
        jailer.download()

        logger.info("Creating snapshot with Firecracker: %s",
                    firecracker.local_path())
        logger.info("Using Jailer: %s", jailer.local_path())

        target_version = firecracker.base_name()[1:]

        # v0.23 does not support creating diff snapshots.
        # v0.23 does not support balloon.
        diff_snapshots = "0.23" not in target_version

        # Create a snapshot.
        snapshot = create_snapshot_helper(bin_cloner_path,
                                          logger,
                                          drives=scratch_drives,
                                          ifaces=net_ifaces,
                                          fc_binary=firecracker.local_path(),
                                          jailer_binary=jailer.local_path(),
                                          diff_snapshots=diff_snapshots,
                                          balloon=diff_snapshots)

        # Resume microvm using current build of FC/Jailer.
        builder = MicrovmBuilder(bin_cloner_path)
        microvm, _ = builder.build_from_snapshot(snapshot,
                                                 resume=True,
                                                 enable_diff_snapshots=False)
        validate_all_devices(logger, microvm, net_ifaces, scratch_drives,
                             diff_snapshots, legacy_api=False)
        logger.debug("========== Firecracker restore snapshot log ==========")
        logger.debug(microvm.log_data)


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_restore_old_version_all_devices(bin_cloner_path):
    """Test scenario: restore snapshot in previous versions of Firecracker."""
    # Microvm: 2vCPU 256MB RAM, baloon, 4 disks and 4 netdevices.
    logger = logging.getLogger("snapshot_many_devices")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Fetch all firecracker binaries.
    # Create a snapshot with current build and restore with each FC binary
    # artifact.
    firecracker_artifacts = artifacts.firecrackers(
        older_than=get_firecracker_version_from_toml())
    for firecracker in firecracker_artifacts:
        firecracker.download()
        jailer = firecracker.jailer()
        jailer.download()

        logger.info("Creating snapshot with local build")

        # Old version from artifact.
        target_version = firecracker.base_name()[1:]
        # v0.23 does not have a ballon device.
        balloon = "0.23" not in target_version

        legacy = "0.24" in target_version

        # Create a snapshot with current FC version targeting the old version.
        snapshot = create_snapshot_helper(bin_cloner_path,
                                          logger,
                                          target_version=target_version,
                                          drives=scratch_drives,
                                          ifaces=net_ifaces,
                                          balloon=balloon,
                                          diff_snapshots=True)

        logger.info("Restoring snapshot with Firecracker: %s",
                    firecracker.local_path())
        logger.info("Using Jailer: %s", jailer.local_path())

        # Resume microvm using FC/Jailer binary artifacts.
        builder = MicrovmBuilder(bin_cloner_path,
                                 firecracker.local_path(),
                                 jailer.local_path())
        microvm, _ = builder.build_from_snapshot(snapshot,
                                                 resume=True,
                                                 enable_diff_snapshots=False)
        validate_all_devices(logger, microvm, net_ifaces, scratch_drives,
                             balloon, legacy_api=legacy)
        logger.debug("========== Firecracker restore snapshot log ==========")
        logger.debug(microvm.log_data)


def validate_all_devices(
    logger,
    microvm,
    ifaces,
    drives,
    balloon,
    legacy_api=False
):
    """Perform a basic validation for all devices of a microvm."""
    # Test that net devices have connectivity after restore.
    for iface in ifaces:
        logger.info("Testing net device %s", iface.dev_name)
        microvm.ssh_config['hostname'] = iface.guest_ip
        ssh_connection = net_tools.SSHConnection(microvm.ssh_config)
        exit_code, _, _ = ssh_connection.execute_command("sync")

    # Drop page cache.
    # Ensure further reads are going to be served from emulation layer.
    cmd = "sync; echo 1 > /proc/sys/vm/drop_caches"
    exit_code, _, _ = ssh_connection.execute_command(cmd)
    assert exit_code == 0

    # Validate checksum of /dev/vdX/test.
    # Should be ab893875d697a3145af5eed5309bee26 for 10 pages
    # of zeroes.
    for drive in drives:
        # Mount block device.
        logger.info("Testing drive %s", drive)
        cmd = "mount /dev/{drive} /mnt/{drive}".format(drive=drive)
        exit_code, _, _ = ssh_connection.execute_command(cmd)
        assert exit_code == 0

        # Validate checksum.
        cmd = "md5sum /mnt/{}/test | cut -d ' ' -f 1".format(drive)
        exit_code, stdout, _ = ssh_connection.execute_command(cmd)
        assert exit_code == 0
        assert stdout.read().strip() == "ab893875d697a3145af5eed5309bee26"
        logger.info("* checksum OK.")

    if balloon is True:
        logger.info("Testing balloon memory reclaim.")
        # Call helper fn from ballon integration tests.
        _test_rss_memory_lower(microvm, use_legacy_api=legacy_api)


def create_snapshot_helper(bin_cloner_path, logger, target_version=None,
                           drives=None, ifaces=None,
                           fc_binary=None, jailer_binary=None,
                           balloon=False, diff_snapshots=False):
    """Create a snapshot with many devices."""
    vm_instance = VMNano.spawn(bin_cloner_path, False,
                               fc_binary, jailer_binary,
                               net_ifaces=ifaces,
                               diff_snapshots=diff_snapshots)
    vm = vm_instance.vm

    if diff_snapshots is False:
        snapshot_type = SnapshotType.FULL
    else:
        # Version 0.24 and greater has Diff and ballon support.
        snapshot_type = SnapshotType.DIFF

    if balloon:
        legacy_balloon = fc_binary is not None and "0.24" in fc_binary

        # Copy balloon test util.
        copy_util_to_rootfs(vm_instance.disks[0].local_path(), 'fillmem')

        # Add a memory balloon with stats enabled.
        if legacy_balloon:
            response = vm.balloon.put(
                amount_mb=0,
                deflate_on_oom=True,
                stats_polling_interval_s=1
            )
        else:
            response = vm.balloon.put(
                amount_mib=0,
                deflate_on_oom=True,
                stats_polling_interval_s=1
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
    for iface in net_ifaces:
        vm.ssh_config['hostname'] = iface.guest_ip
        ssh_connection = net_tools.SSHConnection(vm.ssh_config)
        exit_code, _, _ = ssh_connection.execute_command("sync")
        assert exit_code == 0

    # Mount scratch drives in guest.
    for blk in scratch_drives:
        # Create mount point and mount each device.
        cmd = "mkdir -p /mnt/{blk} && mount /dev/{blk} /mnt/{blk}".format(
            blk=blk
        )
        exit_code, _, _ = ssh_connection.execute_command(cmd)
        assert exit_code == 0

        # Create file using dd using O_DIRECT.
        # After resume we will compute md5sum on these files.
        dd = "dd if=/dev/zero of=/mnt/{}/test bs=4096 count=10 oflag=direct"
        exit_code, _, _ = ssh_connection.execute_command(dd.format(blk))
        assert exit_code == 0

        # Unmount the device.
        cmd = "umount /dev/{}".format(blk)
        exit_code, _, _ = ssh_connection.execute_command(cmd)
        assert exit_code == 0

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(vm)

    snapshot = snapshot_builder.create(disks,
                                       vm_instance.ssh_key,
                                       target_version=target_version,
                                       snapshot_type=snapshot_type,
                                       net_ifaces=net_ifaces)
    logger.debug("========== Firecracker create snapshot log ==========")
    logger.debug(vm.log_data)
    vm.kill()
    return snapshot
