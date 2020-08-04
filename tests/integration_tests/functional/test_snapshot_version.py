# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import logging
import platform
import pytest
from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.microvms import SmallVM
import host_tools.network as net_tools  # pylint: disable=import-error


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_restore_from_past_versions(bin_cloner_path):
    """Test scenario: restore all previous version snapshots."""
    logger = logging.getLogger("snapshot_version")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Fetch all snapshots artifacts.
    # "fc_release" is the key that should be used for per release snapshot
    # artifacts. Such snapshots are created at release time and target the
    # current version. We are going to restore all these snapshots with current
    # testing build.
    snapshot_artifacts = artifacts.snapshots(keyword="fc_release")
    builder = MicrovmBuilder(bin_cloner_path)

    for snapshot_artifact in snapshot_artifacts:
        snapshot_artifact.download()
        snapshot = snapshot_artifact.copy(builder.root_path)

        logger.info("Resuming from %s", snapshot_artifact.key)

        # TODO: Define network config artifact that can be used to build
        # new vms or can be used as part of the snapshot
        # For now we are good with theses hardcoded values
        microvm, _ = builder.build_from_snapshot(snapshot,
                                                 "192.168.0.1",
                                                 "192.168.0.2",
                                                 30,
                                                 True,
                                                 False)
        # Attempt to connect to resumed microvm.
        ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

        # Run a fio workload and validate succesfull execution.
        fio = """fio --filename=/dev/vda --direct=1 --rw=randread --bs=4k \
        --ioengine=libaio --iodepth=16 --runtime=2 --numjobs=4 --time_based \
        --group_reporting --name=iops-test-job --eta-newline=1 --readonly"""

        exit_code, _, _ = ssh_connection.execute_command(fio)
        assert exit_code == 0


def create_512mb_full_snapshot(bin_cloner_path, target_version: str = None):
    """Create a snapshoft from a 2vcpu 512MB microvm."""
    vm_instance = SmallVM.spawn(bin_cloner_path, True)
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(vm_instance.vm)

    # The snapshot builder expects disks as paths, not artifacts.
    disks = []
    for disk in vm_instance.disks:
        disks.append(disk.local_path())

    snapshot = snapshot_builder.create(disks,
                                       vm_instance.ssh_key,
                                       SnapshotType.FULL,
                                       target_version)

    vm_instance.vm.kill()
    return snapshot


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_restore_in_past_versions(bin_cloner_path):
    """Test scenario: create a snapshot and restore in previous versions."""
    logger = logging.getLogger("snapshot_version")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Fetch all snapshots artifacts.
    # "fc_release" is the key that should be used for per release snapshot
    # artifacts. Such snapshots are created at release time and target the
    # current version. We are going to restore all these snapshots with current
    # testing build.
    firecracker_artifacts = artifacts.firecrackers()
    for firecracker in firecracker_artifacts:
        firecracker.download()
        jailer = firecracker.jailer()
        jailer.download()
        # The target version is in the name of the firecracker binary from S3.
        # We also strip the "v" as fc expects X.Y.Z version string.
        target_version = firecracker.base_name()[1:]
        logger.info("Creating snapshot for version: %s", target_version)

        # Create a fresh snapshot targeted at the binary artifact version.
        snapshot = create_512mb_full_snapshot(bin_cloner_path, target_version)

        builder = MicrovmBuilder(bin_cloner_path,
                                 firecracker.local_path(),
                                 jailer.local_path())
        microvm, _ = builder.build_from_snapshot(snapshot,
                                                 "192.168.0.1",
                                                 "192.168.0.2",
                                                 30,
                                                 True,
                                                 False)

        logger.info("Using Firecracker: %s", firecracker.local_path())
        logger.info("Using Jailer: %s", jailer.local_path())

        # Attempt to connect to resumed microvm.
        ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

        # Run a fio workload and validate succesfull execution.
        fio = """fio --filename=/dev/vda --direct=1 --rw=randread --bs=4k \
        --ioengine=libaio --iodepth=16 --runtime=2 --numjobs=4 --time_based \
        --group_reporting --name=iops-test-job --eta-newline=1 --readonly"""

        exit_code, _, _ = ssh_connection.execute_command(fio)
        assert exit_code == 0
