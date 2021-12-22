# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the correctness of the command line parameters."""

import logging
import platform

from host_tools.cargo_build import get_firecracker_binaries
from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.utils import run_cmd, get_firecracker_version_from_toml


def test_describe_snapshot_all_versions(bin_cloner_path):
    """
    Test `--describe-snapshot` correctness for all snapshot versions.

    @type: functional
    """
    logger = logging.getLogger("describe_snapshot")
    builder = MicrovmBuilder(bin_cloner_path)
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Fetch all firecracker binaries.
    # For each binary create a snapshot and verify the data version
    # of the snapshot state file.

    firecracker_artifacts = artifacts.firecrackers(
        max_version=get_firecracker_version_from_toml())

    for firecracker in firecracker_artifacts:
        firecracker.download()
        jailer = firecracker.jailer()
        jailer.download()

        target_version = firecracker.base_name()[1:]
        # Skip for aarch64, since the snapshotting feature
        # was introduced in v0.24.0.
        if platform.machine() == "aarch64" and "v0.23" in target_version:
            continue

        logger.info("Creating snapshot with Firecracker: %s",
                    firecracker.local_path())
        logger.info("Using Jailer: %s", jailer.local_path())
        logger.info("Using target version: %s", target_version)

        # v0.23 does not support creating diff snapshots.
        diff_snapshots = "0.23" not in target_version
        vm_instance = builder.build_vm_nano(fc_binary=firecracker.local_path(),
                                            jailer_binary=jailer.local_path(),
                                            diff_snapshots=diff_snapshots)
        vm = vm_instance.vm
        vm.start()

        # Create a snapshot builder from a microvm.
        snapshot_builder = SnapshotBuilder(vm)
        disks = [vm_instance.disks[0].local_path()]

        # Version 0.24 and greater have Diff support.
        snap_type = SnapshotType.DIFF if diff_snapshots else SnapshotType.FULL

        snapshot = snapshot_builder.create(disks,
                                           vm_instance.ssh_key,
                                           target_version=target_version,
                                           snapshot_type=snap_type)
        logger.debug("========== Firecracker create snapshot log ==========")
        logger.debug(vm.log_data)
        vm.kill()

        # Fetch Firecracker binary for the latest version
        fc_binary, _ = get_firecracker_binaries()
        # Verify the output of `--describe-snapshot` command line parameter
        cmd = [fc_binary] + ["--describe-snapshot", snapshot.vmstate]

        code, stdout, stderr = run_cmd(cmd)
        assert code == 0
        assert stderr == ''
        assert target_version in stdout
