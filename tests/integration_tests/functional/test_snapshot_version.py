# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import logging
import platform
import pytest
from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.microvms import VMMicro
import host_tools.network as net_tools  # pylint: disable=import-error

# Firecracker v0.23 used 16 IRQ lines. For virtio devices,
# IRQs are available from 5 to 23, so the maximum number
# of devices allowed at the same time was 11.
FC_V0_23_MAX_DEVICES_ATTACHED = 11


def _create_and_start_microvm_with_net_devices(test_microvm,
                                               network_config,
                                               devices_no):
    test_microvm.spawn()
    # Set up a basic microVM: configure the boot source and
    # add a root device.
    test_microvm.basic_config(track_dirty_pages=True)

    # Add network devices on top of the already configured rootfs for a
    # total of (`devices_no` + 1) devices.
    for i in range(devices_no):
        # Create tap before configuring interface.
        _tap, _host_ip, _guest_ip = test_microvm.ssh_network_config(
            network_config,
            str(i)
        )
    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    # Verify if guest can run commands.
    exit_code, _, _ = ssh_connection.execute_command("sync")
    assert exit_code == 0


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_restore_from_past_versions(bin_cloner_path):
    """Test scenario: restore all previous version snapshots."""
    logger = logging.getLogger("snapshot_version")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Fetch all firecracker binaries.
    # With each binary create a snapshot and try to restore in current
    # version.
    firecracker_artifacts = artifacts.firecrackers()
    for firecracker in firecracker_artifacts:
        firecracker.download()
        jailer = firecracker.jailer()
        jailer.download()

        logger.info("Source Firecracker: %s", firecracker.local_path())
        logger.info("Source Jailer: %s", jailer.local_path())
        # Create a fresh snapshot using the binary artifacts.
        builder = MicrovmBuilder(bin_cloner_path,
                                 firecracker.local_path(),
                                 jailer.local_path())
        snapshot = create_512mb_full_snapshot(bin_cloner_path, None,
                                              firecracker.local_path(),
                                              jailer.local_path())
        microvm, _ = builder.build_from_snapshot(snapshot,
                                                 True,
                                                 False)
        ssh_connection = net_tools.SSHConnection(microvm.ssh_config)
        exit_code, _, _ = ssh_connection.execute_command("sleep 1 && sync")

        assert exit_code == 0


def create_512mb_full_snapshot(bin_cloner_path, target_version: str = None,
                               fc_binary=None, jailer_binary=None):
    """Test scenario: create a snapshot from a 2vcpu 512MB microvm."""
    vm_instance = VMMicro.spawn(bin_cloner_path, True,
                                fc_binary, jailer_binary)
    # Attempt to connect to the fresh microvm.
    ssh_connection = net_tools.SSHConnection(vm_instance.vm.ssh_config)

    # Run a fio workload and validate succesfull execution.
    fio = """fio --filename=/dev/vda --direct=1 --rw=randread --bs=4k \
    --ioengine=libaio --iodepth=16 --runtime=2 --numjobs=4 --time_based \
    --group_reporting --name=iops-test-job --eta-newline=1 --readonly"""

    exit_code, _, _ = ssh_connection.execute_command(fio)
    assert exit_code == 0

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
                                                 True,
                                                 False)

        logger.info("Using Firecracker: %s", firecracker.local_path())
        logger.info("Using Jailer: %s", jailer.local_path())

        # Attempt to connect to resumed microvm.
        ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

        exit_code, _, _ = ssh_connection.execute_command("sleep 1 && sync")
        assert exit_code == 0


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_create_with_past_version(test_microvm_with_ssh, network_config):
    """Test scenario: restore in previous versions with too many devices."""
    test_microvm = test_microvm_with_ssh

    # Create and start a microVM with (`FC_V0_23_MAX_DEVICES_ATTACHED` - 1)
    # network devices.
    devices_no = FC_V0_23_MAX_DEVICES_ATTACHED - 1
    _create_and_start_microvm_with_net_devices(test_microvm,
                                               network_config,
                                               devices_no)

    snapshot_builder = SnapshotBuilder(test_microvm)
    # Create directory and files for saving snapshot state and memory.
    _snapshot_dir = snapshot_builder.create_snapshot_dir()
    # Pause and create a snapshot of the microVM. Firecracker v0.23 allowed a
    # maximum of `FC_V0_23_MAX_DEVICES_ATTACHED` virtio devices at a time.
    # This microVM has `FC_V0_23_MAX_DEVICES_ATTACHED` devices, including the
    # rootfs, so snapshotting should succeed.
    test_microvm.pause_to_snapshot(
        mem_file_path="/snapshot/vm.mem",
        snapshot_path="/snapshot/vm.vmstate",
        diff=True,
        version="0.23.0")


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_create_with_too_many_devices(test_microvm_with_ssh, network_config):
    """Test scenario: restore in previous versions with too many devices."""
    test_microvm = test_microvm_with_ssh

    # Create and start a microVM with `FC_V0_23_MAX_DEVICES_ATTACHED`
    # network devices.
    devices_no = FC_V0_23_MAX_DEVICES_ATTACHED
    _create_and_start_microvm_with_net_devices(test_microvm,
                                               network_config,
                                               devices_no)

    snapshot_builder = SnapshotBuilder(test_microvm)
    # Create directory and files for saving snapshot state and memory.
    _snapshot_dir = snapshot_builder.create_snapshot_dir()

    # Pause microVM for snapshot.
    response = test_microvm.vm.patch(state='Paused')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Attempt to create a snapshot with version: `0.23.0`. Firecracker
    # v0.23 allowed a maximum of `FC_V0_23_MAX_DEVICES_ATTACHED` virtio
    # devices at a time. This microVM has `FC_V0_23_MAX_DEVICES_ATTACHED`
    # network devices on top of the rootfs, so the limit is exceeded.
    response = test_microvm.snapshot_create.put(
        mem_file_path="/snapshot/vm.vmstate",
        snapshot_path="/snapshot/vm.mem",
        diff=True,
        version="0.23.0"
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Too many devices attached" in response.text
