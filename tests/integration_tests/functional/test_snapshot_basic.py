# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import filecmp
import logging
import os
import tempfile
from pathlib import Path

from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.matrix import TestMatrix, TestContext
from framework.microvms import VMNano
from framework.utils import wait_process_termination
from framework.utils_vsock import make_blob, \
    check_host_connections, check_guest_connections

import host_tools.network as net_tools  # pylint: disable=import-error
import host_tools.drive as drive_tools

VSOCK_UDS_PATH = "v.sock"
ECHO_SERVER_PORT = 5252


def _guest_run_fio_iteration(ssh_connection, iteration):
    fio = """fio --filename=/dev/vda --direct=1 --rw=randread --bs=4k \
        --ioengine=libaio --iodepth=16 --runtime=10 --numjobs=4 --time_based \
        --group_reporting --name=iops-test-job --eta-newline=1 --readonly"""
    ssh_cmd = "screen -L -Logfile /tmp/fio{} -dmS test{} {}"
    ssh_cmd = ssh_cmd.format(iteration, iteration, fio)
    exit_code, _, _ = ssh_connection.execute_command(ssh_cmd)
    assert exit_code == 0


def _get_guest_drive_size(ssh_connection, guest_dev_name='/dev/vdb'):
    # `lsblk` command outputs 2 lines to STDOUT:
    # "SIZE" and the size of the device, in bytes.
    blksize_cmd = "lsblk -b {} --output SIZE".format(guest_dev_name)
    _, stdout, stderr = ssh_connection.execute_command(blksize_cmd)
    assert stderr.read() == ''
    stdout.readline()  # skip "SIZE"
    return stdout.readline().strip()


def _copy_vsock_data_to_guest(ssh_connection,
                              blob_path,
                              vm_blob_path,
                              vsock_helper):
    # Copy the data file and a vsock helper to the guest.
    cmd = "mkdir -p /tmp/vsock && mount -t tmpfs tmpfs /tmp/vsock"
    ecode, _, _ = ssh_connection.execute_command(cmd)
    assert ecode == 0, "Failed to set up tmpfs drive on the guest."

    ssh_connection.scp_file(vsock_helper, '/bin/vsock_helper')
    ssh_connection.scp_file(blob_path, vm_blob_path)


def _test_seq_snapshots(context):
    logger = context.custom['logger']
    seq_len = context.custom['seq_len']
    vm_builder = context.custom['builder']
    snapshot_type = context.custom['snapshot_type']
    enable_diff_snapshots = snapshot_type == SnapshotType.DIFF

    logger.info("Testing {} with microvm: \"{}\", kernel {}, disk {} "
                .format(snapshot_type,
                        context.microvm.name(),
                        context.kernel.name(),
                        context.disk.name()))

    # Create a rw copy artifact.
    root_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from aftifacts.
    basevm = vm_builder.build(kernel=context.kernel,
                              disks=[root_disk],
                              ssh_key=ssh_key,
                              config=context.microvm,
                              enable_diff_snapshots=enable_diff_snapshots)

    # The vsock device is configured for Full snapshots only.
    if snapshot_type == SnapshotType.FULL:
        basevm.vsock.put(
            vsock_id="vsock0",
            guest_cid=3,
            uds_path="/{}".format(VSOCK_UDS_PATH)
        )

    basevm.start()
    ssh_connection = net_tools.SSHConnection(basevm.ssh_config)

    # Verify if guest can run commands.
    exit_code, _, _ = ssh_connection.execute_command("sync")
    assert exit_code == 0

    if snapshot_type == SnapshotType.FULL:
        test_fc_session_root_path = context.custom['test_fc_session_root_path']
        vsock_helper = context.custom['bin_vsock_path']
        vm_blob_path = "/tmp/vsock/test.blob"
        # Generate a random data file for vsock.
        blob_path, blob_hash = make_blob(test_fc_session_root_path)
        # Copy the data file and a vsock helper to the guest.
        _copy_vsock_data_to_guest(ssh_connection,
                                  blob_path,
                                  vm_blob_path,
                                  vsock_helper)

    logger.info("Create {} #0.".format(snapshot_type))
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    # Create base snapshot.
    snapshot = snapshot_builder.create([root_disk.local_path()],
                                       ssh_key,
                                       snapshot_type)

    base_snapshot = snapshot
    basevm.kill()

    for i in range(seq_len):
        logger.info("Load snapshot #{}, mem {}".format(i, snapshot.mem))
        microvm, _ = vm_builder.build_from_snapshot(snapshot,
                                                    True,
                                                    enable_diff_snapshots)

        # Attempt to connect to resumed microvm.
        ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

        if snapshot_type == SnapshotType.FULL:
            # Test vsock guest-initiated connections.
            path = os.path.join(
                microvm.path,
                "{}_{}".format(VSOCK_UDS_PATH, ECHO_SERVER_PORT)
            )
            check_guest_connections(microvm, path, vm_blob_path, blob_hash)
            # Test vsock host-initiated connections.
            path = os.path.join(microvm.jailer.chroot_path(), VSOCK_UDS_PATH)
            check_host_connections(microvm, path, blob_path, blob_hash)

        # Start a new instance of fio on each iteration.
        _guest_run_fio_iteration(ssh_connection, i)

        logger.info("Create snapshot #{}.".format(i + 1))

        # Create a snapshot builder from the currently running microvm.
        snapshot_builder = SnapshotBuilder(microvm)

        snapshot = snapshot_builder.create([root_disk.local_path()],
                                           ssh_key,
                                           snapshot_type)

        # If we are testing incremental snapshots we must merge the base with
        # current layer.
        if snapshot_type == SnapshotType.DIFF:
            logger.info("Base: {}, Layer: {}".format(base_snapshot.mem,
                                                     snapshot.mem))
            snapshot.rebase_snapshot(base_snapshot)
            # Update the base for next iteration.
            base_snapshot = snapshot

        microvm.kill()


def _test_compare_mem_files(context):
    logger = context.custom['logger']
    vm_builder = context.custom['builder']

    # Create a rw copy artifact.
    root_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from aftifacts.
    basevm = vm_builder.build(kernel=context.kernel,
                              disks=[root_disk],
                              ssh_key=ssh_key,
                              config=context.microvm,
                              enable_diff_snapshots=True)

    basevm.start()
    ssh_connection = net_tools.SSHConnection(basevm.ssh_config)

    # Verify if guest can run commands.
    exit_code, _, _ = ssh_connection.execute_command("sync")
    assert exit_code == 0

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    logger.info("Create full snapshot.")
    # Create full snapshot.
    full_snapshot = snapshot_builder.create([root_disk.local_path()],
                                            ssh_key,
                                            SnapshotType.FULL)

    logger.info("Create diff snapshot.")
    # Create diff snapshot.
    diff_snapshot = snapshot_builder.create([root_disk.local_path()],
                                            ssh_key,
                                            SnapshotType.DIFF,
                                            mem_file_name="diff_vm.mem",
                                            snapshot_name="diff_vm.vmstate")
    assert filecmp.cmp(full_snapshot.mem, diff_snapshot.mem)

    basevm.kill()


def test_patch_drive_snapshot(bin_cloner_path):
    """Test scenario: 5 full sequential snapshots."""
    logger = logging.getLogger("snapshot_sequence")

    vm_builder = MicrovmBuilder(bin_cloner_path)
    snapshot_type = SnapshotType.FULL
    enable_diff_snapshots = False

    # Use a predefined vm instance.
    vm_instance = VMNano.spawn(bin_cloner_path)
    basevm = vm_instance.vm
    root_disk = vm_instance.disks[0]
    ssh_key = vm_instance.ssh_key

    # Add a scratch 128MB RW non-root block device.
    scratchdisk1 = drive_tools.FilesystemFile(tempfile.mktemp(), size=128)
    basevm.add_drive('scratch', scratchdisk1.path)

    basevm.start()
    ssh_connection = net_tools.SSHConnection(basevm.ssh_config)

    # Verify if guest can run commands.
    exit_code, _, _ = ssh_connection.execute_command("sync")
    assert exit_code == 0

    # Update drive to have another backing file, double in size.
    new_file_size_mb = 2 * int(scratchdisk1.size()/(1024*1024))
    logger.info("Patch drive, new file: size %sMB.", new_file_size_mb)
    scratchdisk1 = drive_tools.FilesystemFile(tempfile.mktemp(),
                                              new_file_size_mb)
    basevm.patch_drive('scratch', scratchdisk1)

    logger.info("Create %s #0.", snapshot_type)
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    disks = [root_disk.local_path(), scratchdisk1.path]
    # Create base snapshot.
    snapshot = snapshot_builder.create(disks,
                                       ssh_key,
                                       snapshot_type)

    basevm.kill()

    # Load snapshot in a new Firecracker microVM.
    logger.info("Load snapshot, mem %s", snapshot.mem)
    microvm, _ = vm_builder.build_from_snapshot(snapshot,
                                                True,
                                                enable_diff_snapshots)
    # Attempt to connect to resumed microvm.
    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

    # Verify the new microVM has the right scratch drive.
    guest_drive_size = _get_guest_drive_size(ssh_connection)
    assert guest_drive_size == str(scratchdisk1.size())

    microvm.kill()


def test_5_full_snapshots(network_config,
                          bin_cloner_path,
                          bin_vsock_path,
                          test_fc_session_root_path):
    """Test scenario: 5 full sequential snapshots."""
    logger = logging.getLogger("snapshot_sequence")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: Linux 4.9/4.14
    # - Rootfs: Ubuntu 18.04
    # - Microvm: 2vCPU with 512 MB RAM
    # TODO: Multiple microvm sizes must be tested in the async pipeline.
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_512mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels(keyword="vmlinux-4.14"))
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'network_config': network_config,
        'logger': logger,
        'snapshot_type': SnapshotType.FULL,
        'seq_len': 5,
        'bin_vsock_path': bin_vsock_path,
        'test_fc_session_root_path': test_fc_session_root_path
    }

    # Create the test matrix.
    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])

    test_matrix.run_test(_test_seq_snapshots)


def test_5_inc_snapshots(network_config,
                         bin_cloner_path):
    """Test scenario: 5 incremental snapshots with disk intensive workload."""
    logger = logging.getLogger("snapshot_sequence")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: Linux 4.9/4.14
    # - Rootfs: Ubuntu 18.04
    # - Microvm: 2vCPU with 512 MB RAM
    # TODO: Multiple microvm sizes must be tested in the async pipeline.
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_4096mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels(keyword="vmlinux-4.14"))
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'network_config': network_config,
        'logger': logger,
        'snapshot_type': SnapshotType.DIFF,
        'seq_len': 5
    }

    # Create the test matrix.
    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])

    test_matrix.run_test(_test_seq_snapshots)


def test_load_snapshot_failure_handling(test_microvm_with_api):
    """
    Test scenario.

    1. Create two empty files representing snapshot memory and
    microvm state
    2. Try to load a VM snapshot out of the empty files.
    3. Verify that an error was shown and the FC process is terminated.
    """
    logger = logging.getLogger("snapshot_load_failure")
    vm = test_microvm_with_api
    vm.spawn(log_level='Info')

    # Create two empty files for snapshot state and snapshot memory
    chroot_path = vm.jailer.chroot_path()
    snapshot_dir = os.path.join(chroot_path, "snapshot")
    Path(snapshot_dir).mkdir(parents=True, exist_ok=True)

    snapshot_mem = os.path.join(snapshot_dir, "snapshot_mem")
    open(snapshot_mem, "w+").close()
    snapshot_vmstate = os.path.join(snapshot_dir, "snapshot_vmstate")
    open(snapshot_vmstate, "w+").close()

    # Hardlink the snapshot files into the microvm jail.
    jailed_mem = vm.create_jailed_resource(snapshot_mem)
    jailed_vmstate = vm.create_jailed_resource(snapshot_vmstate)

    # Load the snapshot
    response = vm.snapshot.load(mem_file_path=jailed_mem,
                                snapshot_path=jailed_vmstate)

    logger.info("Response status code %d, content: %s.",
                response.status_code,
                response.text)
    assert vm.api_session.is_status_bad_request(response.status_code)
    assert "Cannot deserialize MicrovmState" in response.text

    # Check if FC process is closed
    wait_process_termination(vm.jailer_clone_pid)


def test_cmp_full_and_first_diff_mem(network_config,
                                     bin_cloner_path):
    """Test scenario: cmp memory of 2 consecutive full and diff snapshots."""
    logger = logging.getLogger("snapshot_sequence")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: Linux 4.9/4.14
    # - Rootfs: Ubuntu 18.04
    # - Microvm: 2vCPU with 512 MB RAM
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_512mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels(keyword="vmlinux-4.14"))
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'network_config': network_config,
        'logger': logger
    }

    # Create the test matrix.
    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])

    test_matrix.run_test(_test_compare_mem_files)
