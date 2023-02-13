# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import filecmp
import logging
import os
import tempfile
from pathlib import Path

import pytest

from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.matrix import TestMatrix, TestContext
from framework.utils import (
    wait_process_termination,
    check_filesystem,
)
from framework.utils_vsock import (
    make_blob,
    check_host_connections,
    check_guest_connections,
    _copy_vsock_data_to_guest,
    VSOCK_UDS_PATH,
    make_host_port_path,
    ECHO_SERVER_PORT,
)

import host_tools.drive as drive_tools


def _get_guest_drive_size(ssh_connection, guest_dev_name="/dev/vdb"):
    # `lsblk` command outputs 2 lines to STDOUT:
    # "SIZE" and the size of the device, in bytes.
    blksize_cmd = "lsblk -b {} --output SIZE".format(guest_dev_name)
    _, stdout, stderr = ssh_connection.execute_command(blksize_cmd)
    assert stderr.read() == ""
    stdout.readline()  # skip "SIZE"
    return stdout.readline().strip()


ARTIFACTS = ArtifactCollection(_test_images_s3_bucket())

# Testing matrix:
# - Guest kernel: All supported ones
# - Rootfs: Ubuntu 18.04
# - Microvm: 2vCPU with 512 MB RAM
# TODO: Multiple microvm sizes must be tested in the async pipeline.
@pytest.mark.parametrize(
    "microvm", ARTIFACTS.microvms(keyword="2vcpu_512mb"), ids=lambda x: x.name()
)
@pytest.mark.parametrize("kernel", ARTIFACTS.kernels(), ids=lambda x: x.name())
@pytest.mark.parametrize(
    "disk", ARTIFACTS.disks(keyword="ubuntu"), ids=lambda x: x.name()
)
@pytest.mark.parametrize("snapshot_type", [SnapshotType.DIFF, SnapshotType.FULL])
def test_5_snapshots(
    bin_cloner_path,
    bin_vsock_path,
    test_fc_session_root_path,
    microvm,
    kernel,
    disk,
    snapshot_type,
):
    """
    Create and load 5 snapshots.

    @type: functional
    """
    logger = logging.getLogger("snapshot_sequence")

    vm_builder = MicrovmBuilder(bin_cloner_path)
    seq_len = 5
    diff_snapshots = snapshot_type == SnapshotType.DIFF

    disk.download()
    kernel.download()
    microvm.download()

    # Create a rw copy artifact.
    root_disk = disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = disk.ssh_key()
    # Create a fresh microvm from artifacts.
    vm_instance = vm_builder.build(
        kernel=kernel,
        disks=[root_disk],
        ssh_key=ssh_key,
        config=microvm,
        diff_snapshots=diff_snapshots,
    )
    basevm = vm_instance.vm
    basevm.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path=f"/{VSOCK_UDS_PATH}")

    basevm.start()
    # Verify if guest can run commands.
    exit_code, _, _ = basevm.ssh.run("sync")
    assert exit_code == 0

    vm_blob_path = "/tmp/vsock/test.blob"
    # Generate a random data file for vsock.
    blob_path, blob_hash = make_blob(test_fc_session_root_path)
    # Copy the data file and a vsock helper to the guest.
    _copy_vsock_data_to_guest(basevm.ssh, blob_path, vm_blob_path, bin_vsock_path)

    logger.info("Create %s #0.", snapshot_type)
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    # Create base snapshot.
    snapshot = snapshot_builder.create([root_disk.local_path()], ssh_key, snapshot_type)

    base_snapshot = snapshot
    basevm.kill()

    for i in range(seq_len):
        logger.info("Load snapshot #%s, mem %s", i, snapshot.mem)
        microvm, _ = vm_builder.build_from_snapshot(
            snapshot, resume=True, diff_snapshots=diff_snapshots
        )
        # Test vsock guest-initiated connections.
        path = os.path.join(
            microvm.path, make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT)
        )
        check_guest_connections(microvm, path, vm_blob_path, blob_hash)
        # Test vsock host-initiated connections.
        path = os.path.join(microvm.jailer.chroot_path(), VSOCK_UDS_PATH)
        check_host_connections(microvm, path, blob_path, blob_hash)

        # Check that the root device is not corrupted.
        check_filesystem(microvm.ssh, "ext4", "/dev/vda")

        logger.info("Create snapshot #%d.", i + 1)

        # Create a snapshot builder from the currently running microvm.
        snapshot_builder = SnapshotBuilder(microvm)

        snapshot = snapshot_builder.create(
            [root_disk.local_path()], ssh_key, snapshot_type
        )

        # If we are testing incremental snapshots we must merge the base with
        # current layer.
        if snapshot_type == SnapshotType.DIFF:
            logger.info("Base: %s, Layer: %s", base_snapshot.mem, snapshot.mem)
            snapshot.rebase_snapshot(base_snapshot)
            # Update the base for next iteration.
            base_snapshot = snapshot

        microvm.kill()


def _test_compare_mem_files(context):
    logger = context.custom["logger"]
    vm_builder = context.custom["builder"]

    # Create a rw copy artifact.
    root_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from artifacts.
    vm_instance = vm_builder.build(
        kernel=context.kernel,
        disks=[root_disk],
        ssh_key=ssh_key,
        config=context.microvm,
        diff_snapshots=True,
    )
    basevm = vm_instance.vm
    basevm.start()
    # Verify if guest can run commands.
    exit_code, _, _ = basevm.ssh.execute_command("sync")
    assert exit_code == 0

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    logger.info("Create full snapshot.")
    # Create full snapshot.
    full_snapshot = snapshot_builder.create(
        [root_disk.local_path()], ssh_key, SnapshotType.FULL
    )

    logger.info("Create diff snapshot.")
    # Create diff snapshot.
    diff_snapshot = snapshot_builder.create(
        [root_disk.local_path()],
        ssh_key,
        SnapshotType.DIFF,
        mem_file_name="diff_vm.mem",
        snapshot_name="diff_vm.vmstate",
    )
    assert filecmp.cmp(full_snapshot.mem, diff_snapshot.mem)

    basevm.kill()


def test_patch_drive_snapshot(bin_cloner_path):
    """
    Test that a patched drive is correctly used by guests loaded from snapshot.

    @type: functional
    """
    logger = logging.getLogger("snapshot_sequence")

    vm_builder = MicrovmBuilder(bin_cloner_path)
    snapshot_type = SnapshotType.FULL
    diff_snapshots = False

    # Use a predefined vm instance.
    vm_instance = vm_builder.build_vm_nano()
    basevm = vm_instance.vm
    root_disk = vm_instance.disks[0]
    ssh_key = vm_instance.ssh_key

    # Add a scratch 128MB RW non-root block device.
    scratchdisk1 = drive_tools.FilesystemFile(tempfile.mktemp(), size=128)
    basevm.add_drive("scratch", scratchdisk1.path)

    basevm.start()
    # Verify if guest can run commands.
    exit_code, _, _ = basevm.ssh.run("sync")
    assert exit_code == 0

    # Update drive to have another backing file, double in size.
    new_file_size_mb = 2 * int(scratchdisk1.size() / (1024 * 1024))
    logger.info("Patch drive, new file: size %sMB.", new_file_size_mb)
    scratchdisk1 = drive_tools.FilesystemFile(tempfile.mktemp(), new_file_size_mb)
    basevm.patch_drive("scratch", scratchdisk1)

    logger.info("Create %s #0.", snapshot_type)
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    disks = [root_disk.local_path(), scratchdisk1.path]
    # Create base snapshot.
    snapshot = snapshot_builder.create(disks, ssh_key, snapshot_type)

    basevm.kill()

    # Load snapshot in a new Firecracker microVM.
    logger.info("Load snapshot, mem %s", snapshot.mem)
    microvm, _ = vm_builder.build_from_snapshot(
        snapshot, resume=True, diff_snapshots=diff_snapshots
    )
    # Attempt to connect to resumed microvm and verify the new microVM has the
    # right scratch drive.
    guest_drive_size = _get_guest_drive_size(microvm.ssh)
    assert guest_drive_size == str(scratchdisk1.size())

    microvm.kill()


def test_load_snapshot_failure_handling(test_microvm_with_api):
    """
    Test error case of loading empty snapshot files.

    @type: functional
    """
    logger = logging.getLogger("snapshot_load_failure")
    vm = test_microvm_with_api
    vm.spawn(log_level="Info")

    # Create two empty files for snapshot state and snapshot memory
    chroot_path = vm.jailer.chroot_path()
    snapshot_dir = os.path.join(chroot_path, "snapshot")
    Path(snapshot_dir).mkdir(parents=True, exist_ok=True)

    snapshot_mem = os.path.join(snapshot_dir, "snapshot_mem")
    open(snapshot_mem, "w+", encoding="utf-8").close()
    snapshot_vmstate = os.path.join(snapshot_dir, "snapshot_vmstate")
    open(snapshot_vmstate, "w+", encoding="utf-8").close()

    # Hardlink the snapshot files into the microvm jail.
    jailed_mem = vm.create_jailed_resource(snapshot_mem)
    jailed_vmstate = vm.create_jailed_resource(snapshot_vmstate)

    # Load the snapshot
    response = vm.snapshot.load(mem_file_path=jailed_mem, snapshot_path=jailed_vmstate)

    logger.info(
        "Response status code %d, content: %s.", response.status_code, response.text
    )
    assert vm.api_session.is_status_bad_request(response.status_code)
    assert (
        "Load microVM snapshot error: Failed to restore from snapshot: Failed to get snapshot "
        "state from file: Failed to load snapshot state from file: Snapshot file is smaller "
        "than CRC length."
    ) in response.text

    # Check if FC process is closed
    wait_process_termination(vm.jailer_clone_pid)


def test_cmp_full_and_first_diff_mem(network_config, bin_cloner_path):
    """
    Compare memory of 2 consecutive full and diff snapshots.

    @type: functional
    """
    logger = logging.getLogger("snapshot_sequence")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: All supported ones
    # - Rootfs: Ubuntu 18.04
    # - Microvm: 2vCPU with 512 MB RAM
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_512mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels())
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        "builder": MicrovmBuilder(bin_cloner_path),
        "network_config": network_config,
        "logger": logger,
    }

    # Create the test matrix.
    test_matrix = TestMatrix(
        context=test_context,
        artifact_sets=[microvm_artifacts, kernel_artifacts, disk_artifacts],
    )

    test_matrix.run_test(_test_compare_mem_files)


def test_negative_postload_api(bin_cloner_path):
    """
    Test APIs fail after loading from snapshot.

    @type: negative
    """
    logger = logging.getLogger("snapshot_api_fail")

    vm_builder = MicrovmBuilder(bin_cloner_path)
    vm_instance = vm_builder.build_vm_nano(diff_snapshots=True)
    basevm = vm_instance.vm
    root_disk = vm_instance.disks[0]
    ssh_key = vm_instance.ssh_key

    basevm.start()
    # Verify if guest can run commands.
    exit_code, _, _ = basevm.ssh.run("sync")
    assert exit_code == 0

    logger.info("Create snapshot")
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    # Create base snapshot.
    snapshot = snapshot_builder.create(
        [root_disk.local_path()], ssh_key, SnapshotType.DIFF
    )

    basevm.kill()

    logger.info("Load snapshot, mem %s", snapshot.mem)
    # Do not resume, just load, so we can still call APIs that work.
    microvm, _ = vm_builder.build_from_snapshot(
        snapshot, resume=False, diff_snapshots=True
    )
    fail_msg = "The requested operation is not supported after starting " "the microVM"

    response = microvm.actions.put(action_type="InstanceStart")
    assert fail_msg in response.text

    try:
        microvm.basic_config()
    except AssertionError as error:
        assert fail_msg in str(error)
    else:
        assert False, "Negative test failed"

    microvm.kill()


def test_negative_snapshot_permissions(bin_cloner_path):
    """
    Test missing permission error scenarios.

    @type: negative
    """
    logger = logging.getLogger("snapshot_negative")
    vm_builder = MicrovmBuilder(bin_cloner_path)

    # Use a predefined vm instance.
    vm_instance = vm_builder.build_vm_nano()
    basevm = vm_instance.vm
    root_disk = vm_instance.disks[0]
    ssh_key = vm_instance.ssh_key

    basevm.start()

    logger.info("Create snapshot")
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    disks = [root_disk.local_path()]

    # Remove write permissions.
    os.chmod(basevm.jailer.chroot_path(), 0o444)

    try:
        _ = snapshot_builder.create(disks, ssh_key, SnapshotType.FULL)
    except AssertionError as error:
        # Check if proper error is returned.
        assert "Permission denied" in str(error)
    else:
        assert False, "Negative test failed"

    # Restore proper permissions.
    os.chmod(basevm.jailer.chroot_path(), 0o744)

    # Create base snapshot.
    snapshot = snapshot_builder.create(disks, ssh_key, SnapshotType.FULL)

    logger.info("Load snapshot, mem %s", snapshot.mem)

    basevm.kill()

    # Remove permissions for mem file.
    os.chmod(snapshot.mem, 0o000)

    try:
        _, _ = vm_builder.build_from_snapshot(
            snapshot, resume=True, diff_snapshots=True
        )
    except AssertionError as error:
        # Check if proper error is returned.
        assert (
            "Load microVM snapshot error: Failed to restore from snapshot: Failed to load guest "
            "memory: Error creating guest memory from file: Failed to load guest memory: "
            "Permission denied (os error 13)"
        ) in str(error)
    else:
        assert False, "Negative test failed"

    # Remove permissions for state file.
    os.chmod(snapshot.vmstate, 0o000)

    try:
        _, _ = vm_builder.build_from_snapshot(
            snapshot, resume=True, diff_snapshots=True
        )
    except AssertionError as error:
        # Check if proper error is returned.
        assert (
            "Load microVM snapshot error: Failed to restore from snapshot: Failed to get snapshot "
            "state from file: Failed to open snapshot file: Permission denied (os error 13)"
        ) in str(error)
    else:
        assert False, "Negative test failed"

    # Restore permissions for state file.
    os.chmod(snapshot.vmstate, 0o744)
    os.chmod(snapshot.mem, 0o744)

    # Remove permissions for block file.
    os.chmod(snapshot.disks[0], 0o000)

    try:
        _, _ = vm_builder.build_from_snapshot(
            snapshot, resume=True, diff_snapshots=True
        )
    except AssertionError as error:
        # Check if proper error is returned.
        assert "Block(BackingFile(Os { code: 13, kind: PermissionDenied" in str(error)
    else:
        assert False, "Negative test failed"


def test_negative_snapshot_create(bin_cloner_path):
    """
    Test create snapshot before pause.

    @type: negative
    """
    vm_builder = MicrovmBuilder(bin_cloner_path)
    vm_instance = vm_builder.build_vm_nano()
    vm = vm_instance.vm

    vm.start()

    response = vm.snapshot.create(
        mem_file_path="memfile", snapshot_path="statefile", diff=False
    )

    assert vm.api_session.is_status_bad_request(response.status_code)
    assert "save/restore unavailable while running" in response.text

    response = vm.vm.patch(state="Paused")
    assert vm.api_session.is_status_no_content(response.status_code)

    # Try diff with dirty pages tracking disabled.
    response = vm.snapshot.create(
        mem_file_path="memfile", snapshot_path="statefile", diff=True
    )
    msg = "Diff snapshots are not allowed on uVMs with dirty page" " tracking disabled"
    assert msg in response.text
    assert not os.path.exists("statefile")
    assert not os.path.exists("memfile")

    vm.kill()


def test_create_large_diff_snapshot(test_microvm_with_api):
    """
    Create large diff snapshot seccomp regression test.

    When creating a diff snapshot of a microVM with a large memory size, a
    mmap(MAP_PRIVATE|MAP_ANONYMOUS) is issued. Test that the default seccomp
    filter allows it.

    @type: regression
    @issue: https://github.com/firecracker-microvm/firecracker/discussions/2811
    """
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config(mem_size_mib=16 * 1024, track_dirty_pages=True)

    vm.start()

    response = vm.vm.patch(state="Paused")
    assert vm.api_session.is_status_no_content(response.status_code)

    response = vm.snapshot.create(
        mem_file_path="memfile", snapshot_path="statefile", diff=True
    )

    # If the regression was not fixed, this would have failed. The Firecracker
    # process would have been taken down.
    assert vm.api_session.is_status_no_content(response.status_code)
