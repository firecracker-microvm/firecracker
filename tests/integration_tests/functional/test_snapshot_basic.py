# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import filecmp
import logging
import os
from pathlib import Path

import pytest

import host_tools.drive as drive_tools
from framework.microvm import SnapshotType
from framework.utils import check_filesystem, wait_process_termination
from framework.utils_vsock import (
    ECHO_SERVER_PORT,
    VSOCK_UDS_PATH,
    _copy_vsock_data_to_guest,
    check_guest_connections,
    check_host_connections,
    make_blob,
    make_host_port_path,
)


def _get_guest_drive_size(ssh_connection, guest_dev_name="/dev/vdb"):
    # `lsblk` command outputs 2 lines to STDOUT:
    # "SIZE" and the size of the device, in bytes.
    blksize_cmd = "lsblk -b {} --output SIZE".format(guest_dev_name)
    _, stdout, stderr = ssh_connection.execute_command(blksize_cmd)
    assert stderr == ""
    lines = stdout.split("\n")
    return lines[1].strip()


# Testing matrix:
# - Guest kernel: All supported ones
# - Rootfs: Ubuntu 18.04
# - Microvm: 2vCPU with 512 MB RAM
# TODO: Multiple microvm sizes must be tested in the async pipeline.
@pytest.mark.parametrize("snapshot_type", [SnapshotType.DIFF, SnapshotType.FULL])
def test_5_snapshots(
    bin_vsock_path,
    tmp_path,
    microvm_factory,
    guest_kernel,
    rootfs,
    snapshot_type,
):
    """
    Create and load 5 snapshots.
    """
    logger = logging.getLogger("snapshot_sequence")
    seq_len = 5
    diff_snapshots = snapshot_type == SnapshotType.DIFF

    vm = microvm_factory.build(guest_kernel, rootfs)
    vm.spawn()
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=512,
        track_dirty_pages=diff_snapshots,
    )
    vm.add_net_iface()
    vm.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path=VSOCK_UDS_PATH)
    vm.start()
    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.run("sync")
    assert exit_code == 0

    vm_blob_path = "/tmp/vsock/test.blob"
    # Generate a random data file for vsock.
    blob_path, blob_hash = make_blob(tmp_path)
    # Copy the data file and a vsock helper to the guest.
    _copy_vsock_data_to_guest(vm.ssh, blob_path, vm_blob_path, bin_vsock_path)

    logger.info("Create %s #0.", snapshot_type)
    # Create a snapshot from a microvm.
    snapshot = vm.make_snapshot(snapshot_type)
    base_snapshot = snapshot

    for i in range(seq_len):
        logger.info("Load snapshot #%s, mem %s", i, snapshot.mem)
        microvm = microvm_factory.build()
        microvm.spawn()
        microvm.restore_from_snapshot(snapshot, resume=True)
        # Test vsock guest-initiated connections.
        path = os.path.join(
            microvm.path, make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT)
        )
        check_guest_connections(microvm, path, vm_blob_path, blob_hash)
        # Test vsock host-initiated connections.
        path = os.path.join(microvm.jailer.chroot_path(), VSOCK_UDS_PATH)
        check_host_connections(microvm, path, blob_path, blob_hash)

        # Check that the root device is not corrupted.
        check_filesystem(microvm.ssh, "squashfs", "/dev/vda")

        logger.info("Create snapshot %s #%d.", snapshot_type, i + 1)
        snapshot = microvm.make_snapshot(snapshot_type)

        # If we are testing incremental snapshots we must merge the base with
        # current layer.
        if snapshot.is_diff:
            logger.info("Base: %s, Layer: %s", base_snapshot.mem, snapshot.mem)
            snapshot = snapshot.rebase_snapshot(base_snapshot)

        # Update the base for next iteration.
        base_snapshot = snapshot


def test_patch_drive_snapshot(uvm_nano, microvm_factory):
    """
    Test that a patched drive is correctly used by guests loaded from snapshot.
    """
    logger = logging.getLogger("snapshot_sequence")

    # Use a predefined vm instance.
    basevm = uvm_nano
    basevm.add_net_iface()

    # Add a scratch 128MB RW non-root block device.
    root = Path(basevm.path)
    scratch_path1 = str(root / "scratch1")
    scratch_disk1 = drive_tools.FilesystemFile(scratch_path1, size=128)
    basevm.add_drive("scratch", scratch_disk1.path)
    basevm.start()
    # Verify if guest can run commands.
    exit_code, _, _ = basevm.ssh.run("sync")
    assert exit_code == 0

    # Update drive to have another backing file, double in size.
    new_file_size_mb = 2 * int(scratch_disk1.size() / (1024 * 1024))
    logger.info("Patch drive, new file: size %sMB.", new_file_size_mb)
    scratch_path2 = str(root / "scratch2")
    scratch_disk2 = drive_tools.FilesystemFile(scratch_path2, new_file_size_mb)
    basevm.patch_drive("scratch", scratch_disk2)

    # Create base snapshot.
    logger.info("Create FULL snapshot #0.")
    snapshot = basevm.snapshot_full()

    # Load snapshot in a new Firecracker microVM.
    logger.info("Load snapshot, mem %s", snapshot.mem)
    vm = microvm_factory.build()
    vm.spawn()
    vm.restore_from_snapshot(snapshot, resume=True)
    # Attempt to connect to resumed microvm and verify the new microVM has the
    # right scratch drive.
    guest_drive_size = _get_guest_drive_size(vm.ssh)
    assert guest_drive_size == str(scratch_disk2.size())


def test_load_snapshot_failure_handling(test_microvm_with_api):
    """
    Test error case of loading empty snapshot files.
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


def test_cmp_full_and_first_diff_mem(microvm_factory, guest_kernel, rootfs):
    """
    Compare memory of 2 consecutive full and diff snapshots.

    Testing matrix:
    - Guest kernel: All supported ones
    - Rootfs: Ubuntu 18.04
    - Microvm: 2vCPU with 512 MB RAM
    """
    logger = logging.getLogger("snapshot_sequence")

    vm = microvm_factory.build(guest_kernel, rootfs)
    vm.spawn()
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=512,
        track_dirty_pages=True,
    )
    vm.add_net_iface()
    vm.start()

    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.execute_command("sync")
    assert exit_code == 0

    logger.info("Create full snapshot.")
    # Create full snapshot.
    full_snapshot = vm.snapshot_full()

    logger.info("Create diff snapshot.")
    # Create diff snapshot.
    diff_snapshot = vm.snapshot_diff()

    assert filecmp.cmp(full_snapshot.mem, diff_snapshot.mem)


def test_negative_postload_api(test_microvm_with_api, microvm_factory):
    """
    Test APIs fail after loading from snapshot.
    """
    basevm = test_microvm_with_api
    basevm.spawn()
    basevm.basic_config(track_dirty_pages=True)
    basevm.add_net_iface()
    basevm.start()
    # Verify if guest can run commands.
    exit_code, _, _ = basevm.ssh.run("sync")
    assert exit_code == 0

    # Create base snapshot.
    snapshot = basevm.snapshot_diff()
    basevm.kill()

    # Do not resume, just load, so we can still call APIs that work.
    microvm = microvm_factory.build()
    microvm.spawn()
    microvm.restore_from_snapshot(snapshot)

    fail_msg = "The requested operation is not supported after starting the microVM"
    response = microvm.actions.put(action_type="InstanceStart")
    assert fail_msg in response.text

    try:
        microvm.basic_config()
    except AssertionError as error:
        assert fail_msg in str(error)
    else:
        assert False, "Negative test failed"


def test_negative_snapshot_permissions(uvm_plain_rw, microvm_factory):
    """
    Test missing permission error scenarios.
    """
    basevm = uvm_plain_rw
    basevm.spawn()
    basevm.basic_config()
    basevm.add_net_iface()
    basevm.start()

    # Remove write permissions.
    os.chmod(basevm.jailer.chroot_path(), 0o444)

    try:
        snapshot = basevm.snapshot_full()
    except AssertionError as error:
        # Check if proper error is returned.
        assert "Permission denied" in str(error)
    else:
        assert False, "Negative test failed"

    # Restore proper permissions.
    os.chmod(basevm.jailer.chroot_path(), 0o744)

    # Create base snapshot.
    snapshot = basevm.snapshot_full()
    basevm.kill()

    # Remove permissions for mem file.
    os.chmod(snapshot.mem, 0o000)

    microvm = microvm_factory.build()
    microvm.spawn()

    try:
        microvm.restore_from_snapshot(snapshot, resume=True)
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

    microvm = microvm_factory.build()
    microvm.spawn()

    try:
        microvm.restore_from_snapshot(snapshot, resume=True)
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
    os.chmod(snapshot.disks["rootfs"], 0o000)

    microvm = microvm_factory.build()
    microvm.spawn()

    try:
        microvm.restore_from_snapshot(snapshot, resume=True)
    except AssertionError as error:
        # Check if proper error is returned.
        assert "Block(BackingFile(Os { code: 13, kind: PermissionDenied" in str(error)
    else:
        assert False, "Negative test failed"


def test_negative_snapshot_create(uvm_nano):
    """
    Test create snapshot before pause.
    """
    vm = uvm_nano
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
