# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import filecmp
import logging
import os
import re
import shutil
from pathlib import Path

import pytest

import host_tools.drive as drive_tools
from framework.microvm import SnapshotType
from framework.utils import (
    check_filesystem,
    get_firecracker_version_from_toml,
    run_cmd,
    wait_process_termination,
)
from framework.utils_vsock import (
    ECHO_SERVER_PORT,
    VSOCK_UDS_PATH,
    _copy_vsock_data_to_guest,
    check_guest_connections,
    check_host_connections,
    make_blob,
    make_host_port_path,
    start_guest_echo_server,
)


def _get_guest_drive_size(ssh_connection, guest_dev_name="/dev/vdb"):
    # `lsblk` command outputs 2 lines to STDOUT:
    # "SIZE" and the size of the device, in bytes.
    blksize_cmd = "lsblk -b {} --output SIZE".format(guest_dev_name)
    _, stdout, stderr = ssh_connection.run(blksize_cmd)
    assert stderr == ""
    lines = stdout.split("\n")
    return lines[1].strip()


def test_snapshot_current_version(uvm_nano):
    """Tests taking a snapshot at the version specified in Cargo.toml

    Check that it is possible to take a snapshot at the version of the upcoming
    release (during the release process this ensures that if we release version
    x.y, then taking a snapshot at version x.y works - something we'd otherwise
    only be able to test once the x.y binary has been uploaded to S3, at which
    point it is too late, see also the 1.3 release).
    """
    vm = uvm_nano
    vm.start()

    version = get_firecracker_version_from_toml()
    # normalize to a snapshot version
    version = f"{version.major}.{version.minor}.0"
    snapshot = vm.snapshot_full()

    # Fetch Firecracker binary for the latest version
    fc_binary = uvm_nano.fc_binary_path
    # Verify the output of `--describe-snapshot` command line parameter
    cmd = [str(fc_binary)] + ["--describe-snapshot", str(snapshot.vmstate)]

    _, stdout, _ = run_cmd(cmd)
    assert version in stdout


# Testing matrix:
# - Guest kernel: All supported ones
# - Rootfs: Ubuntu 18.04
# - Microvm: 2vCPU with 512 MB RAM
# TODO: Multiple microvm sizes must be tested in the async pipeline.
@pytest.mark.parametrize("snapshot_type", [SnapshotType.DIFF, SnapshotType.FULL])
@pytest.mark.parametrize("use_snapshot_editor", [False, True])
def test_5_snapshots(
    bin_vsock_path,
    tmp_path,
    microvm_factory,
    guest_kernel,
    rootfs,
    snapshot_type,
    use_snapshot_editor,
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
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path=VSOCK_UDS_PATH)
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
    start_guest_echo_server(vm)
    snapshot = vm.make_snapshot(snapshot_type)
    base_snapshot = snapshot

    for i in range(seq_len):
        logger.info("Load snapshot #%s, mem %s", i, snapshot.mem)
        microvm = microvm_factory.build()
        microvm.spawn()
        microvm.restore_from_snapshot(snapshot, resume=True)
        # TODO: SIGCONT here and SIGSTOP later before creating snapshot
        # is a temporary fix to avoid vsock timeout in
        # _vsock_connect_to_guest(). This will be removed once we
        # find the right solution for the timeout.
        vm.ssh.run("pkill -SIGCONT socat")
        # Test vsock guest-initiated connections.
        path = os.path.join(
            microvm.path, make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT)
        )
        check_guest_connections(microvm, path, vm_blob_path, blob_hash)
        # Test vsock host-initiated connections.
        path = os.path.join(microvm.jailer.chroot_path(), VSOCK_UDS_PATH)
        check_host_connections(path, blob_path, blob_hash)

        # Check that the root device is not corrupted.
        check_filesystem(microvm.ssh, "squashfs", "/dev/vda")
        vm.ssh.run("pkill -SIGSTOP socat")

        logger.info("Create snapshot %s #%d.", snapshot_type, i + 1)
        snapshot = microvm.make_snapshot(snapshot_type)

        # If we are testing incremental snapshots we must merge the base with
        # current layer.
        if snapshot.is_diff:
            logger.info("Base: %s, Layer: %s", base_snapshot.mem, snapshot.mem)
            snapshot = snapshot.rebase_snapshot(
                base_snapshot, use_snapshot_editor=use_snapshot_editor
            )

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
    expected_msg = (
        "Load snapshot error: Failed to restore from snapshot: Failed to get snapshot "
        "state from file: Failed to load snapshot state from file: Snapshot file is smaller "
        "than CRC length."
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.snapshot_load.put(mem_file_path=jailed_mem, snapshot_path=jailed_vmstate)

    # Check if FC process is closed
    wait_process_termination(vm.firecracker_pid)


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
    exit_code, _, _ = vm.ssh.run("sync")
    assert exit_code == 0

    logger.info("Create full snapshot.")
    # Create full snapshot.
    full_snapshot = vm.snapshot_full(mem_path="mem_full")

    logger.info("Create diff snapshot.")
    # Create diff snapshot.
    diff_snapshot = vm.snapshot_diff()

    assert full_snapshot.mem != diff_snapshot.mem
    assert filecmp.cmp(full_snapshot.mem, diff_snapshot.mem, shallow=False)


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
    microvm.restore_from_snapshot(snapshot, resume=True)

    fail_msg = "The requested operation is not supported after starting the microVM"
    with pytest.raises(RuntimeError, match=fail_msg):
        microvm.api.actions.put(action_type="InstanceStart")

    with pytest.raises(RuntimeError, match=fail_msg):
        microvm.basic_config()


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

    with pytest.raises(RuntimeError, match="Permission denied"):
        basevm.snapshot_full()

    # Restore proper permissions.
    os.chmod(basevm.jailer.chroot_path(), 0o744)

    # Create base snapshot.
    snapshot = basevm.snapshot_full()
    basevm.kill()

    # Remove permissions for mem file.
    os.chmod(snapshot.mem, 0o000)

    microvm = microvm_factory.build()
    microvm.spawn()

    expected_err = re.escape(
        "Load snapshot error: Failed to restore from snapshot: Failed to load guest "
        "memory: Error creating guest memory from file: Failed to load guest memory: "
        "Permission denied (os error 13)"
    )
    with pytest.raises(RuntimeError, match=expected_err):
        microvm.restore_from_snapshot(snapshot, resume=True)

    # Remove permissions for state file.
    os.chmod(snapshot.vmstate, 0o000)

    microvm = microvm_factory.build()
    microvm.spawn()

    expected_err = re.escape(
        "Load snapshot error: Failed to restore from snapshot: Failed to get snapshot "
        "state from file: Failed to open snapshot file: Permission denied (os error 13)"
    )
    with pytest.raises(RuntimeError, match=expected_err):
        microvm.restore_from_snapshot(snapshot, resume=True)

    # Restore permissions for state file.
    os.chmod(snapshot.vmstate, 0o744)
    os.chmod(snapshot.mem, 0o744)

    # Remove permissions for block file.
    os.chmod(snapshot.disks["rootfs"], 0o000)

    microvm = microvm_factory.build()
    microvm.spawn()

    expected_err = "VirtioBlock: Error manipulating the backing file: Permission denied (os error 13)"
    with pytest.raises(RuntimeError, match=re.escape(expected_err)):
        microvm.restore_from_snapshot(snapshot, resume=True)


def test_negative_snapshot_create(uvm_nano):
    """
    Test create snapshot before pause.
    """
    vm = uvm_nano
    vm.start()

    with pytest.raises(RuntimeError, match="save/restore unavailable while running"):
        vm.api.snapshot_create.put(
            mem_file_path="memfile", snapshot_path="statefile", snapshot_type="Full"
        )

    vm.api.vm.patch(state="Paused")

    # Try diff with dirty pages tracking disabled.
    expected_msg = (
        "Diff snapshots are not allowed on uVMs with dirty page tracking disabled"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.snapshot_create.put(
            mem_file_path="memfile", snapshot_path="statefile", snapshot_type="Diff"
        )
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

    vm.api.vm.patch(state="Paused")

    vm.api.snapshot_create.put(
        mem_file_path="memfile", snapshot_path="statefile", snapshot_type="Diff"
    )

    # If the regression was not fixed, this would have failed. The Firecracker
    # process would have been taken down.


def test_diff_snapshot_overlay(guest_kernel, rootfs, microvm_factory):
    """
    Tests that if we take a diff snapshot and direct firecracker to write it on
    top of an existing snapshot file, it will successfully merge them.
    """
    basevm = microvm_factory.build(guest_kernel, rootfs)
    basevm.spawn()
    basevm.basic_config(track_dirty_pages=True)
    basevm.add_net_iface()
    basevm.start()

    # Wait for microvm to be booted
    rc, _, stderr = basevm.ssh.run("true")
    assert rc == 0, stderr

    # The first snapshot taken will always contain all memory (even if its specified as "diff").
    # We use a diff snapshot here, as taking a full snapshot does not clear the dirty page tracking,
    # meaning the `snapshot_diff()` call below would again dump the entire guest memory instead of
    # only dirty regions.
    full_snapshot = basevm.snapshot_diff()
    basevm.resume()

    # Run some command to dirty some pages
    rc, _, stderr = basevm.ssh.run("true")
    assert rc == 0, stderr

    # First copy the base snapshot somewhere else, so we can make sure
    # it will actually get updated
    first_snapshot_backup = Path(basevm.chroot()) / "mem.old"
    shutil.copyfile(full_snapshot.mem, first_snapshot_backup)

    # One Microvm object will always write its snapshot files to the same location
    merged_snapshot = basevm.snapshot_diff()
    assert full_snapshot.mem == merged_snapshot.mem

    assert not filecmp.cmp(merged_snapshot.mem, first_snapshot_backup, shallow=False)

    new_vm = microvm_factory.build()
    new_vm.spawn()
    new_vm.restore_from_snapshot(merged_snapshot, resume=True)

    # Run some command to check that the restored VM works
    rc, _, stderr = new_vm.ssh.run("true")
    assert rc == 0, stderr


def test_snapshot_overwrite_self(guest_kernel, rootfs, microvm_factory):
    """Tests that if we try to take a snapshot that would overwrite the
    very file from which the current VM is stored, nothing happens.

    Note that even though we map the file as MAP_PRIVATE, the documentation
    of mmap does not specify what should happen if the file is changed after being
    mmap'd (https://man7.org/linux/man-pages/man2/mmap.2.html). It seems that
    these changes can propagate to the mmap'd memory region."""
    base_vm = microvm_factory.build(guest_kernel, rootfs)
    base_vm.spawn()
    base_vm.basic_config()
    base_vm.add_net_iface()
    base_vm.start()

    # Wait for microvm to be booted
    rc, _, stderr = base_vm.ssh.run("true")
    assert rc == 0, stderr

    snapshot = base_vm.snapshot_full()
    base_vm.kill()

    vm = microvm_factory.build()
    vm.spawn()
    vm.restore_from_snapshot(snapshot, resume=True)

    # When restoring a snapshot, vm.restore_from_snapshot first copies
    # the memory file (inside of the jailer) to /mem.src
    currently_loaded = Path(vm.chroot()) / "mem.src"

    assert currently_loaded.exists()

    vm.snapshot_full(mem_path="mem.src")
    vm.resume()

    # Check the overwriting the snapshot file from which this microvm was originally
    # restored, with a new snapshot of this vm, does not break the VM
    rc, _, stderr = vm.ssh.run("true")
    assert rc == 0, stderr
