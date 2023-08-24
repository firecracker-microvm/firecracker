# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /drives resources."""

# pylint:disable=redefined-outer-name

import os
from subprocess import check_output

import pytest

import host_tools.drive as drive_tools
from framework import utils

MB = 1024 * 1024


@pytest.fixture
def uvm_with_partuuid(uvm_plain, record_property, rootfs_ubuntu_22, tmp_path):
    """uvm_plain with a partuuid rootfs

    We build the disk image here so we don't need a separate artifact for it.
    """
    disk_img = tmp_path / "disk.img"
    initial_size = rootfs_ubuntu_22.stat().st_size + 50 * MB
    disk_img.touch()
    os.truncate(disk_img, initial_size)
    check_output(f"echo type=83 | sfdisk {str(disk_img)}", shell=True)
    stdout = check_output(
        f"losetup --find --partscan --show {str(disk_img)}", shell=True
    )
    loop_dev = stdout.decode("ascii").strip()
    check_output(f"dd if={str(rootfs_ubuntu_22)} of={loop_dev}p1", shell=True)

    # UUID=$(sudo blkid -s UUID -o value "${loop_dev}p1")
    stdout = check_output(f"blkid -s PARTUUID -o value {loop_dev}p1", shell=True)
    partuuid = stdout.decode("ascii").strip()

    # cleanup: release loop device
    check_output(f"losetup -d {loop_dev}", shell=True)

    record_property("rootfs", rootfs_ubuntu_22.name)
    uvm_plain.spawn()
    uvm_plain.rootfs_file = disk_img
    uvm_plain.ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    uvm_plain.partuuid = partuuid
    uvm_plain.basic_config(add_root_device=False)
    uvm_plain.add_net_iface()
    yield uvm_plain
    disk_img.unlink()


def test_rescan_file(test_microvm_with_api):
    """
    Verify that rescan works with a file-backed virtio device.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM and a root file system
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    block_size = 2
    # Add a scratch block device.
    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch"), size=block_size
    )
    test_microvm.add_drive("scratch", fs.path)

    test_microvm.start()

    _check_block_size(test_microvm.ssh, "/dev/vdb", fs.size())

    # Check if reading from the entire disk results in a file of the same size
    # or errors out, after a truncate on the host.
    truncated_size = block_size // 2
    utils.run_cmd(f"truncate --size {truncated_size}M {fs.path}")
    block_copy_name = "/tmp/dev_vdb_copy"
    _, _, stderr = test_microvm.ssh.run(
        f"dd if=/dev/vdb of={block_copy_name} bs=1M count={block_size}"
    )
    assert "dd: error reading '/dev/vdb': Input/output error" in stderr
    _check_file_size(test_microvm.ssh, f"{block_copy_name}", truncated_size * MB)

    test_microvm.api.drive.patch(
        drive_id="scratch",
        path_on_host=test_microvm.create_jailed_resource(fs.path),
    )

    _check_block_size(test_microvm.ssh, "/dev/vdb", fs.size())


def test_device_ordering(test_microvm_with_api):
    """
    Verify device ordering.

    The root device should correspond to /dev/vda in the guest and
    the order of the other devices should match their configuration order.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Add first scratch block device.
    fs1 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch1"), size=128
    )
    test_microvm.add_drive("scratch1", fs1.path)

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM and a root file system
    # (this is the second block device added).
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add the third block device.
    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch2"), size=512
    )
    test_microvm.add_drive("scratch2", fs2.path)

    test_microvm.start()

    # Determine the size of the microVM rootfs in bytes.
    rc, stdout, stderr = utils.run_cmd(
        "du --apparent-size --block-size=1 {}".format(test_microvm.rootfs_file),
    )
    assert rc == 0, f"Failed to get microVM rootfs size: {stderr}"

    assert len(stdout.split()) == 2
    rootfs_size = stdout.split("\t")[0]

    # The devices were added in this order: fs1, rootfs, fs2.
    # However, the rootfs is the root device and goes first,
    # so we expect to see this order: rootfs, fs1, fs2.
    # The devices are identified by their size.
    ssh_connection = test_microvm.ssh
    _check_block_size(ssh_connection, "/dev/vda", rootfs_size)
    _check_block_size(ssh_connection, "/dev/vdb", fs1.size())
    _check_block_size(ssh_connection, "/dev/vdc", fs2.size())


def test_rescan_dev(test_microvm_with_api):
    """
    Verify that rescan works with a device-backed virtio device.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM and a root file system
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a scratch block device.
    fs1 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "fs1"))
    test_microvm.add_drive("scratch", fs1.path)

    test_microvm.start()

    _check_block_size(test_microvm.ssh, "/dev/vdb", fs1.size())

    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "fs2"), size=512
    )

    losetup = ["losetup", "--find", "--show", fs2.path]
    rc, stdout, _ = utils.run_cmd(losetup)
    assert rc == 0
    loopback_device = stdout.rstrip()

    try:
        test_microvm.api.drive.patch(
            drive_id="scratch",
            path_on_host=test_microvm.create_jailed_resource(loopback_device),
        )

        _check_block_size(test_microvm.ssh, "/dev/vdb", fs2.size())
    finally:
        if loopback_device:
            utils.run_cmd(["losetup", "--detach", loopback_device])


def test_non_partuuid_boot(test_microvm_with_api):
    """
    Test the output reported by blockdev when booting from /dev/vda.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Sets up the microVM with 1 vCPUs, 256 MiB of RAM and a root file system
    test_microvm.basic_config(vcpu_count=1)
    test_microvm.add_net_iface()

    # Add another read-only block device.
    fs = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "readonly"))
    test_microvm.add_drive("scratch", fs.path, is_read_only=True)

    test_microvm.start()

    # Prepare the input for doing the assertion
    assert_dict = {}
    # Keep an array of strings specifying the location where some string
    # from the output is located.
    # 1-0 means line 1, column 0.
    keys_array = ["1-0", "1-6", "2-0"]
    # Keep a dictionary where the keys are the location and the values
    # represent the input to assert against.
    assert_dict[keys_array[0]] = "ro"
    assert_dict[keys_array[1]] = "/dev/vda"
    assert_dict[keys_array[2]] = "ro"
    _check_drives(test_microvm, assert_dict, keys_array)


def test_partuuid_boot(uvm_with_partuuid):
    """
    Test the output reported by blockdev when booting with PARTUUID.
    """
    test_microvm = uvm_with_partuuid
    # Add the root block device specified through PARTUUID.
    test_microvm.add_drive(
        "rootfs",
        test_microvm.rootfs_file,
        is_root_device=True,
        partuuid=test_microvm.partuuid,
    )
    test_microvm.start()

    assert_dict = {}
    keys_array = ["1-0", "1-6", "2-0", "2-6"]
    assert_dict[keys_array[0]] = "rw"
    assert_dict[keys_array[1]] = "/dev/vda"
    assert_dict[keys_array[2]] = "rw"
    assert_dict[keys_array[3]] = "/dev/vda1"
    _check_drives(test_microvm, assert_dict, keys_array)


def test_partuuid_update(test_microvm_with_api):
    """
    Test successful switching from PARTUUID boot to /dev/vda boot.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM
    test_microvm.basic_config(vcpu_count=1, add_root_device=False)
    test_microvm.add_net_iface()

    # Add the root block device specified through PARTUUID.
    test_microvm.add_drive(
        "rootfs", test_microvm.rootfs_file, is_root_device=True, partuuid="0eaa91a0-01"
    )

    # Update the root block device to boot from /dev/vda.
    test_microvm.add_drive(
        "rootfs",
        test_microvm.rootfs_file,
        is_root_device=True,
    )

    test_microvm.start()

    # Assert that the final booting method is from /dev/vda.
    assert_dict = {}
    keys_array = ["1-0", "1-6"]
    assert_dict[keys_array[0]] = "rw"
    assert_dict[keys_array[1]] = "/dev/vda"
    _check_drives(test_microvm, assert_dict, keys_array)


def test_patch_drive(test_microvm_with_api):
    """
    Test replacing the backing filesystem after guest boot works.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM and a root file system
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    fs1 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "scratch"))
    test_microvm.add_drive("scratch", fs1.path)

    test_microvm.start()

    # Updates to `path_on_host` with a valid path are allowed.
    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "otherscratch"), size=512
    )
    test_microvm.api.drive.patch(
        drive_id="scratch", path_on_host=test_microvm.create_jailed_resource(fs2.path)
    )

    # The `lsblk` command should output 2 lines to STDOUT: "SIZE" and the size
    # of the device, in bytes.
    blksize_cmd = "lsblk -b /dev/vdb --output SIZE"
    size_bytes_str = "536870912"  # = 512 MiB
    _, stdout, stderr = test_microvm.ssh.run(blksize_cmd)
    assert stderr == ""
    lines = stdout.split("\n")
    # skip "SIZE"
    assert lines[1].strip() == size_bytes_str


def test_no_flush(test_microvm_with_api):
    """
    Verify default block ignores flush.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    test_microvm.basic_config(vcpu_count=1, add_root_device=False)
    test_microvm.add_net_iface()

    # Add the block device
    test_microvm.add_drive(
        "rootfs",
        test_microvm.rootfs_file,
        is_root_device=True,
    )
    test_microvm.start()

    # Verify all flush commands were ignored during boot.
    fc_metrics = test_microvm.flush_metrics()
    assert fc_metrics["block"]["flush_count"] == 0

    # Have the guest drop the caches to generate flush requests.
    cmd = "sync; echo 1 > /proc/sys/vm/drop_caches"
    _, _, stderr = test_microvm.ssh.run(cmd)
    assert stderr == ""

    # Verify all flush commands were ignored even after
    # dropping the caches.
    fc_metrics = test_microvm.flush_metrics()
    assert fc_metrics["block"]["flush_count"] == 0


def test_flush(uvm_plain_rw):
    """
    Verify block with flush actually flushes.
    """
    test_microvm = uvm_plain_rw
    test_microvm.spawn()
    test_microvm.basic_config(vcpu_count=1, add_root_device=False)
    test_microvm.add_net_iface()

    # Add the block device with explicitly enabling flush.
    test_microvm.add_drive(
        "rootfs",
        test_microvm.rootfs_file,
        is_root_device=True,
        cache_type="Writeback",
    )
    test_microvm.start()

    # Have the guest drop the caches to generate flush requests.
    cmd = "sync; echo 1 > /proc/sys/vm/drop_caches"
    _, _, stderr = test_microvm.ssh.run(cmd)
    assert stderr == ""

    # On average, dropping the caches right after boot generates
    # about 6 block flush requests.
    fc_metrics = test_microvm.flush_metrics()
    assert fc_metrics["block"]["flush_count"] > 0


def test_block_default_cache_old_version(test_microvm_with_api):
    """
    Verify that saving a snapshot for old versions works correctly.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    test_microvm.basic_config(vcpu_count=1, add_root_device=False)

    # Add the block device with explicitly enabling flush.
    test_microvm.add_drive(
        "rootfs",
        test_microvm.rootfs_file,
        is_root_device=True,
        cache_type="Writeback",
    )

    test_microvm.start()

    # Pause the VM to create the snapshot.
    test_microvm.pause()

    # Create the snapshot for a version without block cache type.
    test_microvm.api.snapshot_create.put(
        mem_file_path="memfile",
        snapshot_path="snapsfile",
        snapshot_type="Full",
        version="0.24.0",
    )

    # We should find a warning in the logs for this case as this
    # cache type was not supported in 0.24.0 and we should default
    # to "Unsafe" mode.
    test_microvm.check_log_message(
        "Target version does not implement the"
        " current cache type. "
        'Defaulting to "unsafe" mode.'
    )


def _check_block_size(ssh_connection, dev_path, size):
    _, stdout, stderr = ssh_connection.run("blockdev --getsize64 {}".format(dev_path))
    assert stderr == ""
    assert stdout.strip() == str(size)


def _check_file_size(ssh_connection, dev_path, size):
    _, stdout, stderr = ssh_connection.run("stat --format=%s {}".format(dev_path))
    assert stderr == ""
    assert stdout.strip() == str(size)


def _process_blockdev_output(blockdev_out, assert_dict, keys_array):
    blockdev_out_lines = blockdev_out.splitlines()
    for key in keys_array:
        line = int(key.split("-")[0])
        col = int(key.split("-")[1])
        blockdev_out_line_cols = blockdev_out_lines[line].split()
        assert blockdev_out_line_cols[col] == assert_dict[key]


def _check_drives(test_microvm, assert_dict, keys_array):
    _, stdout, stderr = test_microvm.ssh.run("blockdev --report")
    assert stderr == ""
    _process_blockdev_output(stdout, assert_dict, keys_array)
