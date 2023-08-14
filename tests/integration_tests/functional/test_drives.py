# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /drives resources."""

# pylint:disable=redefined-outer-name

import os
from subprocess import check_output

import pytest

import host_tools.drive as drive_tools
import host_tools.logging as log_tools
from framework import utils

MB = 1024 * 1024


@pytest.fixture
def uvm_with_partuuid(uvm_plain, record_property, rootfs_ubuntu_22, tmp_path):
    """uvm_plain with a partuuid rootfs

    We build the disk image here so we don't need a separate artifact for it.
    """
    disk_img = tmp_path / "disk.img"
    initial_size = rootfs_ubuntu_22.stat().st_size + 50 * 2**20
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
    _, _, stderr = test_microvm.ssh.execute_command(
        f"dd if=/dev/vdb of={block_copy_name} bs=1M count={block_size}"
    )
    assert "dd: error reading '/dev/vdb': Input/output error" in stderr
    _check_file_size(test_microvm.ssh, f"{block_copy_name}", truncated_size * MB)

    response = test_microvm.drive.patch(
        drive_id="scratch",
        path_on_host=test_microvm.create_jailed_resource(fs.path),
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

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
    session = test_microvm.api_session

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
        response = test_microvm.drive.patch(
            drive_id="scratch",
            path_on_host=test_microvm.create_jailed_resource(loopback_device),
        )
        assert session.is_status_no_content(response.status_code), response.content

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
    response = test_microvm.drive.patch(
        drive_id="scratch", path_on_host=test_microvm.create_jailed_resource(fs2.path)
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # The `lsblk` command should output 2 lines to STDOUT: "SIZE" and the size
    # of the device, in bytes.
    blksize_cmd = "lsblk -b /dev/vdb --output SIZE"
    size_bytes_str = "536870912"  # = 512 MiB
    _, stdout, stderr = test_microvm.ssh.execute_command(blksize_cmd)
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

    # Configure the metrics.
    metrics_fifo_path = os.path.join(test_microvm.path, "metrics_fifo")
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = test_microvm.metrics.put(
        metrics_path=test_microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    # Verify all flush commands were ignored during boot.
    fc_metrics = test_microvm.flush_metrics(metrics_fifo)
    assert fc_metrics["block"]["flush_count"] == 0

    # Have the guest drop the caches to generate flush requests.
    cmd = "sync; echo 1 > /proc/sys/vm/drop_caches"
    _, _, stderr = test_microvm.ssh.execute_command(cmd)
    assert stderr == ""

    # Verify all flush commands were ignored even after
    # dropping the caches.
    fc_metrics = test_microvm.flush_metrics(metrics_fifo)
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

    # Configure metrics, to get later the `flush_count`.
    metrics_fifo_path = os.path.join(test_microvm.path, "metrics_fifo")
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = test_microvm.metrics.put(
        metrics_path=test_microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    # Have the guest drop the caches to generate flush requests.
    cmd = "sync; echo 1 > /proc/sys/vm/drop_caches"
    _, _, stderr = test_microvm.ssh.execute_command(cmd)
    assert stderr == ""

    # On average, dropping the caches right after boot generates
    # about 6 block flush requests.
    fc_metrics = test_microvm.flush_metrics(metrics_fifo)
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
    response = test_microvm.snapshot.create(
        mem_file_path="memfile", snapshot_path="snapsfile", diff=False, version="0.24.0"
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # We should find a warning in the logs for this case as this
    # cache type was not supported in 0.24.0 and we should default
    # to "Unsafe" mode.
    test_microvm.check_log_message(
        "Target version does not implement the"
        " current cache type. "
        'Defaulting to "unsafe" mode.'
    )


def check_iops_limit(ssh_connection, block_size, count, min_time, max_time):
    """Verify if the rate limiter throttles block iops using dd."""
    obs = block_size
    byte_count = block_size * count
    dd = "dd if=/dev/zero of=/dev/vdb ibs={} obs={} count={} oflag=direct".format(
        block_size, obs, count
    )
    print("Running cmd {}".format(dd))
    # Check write iops (writing with oflag=direct is more reliable).
    exit_code, _, stderr = ssh_connection.execute_command(dd)
    assert exit_code == 0

    # "dd" writes to stderr by design. We drop first lines
    lines = stderr.split("\n")
    dd_result = lines[2].strip()

    # Interesting output looks like this:
    # 4194304 bytes (4.2 MB, 4.0 MiB) copied, 0.0528524 s, 79.4 MB/s
    tokens = dd_result.split()

    # Check total read bytes.
    assert int(tokens[0]) == byte_count
    # Check duration.
    assert float(tokens[7]) > min_time
    assert float(tokens[7]) < max_time


def test_patch_drive_limiter(test_microvm_with_api):
    """
    Test replacing the drive rate-limiter after guest boot works.
    """
    test_microvm = test_microvm_with_api
    test_microvm.jailer.daemonize = False
    test_microvm.spawn()
    # Set up the microVM with 2 vCPUs, 512 MiB of RAM, 1 network iface, a root
    # file system, and a scratch drive.
    test_microvm.basic_config(
        vcpu_count=2, mem_size_mib=512, boot_args="console=ttyS0 reboot=k panic=1"
    )
    test_microvm.add_net_iface()

    fs1 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch"), size=512
    )
    response = test_microvm.drive.put(
        drive_id="scratch",
        path_on_host=test_microvm.create_jailed_resource(fs1.path),
        is_root_device=False,
        is_read_only=False,
        rate_limiter={
            "bandwidth": {"size": 10 * MB, "refill_time": 100},
            "ops": {"size": 100, "refill_time": 100},
        },
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    test_microvm.start()

    # Validate IOPS stays within above configured limits.
    # For example, the below call will validate that reading 1000 blocks
    # of 512b will complete in at 0.8-1.2 seconds ('dd' is not very accurate,
    # so we target to stay within 30% error).
    check_iops_limit(test_microvm.ssh, 512, 1000, 0.7, 1.3)
    check_iops_limit(test_microvm.ssh, 4096, 1000, 0.7, 1.3)

    # Patch ratelimiter
    response = test_microvm.drive.patch(
        drive_id="scratch",
        rate_limiter={
            "bandwidth": {"size": 100 * MB, "refill_time": 100},
            "ops": {"size": 200, "refill_time": 100},
        },
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    check_iops_limit(test_microvm.ssh, 512, 2000, 0.7, 1.3)
    check_iops_limit(test_microvm.ssh, 4096, 2000, 0.7, 1.3)

    # Patch ratelimiter
    response = test_microvm.drive.patch(
        drive_id="scratch", rate_limiter={"ops": {"size": 1000, "refill_time": 100}}
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    check_iops_limit(test_microvm.ssh, 512, 10000, 0.7, 1.3)
    check_iops_limit(test_microvm.ssh, 4096, 10000, 0.7, 1.3)


def _check_block_size(ssh_connection, dev_path, size):
    _, stdout, stderr = ssh_connection.execute_command(
        "blockdev --getsize64 {}".format(dev_path)
    )
    assert stderr == ""
    assert stdout.strip() == str(size)


def _check_file_size(ssh_connection, dev_path, size):
    _, stdout, stderr = ssh_connection.execute_command(
        "stat --format=%s {}".format(dev_path)
    )
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
    _, stdout, stderr = test_microvm.ssh.execute_command("blockdev --report")
    assert stderr == ""
    _process_blockdev_output(stdout, assert_dict, keys_array)
