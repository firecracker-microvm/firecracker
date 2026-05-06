# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /drives resources."""

import os

import pytest

import host_tools.drive as drive_tools
from framework import utils
from framework.utils_drive import partuuid_and_disk_path

MB = 1024 * 1024


@pytest.fixture
def partuuid_and_disk_path_tmpfs(rootfs, tmp_path):
    """
    We create a new file in tmpfs, get its partuuid and use it as a rootfs.
    """
    disk_path = tmp_path / "disk.img"
    yield partuuid_and_disk_path(rootfs, disk_path)
    disk_path.unlink()


def test_rescan_file(uvm_plain_any, io_engine):
    """
    Verify that rescan works with a file-backed virtio device.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM and a root file system
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    block_size = 2
    # Add a scratch block device.
    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch"), size=block_size
    )
    test_microvm.add_drive("scratch", fs.path, io_engine=io_engine)

    test_microvm.start()

    _check_block_size(test_microvm.ssh, "/dev/vdb", fs.size())

    # Check if reading from the entire disk results in a file of the same size
    # or errors out, after a truncate on the host.
    truncated_size = block_size // 2
    utils.check_output(f"truncate --size {truncated_size}M {fs.path}")
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


def test_device_ordering(uvm_plain_any, io_engine):
    """
    Verify device ordering.

    The root device should correspond to /dev/vda in the guest and
    the order of the other devices should match their configuration order.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()

    # Add first scratch block device.
    fs1 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch1"), size=128
    )
    test_microvm.add_drive("scratch1", fs1.path, io_engine=io_engine)

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM and a root file system
    # (this is the second block device added).
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add the third block device.
    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch2"), size=512
    )
    test_microvm.add_drive("scratch2", fs2.path, io_engine=io_engine)

    test_microvm.start()

    # Determine the size of the microVM rootfs in bytes.
    _, stdout, _ = utils.check_output(
        "du --apparent-size --block-size=1 {}".format(test_microvm.rootfs_file),
    )

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


def test_rescan_dev(uvm_plain_any, io_engine):
    """
    Verify that rescan works with a device-backed virtio device.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM and a root file system
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a scratch block device.
    fs1 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "fs1"))
    test_microvm.add_drive("scratch", fs1.path, io_engine=io_engine)

    test_microvm.start()

    _check_block_size(test_microvm.ssh, "/dev/vdb", fs1.size())

    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "fs2"), size=512
    )

    losetup = ["losetup", "--find", "--show", fs2.path]
    rc, stdout, _ = utils.check_output(losetup)
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
            utils.check_output(["losetup", "--detach", loopback_device])


def test_non_partuuid_boot(uvm_plain_any, io_engine):
    """
    Test the output reported by blockdev when booting from /dev/vda.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()

    # Sets up the microVM with 1 vCPUs, 256 MiB of RAM and a root file system
    test_microvm.basic_config(vcpu_count=1)
    test_microvm.add_net_iface()

    # Add another read-only block device.
    fs = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "readonly"))
    test_microvm.add_drive("scratch", fs.path, is_read_only=True, io_engine=io_engine)

    test_microvm.start()

    # Keep a dictionary where the keys are the location and the values
    # represent the input to assert against.
    # 1, 0 means line 1, column 0.
    assert_dict = {
        (1, 0): "ro",
        (1, 6): "/dev/vda",
        (2, 0): "ro",
    }
    _check_drives(test_microvm, assert_dict, assert_dict.keys())


def test_partuuid_boot(uvm_plain_any, partuuid_and_disk_path_tmpfs, io_engine):
    """
    Test the output reported by blockdev when booting with PARTUUID.
    """

    partuuid = partuuid_and_disk_path_tmpfs[0]
    disk_path = partuuid_and_disk_path_tmpfs[1]

    test_microvm = uvm_plain_any
    test_microvm.spawn()

    # Sets up the microVM with 1 vCPUs, 256 MiB of RAM and without root file system
    test_microvm.basic_config(vcpu_count=1, add_root_device=False)
    test_microvm.add_net_iface()

    # Add the root block device specified through PARTUUID.
    test_microvm.add_drive(
        "rootfs",
        disk_path,
        is_root_device=True,
        partuuid=partuuid,
        io_engine=io_engine,
    )
    test_microvm.start()

    assert_dict = {
        (1, 0): "rw",
        (1, 6): "/dev/vda",
        (2, 0): "rw",
        (2, 6): "/dev/vda1",
    }
    _check_drives(test_microvm, assert_dict, assert_dict.keys())


def test_partuuid_update(uvm_plain_any, io_engine):
    """
    Test successful switching from PARTUUID boot to /dev/vda boot.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM
    test_microvm.basic_config(vcpu_count=1, add_root_device=False)
    test_microvm.add_net_iface()

    # Add the root block device specified through PARTUUID.
    test_microvm.add_drive(
        "rootfs",
        test_microvm.rootfs_file,
        is_root_device=True,
        partuuid="0eaa91a0-01",
        io_engine=io_engine,
    )

    # Update the root block device to boot from /dev/vda.
    test_microvm.add_drive(
        "rootfs",
        test_microvm.rootfs_file,
        is_root_device=True,
        io_engine=io_engine,
    )

    test_microvm.start()

    # Assert that the final booting method is from /dev/vda.
    assert_dict = {
        (1, 0): "rw",
        (1, 6): "/dev/vda",
    }
    _check_drives(test_microvm, assert_dict, assert_dict.keys())


def test_patch_drive(uvm_plain_any, io_engine):
    """
    Test replacing the backing filesystem after guest boot works.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM and a root file system
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    fs1 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "scratch"))
    test_microvm.add_drive("scratch", fs1.path, io_engine=io_engine)

    test_microvm.start()

    _check_mount(test_microvm.ssh, "/dev/vdb")

    # Updates to `path_on_host` with a valid path are allowed.
    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "otherscratch"), size=512
    )
    test_microvm.api.drive.patch(
        drive_id="scratch", path_on_host=test_microvm.create_jailed_resource(fs2.path)
    )

    _check_mount(test_microvm.ssh, "/dev/vdb")

    # The `lsblk` command should output 2 lines to STDOUT: "SIZE" and the size
    # of the device, in bytes.
    blksize_cmd = "LSBLK_DEBUG=all lsblk -b /dev/vdb --output SIZE"
    size_bytes_str = "536870912"  # = 512 MiB
    _, stdout, _ = test_microvm.ssh.check_output(blksize_cmd)
    lines = stdout.split("\n")
    # skip "SIZE"
    assert lines[1].strip() == size_bytes_str


def test_no_flush(uvm_plain_any, io_engine):
    """
    Verify default block ignores flush.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()

    test_microvm.basic_config(vcpu_count=1, add_root_device=False)
    test_microvm.add_net_iface()

    # Add the block device
    test_microvm.add_drive(
        "rootfs",
        test_microvm.rootfs_file,
        is_root_device=True,
        io_engine=io_engine,
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


def test_flush(uvm_plain_rw, io_engine):
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
        io_engine=io_engine,
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
    for line, col in keys_array:
        blockdev_out_line_cols = blockdev_out_lines[line].split()
        assert blockdev_out_line_cols[col] == assert_dict[line, col]


def _check_drives(test_microvm, assert_dict, keys_array):
    _, stdout, stderr = test_microvm.ssh.run("blockdev --report")
    assert stderr == ""
    _process_blockdev_output(stdout, assert_dict, keys_array)


def _check_mount(ssh_connection, dev_path):
    _, _, stderr = ssh_connection.run(f"mount {dev_path} /tmp", timeout=30.0)
    assert stderr == ""
    _, _, stderr = ssh_connection.run("umount /tmp", timeout=30.0)
    assert stderr == ""


def _mount_disk(ssh):
    ssh.check_output("mkdir -p /tmp/mnt")
    ssh.check_output("mount /dev/vdb /tmp/mnt")


def _fill_and_trim(ssh):
    ssh.check_output("dd if=/dev/zero of=/tmp/mnt/fill bs=1M count=64 conv=fsync")
    ssh.check_output("rm /tmp/mnt/fill && sync")
    _, stdout, _ = ssh.check_output("fstrim -v /tmp/mnt")
    assert "0 B" not in stdout, f"fstrim reported no bytes trimmed: {stdout}"


def test_discard(uvm_plain_any, microvm_factory, io_engine):
    """
    Verify VIRTIO_BLK_F_DISCARD on a fresh boot and after snapshot/restore.
    """
    vm = uvm_plain_any
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    fs = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "discard_test"), size=256)
    vm.add_drive("discard_disk", fs.path, is_read_only=False, io_engine=io_engine)
    vm.start()

    _mount_disk(vm.ssh)
    _fill_and_trim(vm.ssh)
    st = os.stat(fs.path)
    assert st.st_blocks * 512 < st.st_size, "backing file has no holes after trim"

    snapshot = vm.snapshot_full()
    vm = microvm_factory.build_from_snapshot(snapshot)
    # Disk is still mounted in the restored guest; write+trim again.
    _fill_and_trim(vm.ssh)
    st = os.stat(fs.path)
    assert st.st_blocks * 512 < st.st_size, "backing file has no holes after trim post-restore"

    metrics = vm.flush_metrics()
    assert metrics["block"]["discard_count"] > 0


def test_discard_not_advertised_for_read_only(uvm_plain_any, io_engine):
    """
    Verify VIRTIO_BLK_F_DISCARD is NOT advertised for read-only block devices.

    The kernel exposes discard support via /sys/block/<dev>/queue/discard_max_bytes.
    A value of 0 means the device does not support discard.
    """
    vm = uvm_plain_any
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()

    fs = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "ro_disk"), size=64)
    vm.add_drive("ro_disk", fs.path, is_read_only=True, io_engine=io_engine)
    vm.start()

    _, stdout, _ = vm.ssh.check_output("cat /sys/block/vdb/queue/discard_max_bytes")
    assert (
        stdout.strip() == "0"
    ), f"Expected discard_max_bytes=0 for read-only device, got: {stdout.strip()}"


def _exercise_write_zeroes(ssh):
    """Write random data, issue blkdiscard -z, verify zeros on /dev/vdb."""
    # Sysfs check: the kernel populates write_zeroes_max_bytes from the
    # negotiated feature; a non-zero value proves the feature is advertised.
    _, stdout, _ = ssh.check_output(
        "cat /sys/block/vdb/queue/write_zeroes_max_bytes"
    )
    assert int(stdout.strip()) > 0, (
        f"Expected non-zero write_zeroes_max_bytes, got: {stdout.strip()}"
    )
    # Write random non-zero data so we can tell zeroing apart from
    # "the device was already zero".
    ssh.check_output("dd if=/dev/urandom of=/dev/vdb bs=1M count=1 conv=fsync")
    ssh.check_output("sync && echo 3 > /proc/sys/vm/drop_caches")
    # Issue zero-out via blkdiscard -z (BLKZEROOUT ioctl).
    ssh.check_output("blkdiscard -z --offset 0 --length $((1024*1024)) /dev/vdb")
    ssh.check_output("sync && echo 3 > /proc/sys/vm/drop_caches")
    # Verify the range now reads as zeros.
    ssh.check_output("cmp -n 1048576 /dev/vdb /dev/zero")


def test_write_zeroes(uvm_plain_any, microvm_factory, io_engine):
    """
    Verify VIRTIO_BLK_F_WRITE_ZEROES on a fresh boot and after snapshot/restore.

    Writes random data to a 1 MiB region of /dev/vdb, then issues
    `blkdiscard -z` (BLKZEROOUT ioctl), and asserts that:
      - sysfs /queue/write_zeroes_max_bytes is non-zero (feature negotiated)
      - the region reads back as zeros after the operation
    The same workload is then run against a snapshot-restored VM, which
    catches `persist::restore()` populating the write-zeroes ConfigSpace
    fields wrong (the restored guest would otherwise see a zero
    write_zeroes_max_bytes and the workload would silently regress).

    Note: we deliberately do NOT assert that the `write_zeroes_count` metric
    increased. The Linux kernel's `blkdev_issue_zeroout()` may issue either
    `REQ_OP_WRITE_ZEROES` (counted) or fall back to plain zero-page writes
    (counted as `write_count`) depending on internal heuristics; both
    result in the device contents reading as zeros. Direct WRITE_ZEROES
    request handling is covered by the unit tests.
    """
    vm = uvm_plain_any
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    fs = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "wz_test"), size=64)
    vm.add_drive("wz_disk", fs.path, is_read_only=False, io_engine=io_engine)
    vm.start()

    _exercise_write_zeroes(vm.ssh)

    snapshot = vm.snapshot_full()
    vm = microvm_factory.build_from_snapshot(snapshot)
    _exercise_write_zeroes(vm.ssh)

    metrics = vm.flush_metrics()
    assert metrics["block"]["execute_fails"] == 0


def test_write_zeroes_not_advertised_for_read_only(uvm_plain_any, io_engine):
    """
    Verify VIRTIO_BLK_F_WRITE_ZEROES is NOT advertised for read-only devices.

    The kernel exposes the negotiated feature via
    /sys/block/<dev>/queue/write_zeroes_max_bytes; 0 means not supported.
    """
    vm = uvm_plain_any
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()

    fs = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "ro_wz_disk"), size=64)
    vm.add_drive("ro_wz_disk", fs.path, is_read_only=True, io_engine=io_engine)
    vm.start()

    _, stdout, _ = vm.ssh.check_output(
        "cat /sys/block/vdb/queue/write_zeroes_max_bytes"
    )
    assert stdout.strip() == "0", (
        f"Expected write_zeroes_max_bytes=0 for read-only device, got: {stdout.strip()}"
    )


