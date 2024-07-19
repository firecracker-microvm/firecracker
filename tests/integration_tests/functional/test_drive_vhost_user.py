# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for vhost-user-block device."""

import os
import shutil
from pathlib import Path

import host_tools.drive as drive_tools
from framework.utils_drive import partuuid_and_disk_path
from host_tools.fcmetrics import FcDeviceMetrics


def _check_block_size(ssh_connection, dev_path, size):
    """
    Checks the size of the block device.
    """
    _, stdout, stderr = ssh_connection.run("blockdev --getsize64 {}".format(dev_path))
    assert stderr == ""
    assert stdout.strip() == str(size)


def _check_drives(test_microvm, assert_dict, keys_array):
    """
    Checks the info on the block devices.
    """
    _, stdout, stderr = test_microvm.ssh.run("blockdev --report")
    assert stderr == ""
    blockdev_out_lines = stdout.splitlines()
    for key in keys_array:
        line = int(key.split("-")[0])
        col = int(key.split("-")[1])
        blockdev_out_line_cols = blockdev_out_lines[line].split()
        assert blockdev_out_line_cols[col] == assert_dict[key]


def test_vhost_user_block(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """
    This test simply tries to boot a VM with
    vhost-user-block as a root device.
    """

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_vhost_user_drive(
        "rootfs", rootfs_ubuntu_22, is_root_device=True, is_read_only=True
    )
    vm.add_net_iface()
    vhost_user_block_metrics = FcDeviceMetrics(
        "vhost_user_block", 1, aggr_supported=False
    )
    vm.start()
    vm.wait_for_up()

    # Now check that vhost-user-block with rw is last.
    # 1-0 means line 1, column 0.
    assert_dict = {
        "1-0": "ro",
        "1-6": "/dev/vda",
    }
    _check_drives(vm, assert_dict, assert_dict.keys())
    vhost_user_block_metrics.validate(vm)


def test_vhost_user_block_read_write(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """
    This test simply tries to boot a VM with
    vhost-user-block as a root device.
    This test configures vhost-user-block to be read write.
    """

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)

    # Create a rw rootfs file that is unique to the microVM
    rootfs_rw = Path(vm.chroot()) / "rootfs"
    shutil.copy(rootfs_ubuntu_22, rootfs_rw)

    vm.add_vhost_user_drive("rootfs", rootfs_rw, is_root_device=True)
    vm.add_net_iface()
    vm.start()
    vm.wait_for_up()

    # Now check that vhost-user-block with rw is last.
    # 1-0 means line 1, column 0.
    assert_dict = {
        "1-0": "rw",
        "1-6": "/dev/vda",
    }
    _check_drives(vm, assert_dict, assert_dict.keys())


def test_vhost_user_block_disconnect(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """
    Test that even if backend is killed, Firecracker is still responsive.
    """

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # We need to set up ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_vhost_user_drive(
        "rootfs", rootfs_ubuntu_22, is_root_device=True, is_read_only=True
    )
    vm.add_net_iface()
    vm.start()
    vm.wait_for_up()

    # Killing the backend
    vm.disks_vhost_user["rootfs"].kill()
    del vm.disks_vhost_user["rootfs"]

    # Verify that Firecracker is still responsive
    _config = vm.api.vm_config.get().json()


def test_device_ordering(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """
    Verify device ordering.

    The root device should correspond to /dev/vda in the guest and
    the order of the other devices should match their configuration order.
    """

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_net_iface()

    # Adding first block device.
    fs1 = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "scratch1"), size=128)
    vm.add_drive("scratch1", fs1.path)

    # Adding second block device (rootfs)
    vm.add_vhost_user_drive(
        "rootfs", rootfs_ubuntu_22, is_root_device=True, is_read_only=True
    )

    # Adding third block device.
    fs2 = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "scratch2"), size=512)
    vm.add_drive("scratch2", fs2.path)

    # Create a rw rootfs file that is unique to the microVM
    rootfs_rw = Path(vm.chroot()) / "rootfs"
    shutil.copy(rootfs_ubuntu_22, rootfs_rw)

    # Adding forth block device.
    vm.add_vhost_user_drive("dummy_rootfs", rootfs_rw)

    block_metrics = FcDeviceMetrics("block", 2, aggr_supported=True)
    vhost_user_block_metrics = FcDeviceMetrics(
        "vhost_user_block", 2, aggr_supported=False
    )
    vm.start()

    rootfs_size = rootfs_ubuntu_22.stat().st_size

    # The devices were added in this order: fs1, rootfs, fs2. fs3
    # However, the rootfs is the root device and goes first,
    # so we expect to see this order: rootfs, fs1, fs2. fs3
    # First check drives order by sizes.
    ssh_connection = vm.ssh
    _check_block_size(ssh_connection, "/dev/vda", rootfs_size)
    _check_block_size(ssh_connection, "/dev/vdb", fs1.size())
    _check_block_size(ssh_connection, "/dev/vdc", fs2.size())
    _check_block_size(ssh_connection, "/dev/vdd", rootfs_size)

    # Now check that vhost-user-block with rw is last.
    # 1-0 means line 1, column 0.
    assert_dict = {
        "1-0": "ro",
        "1-6": "/dev/vda",
        "2-0": "rw",
        "2-6": "/dev/vdb",
        "3-0": "rw",
        "3-6": "/dev/vdc",
        "4-0": "rw",
        "4-6": "/dev/vdd",
    }
    _check_drives(vm, assert_dict, assert_dict.keys())
    block_metrics.validate(vm)
    vhost_user_block_metrics.validate(vm)


def test_partuuid_boot(
    microvm_factory,
    guest_kernel,
    rootfs_ubuntu_22,
):
    """
    Test the output reported by blockdev when booting with PARTUUID.
    """

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)

    # Create a rootfs with partuuid unique to this microVM
    partuuid, disk_path = partuuid_and_disk_path(
        rootfs_ubuntu_22, Path(vm.chroot()) / "disk.img"
    )

    vm.add_vhost_user_drive(
        "1", disk_path, is_root_device=True, partuuid=partuuid, is_read_only=True
    )
    vm.add_net_iface()
    vm.start()
    vm.wait_for_up()

    # Now check that vhost-user-block with rw is last.
    # 1-0 means line 1, column 0.
    assert_dict = {
        "1-0": "ro",
        "1-6": "/dev/vda",
    }
    _check_drives(vm, assert_dict, assert_dict.keys())


def test_partuuid_update(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """
    Test successful switching from PARTUUID boot to /dev/vda boot.
    """

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_net_iface()

    # Add the root block device specified through PARTUUID.
    vm.add_vhost_user_drive(
        "rootfs",
        rootfs_ubuntu_22,
        is_root_device=True,
        partuuid="0eaa91a0-01",
        is_read_only=True,
    )

    # Adding a drive with the same ID creates another backend with another socket.
    vm.add_vhost_user_drive(
        "rootfs", rootfs_ubuntu_22, is_root_device=True, is_read_only=True
    )

    vhost_user_block_metrics = FcDeviceMetrics(
        "vhost_user_block", 1, aggr_supported=False
    )
    vm.start()
    vm.wait_for_up()

    # Now check that vhost-user-block with rw is last.
    # 1-0 means line 1, column 0.
    assert_dict = {
        "1-0": "ro",
        "1-6": "/dev/vda",
    }
    _check_drives(vm, assert_dict, assert_dict.keys())
    vhost_user_block_metrics.validate(vm)


def test_config_change(microvm_factory, guest_kernel, rootfs):
    """
    Verify handling of block device resize.
    We expect that the guest will start reporting the updated size
    after Firecracker handles a PATCH request to the vhost-user block device.
    """

    orig_size = 10  # MB
    new_sizes = [20, 10, 30]  # MB
    mkfs_mount_cmd = "mkfs.ext4 /dev/vdb && mkdir -p /tmp/tmp && mount /dev/vdb /tmp/tmp && umount /tmp/tmp"

    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.basic_config()
    vm.add_net_iface()

    # Add a block device to test resizing.
    fs = drive_tools.FilesystemFile(size=orig_size)
    vm.add_vhost_user_drive("scratch", fs.path)
    vm.start()

    # Check that guest reports correct original size.
    _check_block_size(vm.ssh, "/dev/vdb", orig_size * 1024 * 1024)

    # Check that we can create a filesystem and mount it
    vm.ssh.check_output(mkfs_mount_cmd)

    for new_size in new_sizes:
        # Instruct the backend to resize the device.
        # It will both resize the file and update its device config.
        vm.disks_vhost_user["scratch"].resize(new_size)

        # Instruct Firecracker to reread device config and notify
        # the guest of a config change.
        vm.patch_drive("scratch")

        # Check that guest reports correct new size.
        _check_block_size(vm.ssh, "/dev/vdb", new_size * 1024 * 1024)

        # Check that we can create a filesystem and mount it
        vm.ssh.check_output(mkfs_mount_cmd)
