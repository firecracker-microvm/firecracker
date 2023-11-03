# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for vhost-user-block device."""

import os

import pytest

import host_tools.drive as drive_tools
from framework import utils
from framework.defs import LOCAL_BUILD_PATH
from framework.utils_drive import partuuid_and_disk_path, spawn_vhost_user_backend


@pytest.fixture
def partuuid_and_disk_path_host(rootfs_ubuntu_22):
    """
    We create a new file on the host, get its partuuid and use it as a rootfs.
    """
    disk_path = LOCAL_BUILD_PATH / "img" / "disk.img"
    yield partuuid_and_disk_path(rootfs_ubuntu_22, disk_path)
    disk_path.unlink()


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

    vhost_user_socket = "/vub.socket"

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # Converting path from tmpfs ("./srv/..") to local
    # path on the host ("../build/..")
    rootfs_path = utils.to_local_dir_path(str(rootfs_ubuntu_22))
    # Launching vhost-user-block backend
    _backend = spawn_vhost_user_backend(vm, rootfs_path, vhost_user_socket, True)

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_vhost_user_drive("rootfs", vhost_user_socket, is_root_device=True)
    vm.add_net_iface()
    vm.start()

    # Attempt to connect to the VM.
    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.run("ls")
    assert exit_code == 0

    # Now check that vhost-user-block with rw is last.
    # 1-0 means line 1, column 0.
    assert_dict = {
        "1-0": "ro",
        "1-6": "/dev/vda",
    }
    _check_drives(vm, assert_dict, assert_dict.keys())


def test_vhost_user_block_read_write(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """
    This test simply tries to boot a VM with
    vhost-user-block as a root device.
    This test configures vhost-user-block to be read write.
    """

    vhost_user_socket = "/vub.socket"

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # Converting path from tmpfs ("./srv/..") to local
    # path on the host ("../build/..")
    rootfs_path = utils.to_local_dir_path(str(rootfs_ubuntu_22))
    # Launching vhost-user-block backend
    _backend = spawn_vhost_user_backend(vm, rootfs_path, vhost_user_socket, False)

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_vhost_user_drive("rootfs", vhost_user_socket, is_root_device=True)
    vm.add_net_iface()
    vm.start()

    # Attempt to connect to the VM.
    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.run("ls")
    assert exit_code == 0

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

    vhost_user_socket = "/vub.socket"

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # Converting path from tmpfs ("./srv/..") to local
    # path on the host ("../build/..")
    rootfs_path = utils.to_local_dir_path(str(rootfs_ubuntu_22))
    # Launching vhost-user-block backend
    _backend = spawn_vhost_user_backend(vm, rootfs_path, vhost_user_socket, True)

    # We need to set up ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_vhost_user_drive("rootfs", vhost_user_socket, is_root_device=True)
    vm.add_net_iface()
    vm.start()

    # Attempt to connect to the VM.
    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.run("ls")
    assert exit_code == 0

    # Killing the backend
    _backend.kill()

    # Verify that Firecracker is still responsive
    _config = vm.api.vm_config.get().json()


def test_device_ordering(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """
    Verify device ordering.

    The root device should correspond to /dev/vda in the guest and
    the order of the other devices should match their configuration order.
    """

    vhost_user_socket_1 = "/vub_1.socket"
    vhost_user_socket_2 = "/vub_2.socket"

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # Converting path from tmpfs ("./srv/..") to local
    # path on the host ("../build/..")
    rootfs_path = utils.to_local_dir_path(str(rootfs_ubuntu_22))
    # Launching vhost-user-block backend
    _backend = spawn_vhost_user_backend(vm, rootfs_path, vhost_user_socket_1, True)

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
    vm.add_vhost_user_drive("rootfs", vhost_user_socket_1, is_root_device=True)

    # Adding third block device.
    fs2 = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "scratch2"), size=512)
    vm.add_drive("scratch2", fs2.path)

    # Launching vhost-user-block backend
    _backend2 = spawn_vhost_user_backend(vm, rootfs_path, vhost_user_socket_2, False)
    # Adding forth block device.
    vm.add_vhost_user_drive("dummy_rootfs", vhost_user_socket_2)

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


def test_partuuid_boot(
    microvm_factory,
    guest_kernel,
    rootfs_ubuntu_22,
    partuuid_and_disk_path_host,
):
    """
    Test the output reported by blockdev when booting with PARTUUID.
    """

    vhost_user_socket = "/vub.socket"

    partuuid = partuuid_and_disk_path_host[0]
    disk_path = partuuid_and_disk_path_host[1]

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # Launching vhost-user-block backend
    _backend = spawn_vhost_user_backend(vm, disk_path, vhost_user_socket, True)

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_vhost_user_drive(
        "1", vhost_user_socket, is_root_device=True, partuuid=partuuid
    )
    vm.add_net_iface()
    vm.start()

    # Attempt to connect to the VM.
    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.run("ls")
    assert exit_code == 0

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

    vhost_user_socket_1 = "/vub_1.socket"
    vhost_user_socket_2 = "/vub_2.socket"

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # Converting path from tmpfs ("./srv/..") to local
    # path on the host ("../build/..")
    rootfs_path = utils.to_local_dir_path(str(rootfs_ubuntu_22))
    # Launching vhost-user-block backend
    _backend = spawn_vhost_user_backend(vm, rootfs_path, vhost_user_socket_1, True)

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_net_iface()

    # Add the root block device specified through PARTUUID.
    vm.add_vhost_user_drive(
        "rootfs", vhost_user_socket_1, is_root_device=True, partuuid="0eaa91a0-01"
    )

    # We need to craete new backend with another socket because when we updated
    # vhost-user-block device, old connection is closed, and qemu backend will
    # stop after connection is closed.
    _backend = spawn_vhost_user_backend(vm, rootfs_path, vhost_user_socket_2, True)
    vm.add_vhost_user_drive("rootfs", vhost_user_socket_2, is_root_device=True)

    vm.start()

    # Attempt to connect to the VM.
    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.run("ls")
    assert exit_code == 0

    # Now check that vhost-user-block with rw is last.
    # 1-0 means line 1, column 0.
    assert_dict = {
        "1-0": "ro",
        "1-6": "/dev/vda",
    }
    _check_drives(vm, assert_dict, assert_dict.keys())
