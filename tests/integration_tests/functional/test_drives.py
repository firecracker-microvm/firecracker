# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /drives resources."""

import os

import host_tools.drive as drive_tools
import host_tools.network as net_tools  # pylint: disable=import-error


def test_rescan(test_microvm_with_ssh, network_config):
    """Verify that a block device rescan has guest seeing changes."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    # a root file system with the rw permission. The network interface is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config()

    _tap, _, _ = test_microvm_with_ssh.ssh_network_config(network_config, '1')

    # Add a scratch block device.
    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'scratch')
    )
    response = test_microvm.drive.put(
        drive_id='scratch',
        path_on_host=test_microvm.create_jailed_resource(fs.path),
        is_root_device=False,
        is_read_only=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    _check_scratch_size(ssh_connection, fs.size())

    # Resize the filesystem from 256 MiB (default) to 512 MiB.
    fs.resize(512)

    # Rescan operations after the guest boots are allowed.
    response = test_microvm.actions.put(
        action_type='BlockDeviceRescan',
        payload='scratch'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    _check_scratch_size(
        ssh_connection,
        fs.size()
    )


def test_non_partuuid_boot(test_microvm_with_ssh, network_config):
    """Test the output reported by blockdev when booting from /dev/vda."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # Sets up the microVM with 1 vCPUs, 256 MiB of RAM, no network ifaces and
    # a root file system with the rw permission. The network interfaces is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config(vcpu_count=1)

    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')

    # Add another read-only block device.
    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'readonly')
    )
    response = test_microvm.drive.put(
        drive_id='readonly',
        path_on_host=test_microvm.create_jailed_resource(fs.path),
        is_root_device=False,
        is_read_only=True
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    # Prepare the input for doing the assertion
    assert_dict = {}
    # Keep an array of strings specifying the location where some string
    # from the output is located.
    # 1-0 means line 1, column 0.
    keys_array = ['1-0', '1-8', '2-0']
    # Keep a dictionary where the keys are the location and the values
    # represent the input to assert against.
    assert_dict[keys_array[0]] = 'rw'
    assert_dict[keys_array[1]] = '/dev/vda'
    assert_dict[keys_array[2]] = 'ro'
    _check_drives(test_microvm, assert_dict, keys_array)


def test_partuuid_boot(test_microvm_with_partuuid, network_config):
    """Test the output reported by blockdev when booting with PARTUUID."""
    test_microvm = test_microvm_with_partuuid
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, no network ifaces and
    # a root file system with the rw permission. The network interfaces is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config(
        vcpu_count=1,
        add_root_device=False
    )

    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')

    # Add the root block device specified through PARTUUID.
    response = test_microvm.drive.put(
        drive_id='rootfs',
        path_on_host=test_microvm.create_jailed_resource(
            test_microvm.rootfs_file
        ),
        is_root_device=True,
        is_read_only=False,
        partuuid='0eaa91a0-01'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    assert_dict = {}
    keys_array = ['1-0', '1-8', '2-0', '2-7']
    assert_dict[keys_array[0]] = "rw"
    assert_dict[keys_array[1]] = '/dev/vda'
    assert_dict[keys_array[2]] = 'rw'
    assert_dict[keys_array[3]] = '/dev/vda1'
    _check_drives(test_microvm, assert_dict, keys_array)


def test_partuuid_update(test_microvm_with_ssh, network_config):
    """Test successful switching from PARTUUID boot to /dev/vda boot."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    # a root file system with the rw permission. The network interfaces is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config(
        vcpu_count=1,
        add_root_device=False
    )

    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')

    # Add the root block device specified through PARTUUID.
    response = test_microvm.drive.put(
        drive_id='rootfs',
        path_on_host=test_microvm.create_jailed_resource(
            test_microvm.rootfs_file
        ),
        is_root_device=True,
        is_read_only=False,
        partuuid='0eaa91a0-01'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Update the root block device to boot from /dev/vda.
    response = test_microvm.drive.put(
        drive_id='rootfs',
        path_on_host=test_microvm.create_jailed_resource(
            test_microvm.rootfs_file
        ),
        is_root_device=True,
        is_read_only=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    # Assert that the final booting method is from /dev/vda.
    assert_dict = {}
    keys_array = ['1-0', '1-8']
    assert_dict[keys_array[0]] = 'rw'
    assert_dict[keys_array[1]] = '/dev/vda'
    _check_drives(test_microvm, assert_dict, keys_array)


def test_patch_drive(test_microvm_with_ssh, network_config):
    """Test replacing the backing filesystem after guest boot works."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, 1 network iface, a root
    # file system with the rw permission, and a scratch drive.
    test_microvm.basic_config()

    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')

    fs1 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'scratch')
    )
    response = test_microvm.drive.put(
        drive_id='scratch',
        path_on_host=test_microvm.create_jailed_resource(fs1.path),
        is_root_device=False,
        is_read_only=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    # Updates to `path_on_host` with a valid path are allowed.
    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'otherscratch'), size=512
    )
    response = test_microvm.drive.patch(
        drive_id='scratch',
        path_on_host=test_microvm.create_jailed_resource(fs2.path)
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # The `lsblk` command should output 2 lines to STDOUT: "SIZE" and the size
    # of the device, in bytes.
    blksize_cmd = "lsblk -b /dev/vdb --output SIZE"
    size_bytes_str = "536870912"  # = 512 MiB
    _, stdout, stderr = ssh_connection.execute_command(blksize_cmd)
    assert stderr.read().decode("utf-8") == ''
    stdout.readline()  # skip "SIZE"
    assert stdout.readline().decode('utf-8').strip() == size_bytes_str


def _check_scratch_size(ssh_connection, size):
    # The scratch block device is /dev/vdb in the guest.
    _, stdout, stderr = ssh_connection.execute_command(
        'blockdev --getsize64 /dev/vdb'
    )

    assert stderr.read().decode('utf-8') == ''
    assert stdout.readline().decode('utf-8').strip() == str(size)


def _process_blockdev_output(blockdev_out, assert_dict, keys_array):
    blockdev_out_lines = blockdev_out.splitlines()

    for key in keys_array:
        line = int(key.split('-')[0])
        col = int(key.split('-')[1])
        blockdev_out_line = blockdev_out_lines[line]
        assert blockdev_out_line.split("   ")[col] == assert_dict[key]


def _check_drives(test_microvm, assert_dict, keys_array):
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    _, stdout, stderr = ssh_connection.execute_command('blockdev --report')
    assert stderr.read().decode('utf-8') == ''
    _process_blockdev_output(
        stdout.read().decode('utf-8'),
        assert_dict,
        keys_array)
