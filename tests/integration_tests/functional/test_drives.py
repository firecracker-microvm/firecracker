# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /drives resources."""

import os
import platform
import pytest

import framework.utils as utils

import host_tools.drive as drive_tools
import host_tools.network as net_tools  # pylint: disable=import-error


def test_rescan_file(test_microvm_with_ssh, network_config):
    """Verify that rescan works with a file-backed virtio device."""
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
    test_microvm.add_drive(
        'scratch',
        fs.path,
    )

    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    _check_block_size(ssh_connection, '/dev/vdb', fs.size())

    # Resize the filesystem from 256 MiB (default) to 512 MiB.
    fs.resize(512)

    response = test_microvm.drive.patch(
        drive_id='scratch',
        path_on_host=test_microvm.create_jailed_resource(fs.path),
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    _check_block_size(
        ssh_connection,
        '/dev/vdb',
        fs.size()
    )


def test_device_ordering(test_microvm_with_ssh, network_config):
    """Verify device ordering.

    The root device should correspond to /dev/vda in the guest and
    the order of the other devices should match their configuration order.
    """
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # Add first scratch block device.
    fs1 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'scratch1'),
        size=128
    )
    test_microvm.add_drive(
        'scratch1',
        fs1.path
    )

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces,
    # a read-write root file system (this is the second block device added).
    # The network interface is added after we get a unique MAC and IP.
    test_microvm.basic_config()

    # Add the third block device.
    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'scratch2'),
        size=512
    )
    test_microvm.add_drive(
        'scratch2',
        fs2.path
    )

    _tap, _, _ = test_microvm_with_ssh.ssh_network_config(network_config, '1')

    test_microvm.start()

    # Determine the size of the microVM rootfs in bytes.
    try:
        result = utils.run_cmd(
            'du --apparent-size --block-size=1 {}'
            .format(test_microvm.rootfs_file),
        )
    except ChildProcessError:
        pytest.skip('Failed to get microVM rootfs size: {}'
                    .format(result.stderr))

    assert len(result.stdout.split()) == 2
    rootfs_size = result.stdout.split('\t')[0]

    # The devices were added in this order: fs1, rootfs, fs2.
    # However, the rootfs is the root device and goes first,
    # so we expect to see this order: rootfs, fs1, fs2.
    # The devices are identified by their size.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    _check_block_size(ssh_connection, '/dev/vda', rootfs_size)
    _check_block_size(ssh_connection, '/dev/vdb', fs1.size())
    _check_block_size(ssh_connection, '/dev/vdc', fs2.size())


def test_rescan_dev(test_microvm_with_ssh, network_config):
    """Verify that rescan works with a device-backed virtio device."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()
    session = test_microvm.api_session

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    # a root file system with the rw permission. The network interface is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config()

    _tap, _, _ = test_microvm_with_ssh.ssh_network_config(network_config, '1')

    # Add a scratch block device.
    fs1 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, 'fs1'))
    test_microvm.add_drive(
        'scratch',
        fs1.path
    )

    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    _check_block_size(ssh_connection, '/dev/vdb', fs1.size())

    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'fs2'),
        size=512
    )

    losetup = ['losetup', '--find', '--show', fs2.path]
    loopback_device = None
    result = None
    try:
        result = utils.run_cmd(losetup)
        loopback_device = result.stdout.rstrip()
    except ChildProcessError:
        pytest.skip('failed to create a lookback device: ' +
                    f'stdout={result.stdout}, stderr={result.stderr}')

    try:
        response = test_microvm.drive.patch(
            drive_id='scratch',
            path_on_host=test_microvm.create_jailed_resource(loopback_device),
        )
        assert session.is_status_no_content(response.status_code)

        _check_block_size(ssh_connection, '/dev/vdb', fs2.size())
    finally:
        if loopback_device:
            utils.run_cmd(['losetup', '--detach', loopback_device])


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
    test_microvm.add_drive(
        'scratch',
        fs.path,
        is_read_only=True
    )

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


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="need to create the proper rootfs for arm"
)
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
    test_microvm.add_drive(
        'rootfs',
        test_microvm.rootfs_file,
        root_device=True,
        partuuid='0eaa91a0-01'
    )

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
    test_microvm.add_drive(
        'rootfs',
        test_microvm.rootfs_file,
        root_device=True,
        partuuid='0eaa91a0-01'
    )

    # Update the root block device to boot from /dev/vda.
    test_microvm.add_drive(
        'rootfs',
        test_microvm.rootfs_file,
        root_device=True,
    )

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
    test_microvm.add_drive(
        'scratch',
        fs1.path
    )

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
    assert stderr.read() == ''
    stdout.readline()  # skip "SIZE"
    assert stdout.readline().strip() == size_bytes_str


def _check_block_size(ssh_connection, dev_path, size):
    _, stdout, stderr = ssh_connection.execute_command(
        'blockdev --getsize64 {}'.format(dev_path)
    )

    assert stderr.read() == ''
    assert stdout.readline().strip() == str(size)


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
    assert stderr.read() == ''
    _process_blockdev_output(
        stdout.read(),
        assert_dict,
        keys_array)
