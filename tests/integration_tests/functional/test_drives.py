# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /drives resources."""

import os
import platform

from framework import utils

import host_tools.drive as drive_tools
import host_tools.network as net_tools  # pylint: disable=import-error
import host_tools.logging as log_tools

PARTUUID = {"x86_64": "f647d602-01", "aarch64": "69d7c052-01"}
MB = 1024 * 1024


def test_rescan_file(test_microvm_with_api, network_config):
    """
    Verify that rescan works with a file-backed virtio device.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    # a root file system with the rw permission. The network interface is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config()

    _tap, _, _ = test_microvm_with_api.ssh_network_config(network_config, '1')

    block_size = 2
    # Add a scratch block device.
    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'scratch'),
        size=block_size
    )
    test_microvm.add_drive(
        'scratch',
        fs.path,
    )

    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    _check_block_size(ssh_connection, '/dev/vdb', fs.size())

    # Check if reading from the entire disk results in a file of the same size
    # or errors out, after a truncate on the host.
    truncated_size = block_size//2
    utils.run_cmd(f"truncate --size {truncated_size}M {fs.path}")
    block_copy_name = "dev_vdb_copy"
    _, _, stderr = ssh_connection.execute_command(
        f"dd if=/dev/vdb of={block_copy_name} bs=1M count={block_size}")
    assert "dd: error reading '/dev/vdb': Input/output error" in stderr.read()
    _check_file_size(ssh_connection, f'{block_copy_name}',
                     truncated_size * MB)

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


def test_device_ordering(test_microvm_with_api, network_config):
    """
    Verify device ordering.

    The root device should correspond to /dev/vda in the guest and
    the order of the other devices should match their configuration order.

    @type: functional
    """
    test_microvm = test_microvm_with_api
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

    _tap, _, _ = test_microvm_with_api.ssh_network_config(network_config, '1')

    test_microvm.start()

    # Determine the size of the microVM rootfs in bytes.
    rc, stdout, stderr = utils.run_cmd(
        'du --apparent-size --block-size=1 {}'
        .format(test_microvm.rootfs_file),
    )
    assert rc == 0, f"Failed to get microVM rootfs size: {stderr}"

    assert len(stdout.split()) == 2
    rootfs_size = stdout.split('\t')[0]

    # The devices were added in this order: fs1, rootfs, fs2.
    # However, the rootfs is the root device and goes first,
    # so we expect to see this order: rootfs, fs1, fs2.
    # The devices are identified by their size.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    _check_block_size(ssh_connection, '/dev/vda', rootfs_size)
    _check_block_size(ssh_connection, '/dev/vdb', fs1.size())
    _check_block_size(ssh_connection, '/dev/vdc', fs2.size())


def test_rescan_dev(test_microvm_with_api, network_config):
    """
    Verify that rescan works with a device-backed virtio device.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    session = test_microvm.api_session

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    # a root file system with the rw permission. The network interface is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config()

    _tap, _, _ = test_microvm_with_api.ssh_network_config(network_config, '1')

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
    rc, stdout, _ = utils.run_cmd(losetup)
    assert rc == 0
    loopback_device = stdout.rstrip()

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


def test_non_partuuid_boot(test_microvm_with_api, network_config):
    """
    Test the output reported by blockdev when booting from /dev/vda.

    @type: functional
    """
    test_microvm = test_microvm_with_api
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


def test_partuuid_boot(test_microvm_with_partuuid, network_config):
    """
    Test the output reported by blockdev when booting with PARTUUID.

    @type: functional
    """
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
        partuuid=PARTUUID[platform.machine()]
    )

    test_microvm.start()

    assert_dict = {}
    keys_array = ['1-0', '1-8', '2-0', '2-7']
    assert_dict[keys_array[0]] = "rw"
    assert_dict[keys_array[1]] = '/dev/vda'
    assert_dict[keys_array[2]] = 'rw'
    assert_dict[keys_array[3]] = '/dev/vda1'
    _check_drives(test_microvm, assert_dict, keys_array)


def test_partuuid_update(test_microvm_with_api, network_config):
    """
    Test successful switching from PARTUUID boot to /dev/vda boot.

    @type: functional
    """
    test_microvm = test_microvm_with_api
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


def test_patch_drive(test_microvm_with_api, network_config):
    """
    Test replacing the backing filesystem after guest boot works.

    @type: functional
    """
    test_microvm = test_microvm_with_api
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


def test_no_flush(test_microvm_with_api, network_config):
    """
    Verify default block ignores flush.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    test_microvm.basic_config(
        vcpu_count=1,
        add_root_device=False
    )

    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')

    # Add the block device
    test_microvm.add_drive(
        'rootfs',
        test_microvm.rootfs_file,
        root_device=True,
    )

    # Configure the metrics.
    metrics_fifo_path = os.path.join(test_microvm.path, 'metrics_fifo')
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = test_microvm.metrics.put(
        metrics_path=test_microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    # Verify all flush commands were ignored during boot.
    fc_metrics = test_microvm.flush_metrics(metrics_fifo)
    assert fc_metrics['block']['flush_count'] == 0

    # Have the guest drop the caches to generate flush requests.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    cmd = "sync; echo 1 > /proc/sys/vm/drop_caches"
    _, _, stderr = ssh_connection.execute_command(cmd)
    assert stderr.read() == ''

    # Verify all flush commands were ignored even after
    # dropping the caches.
    fc_metrics = test_microvm.flush_metrics(metrics_fifo)
    assert fc_metrics['block']['flush_count'] == 0


def test_flush(test_microvm_with_api, network_config):
    """
    Verify block with flush actually flushes.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    test_microvm.basic_config(
        vcpu_count=1,
        add_root_device=False
    )

    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')

    # Add the block device with explicitly enabling flush.
    test_microvm.add_drive(
        'rootfs',
        test_microvm.rootfs_file,
        root_device=True,
        cache_type="Writeback",
    )

    # Configure metrics, to get later the `flush_count`.
    metrics_fifo_path = os.path.join(test_microvm.path, 'metrics_fifo')
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = test_microvm.metrics.put(
        metrics_path=test_microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    # Have the guest drop the caches to generate flush requests.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    cmd = "sync; echo 1 > /proc/sys/vm/drop_caches"
    _, _, stderr = ssh_connection.execute_command(cmd)
    assert stderr.read() == ''

    # On average, dropping the caches right after boot generates
    # about 6 block flush requests.
    fc_metrics = test_microvm.flush_metrics(metrics_fifo)
    assert fc_metrics['block']['flush_count'] > 0


def test_block_default_cache_old_version(test_microvm_with_api):
    """
    Verify that saving a snapshot for old versions works correctly.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    test_microvm.basic_config(
        vcpu_count=1,
        add_root_device=False
    )

    # Add the block device with explicitly enabling flush.
    test_microvm.add_drive(
        'rootfs',
        test_microvm.rootfs_file,
        root_device=True,
        cache_type="Writeback",
    )

    test_microvm.start()

    # Pause the VM to create the snapshot.
    response = test_microvm.vm.patch(state='Paused')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Create the snapshot for a version without block cache type.
    response = test_microvm.snapshot.create(
        mem_file_path='memfile',
        snapshot_path='snapsfile',
        diff=False,
        version='0.24.0'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # We should find a warning in the logs for this case as this
    # cache type was not supported in 0.24.0 and we should default
    # to "Unsafe" mode.
    test_microvm.check_log_message("Target version does not implement the"
                                   " current cache type. "
                                   "Defaulting to \"unsafe\" mode.")


def check_iops_limit(ssh_connection, block_size, count, min_time, max_time):
    """Verify if the rate limiter throttles block iops using dd."""
    obs = block_size
    byte_count = block_size * count
    dd = "dd if=/dev/zero of=/dev/vdb ibs={} obs={} count={} oflag=direct"\
        .format(block_size, obs, count)
    print("Running cmd {}".format(dd))
    # Check write iops (writing with oflag=direct is more reliable).
    exit_code, _, stderr = ssh_connection.execute_command(dd)
    assert exit_code == 0

    # "dd" writes to stderr by design. We drop first lines
    stderr.readline().strip()
    stderr.readline().strip()
    dd_result = stderr.readline().strip()

    # Interesting output looks like this:
    # 4194304 bytes (4.2 MB, 4.0 MiB) copied, 0.0528524 s, 79.4 MB/s
    tokens = dd_result.split()

    # Check total read bytes.
    assert int(tokens[0]) == byte_count
    # Check duration.
    assert float(tokens[7]) > min_time
    assert float(tokens[7]) < max_time


def test_patch_drive_limiter(test_microvm_with_api, network_config):
    """
    Test replacing the drive rate-limiter after guest boot works.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.jailer.daemonize = False
    test_microvm.spawn()
    # Set up the microVM with 2 vCPUs, 512 MiB of RAM, 1 network iface, a root
    # file system with the rw permission, and a scratch drive.
    test_microvm.basic_config(vcpu_count=2,
                              mem_size_mib=512,
                              boot_args='console=ttyS0 reboot=k panic=1')

    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')

    fs1 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'scratch'),
        size=512
    )
    response = test_microvm.drive.put(
        drive_id='scratch',
        path_on_host=test_microvm.create_jailed_resource(fs1.path),
        is_root_device=False,
        is_read_only=False,
        rate_limiter={
            'bandwidth': {
                'size': 10 * MB,
                'refill_time': 100
            },
            'ops': {
                'size': 100,
                'refill_time': 100
            }
        }
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    test_microvm.start()
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Validate IOPS stays within above configured limits.
    # For example, the below call will validate that reading 1000 blocks
    # of 512b will complete in at 0.8-1.2 seconds ('dd' is not very accurate,
    # so we target to stay within 30% error).
    check_iops_limit(ssh_connection, 512, 1000, 0.7, 1.3)
    check_iops_limit(ssh_connection, 4096, 1000, 0.7, 1.3)

    # Patch ratelimiter
    response = test_microvm.drive.patch(
        drive_id='scratch',
        rate_limiter={
            'bandwidth': {
                'size': 100 * MB,
                'refill_time': 100
            },
            'ops': {
                'size': 200,
                'refill_time': 100
            }
        }
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    check_iops_limit(ssh_connection, 512, 2000, 0.7, 1.3)
    check_iops_limit(ssh_connection, 4096, 2000, 0.7, 1.3)

    # Patch ratelimiter
    response = test_microvm.drive.patch(
        drive_id='scratch',
        rate_limiter={
            'ops': {
                'size': 1000,
                'refill_time': 100
            }
        }
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    check_iops_limit(ssh_connection, 512, 10000, 0.7, 1.3)
    check_iops_limit(ssh_connection, 4096, 10000, 0.7, 1.3)


def _check_block_size(ssh_connection, dev_path, size):
    _, stdout, stderr = ssh_connection.execute_command(
        'blockdev --getsize64 {}'.format(dev_path)
    )

    assert stderr.read() == ''
    assert stdout.readline().strip() == str(size)


def _check_file_size(ssh_connection, dev_path, size):
    _, stdout, stderr = ssh_connection.execute_command(
        'stat --format=%s {}'.format(dev_path)
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
