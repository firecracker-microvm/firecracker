# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the correctness of the Firecracker API."""

import os
import platform
import time

import pytest

import host_tools.drive as drive_tools
import host_tools.logging as log_tools
import host_tools.network as net_tools


def test_api_happy_start(test_microvm_with_api):
    """Test a regular microvm API start sequence."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    test_microvm.start()


def test_api_put_update_pre_boot(test_microvm_with_api):
    """Test that PUT updates are allowed before the microvm boots."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM  and
    # a root file system with the rw permission.
    test_microvm.basic_config()

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

    # Updates to `kernel_image_path` with an invalid path are not allowed.
    response = test_microvm.boot.put(
        kernel_image_path='foo.bar'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "The kernel file cannot be opened due to invalid kernel path or " \
           "invalid permissions" in response.text

    # Updates to `kernel_image_path` with a valid path are allowed.
    response = test_microvm.boot.put(
        kernel_image_path=test_microvm.get_jailed_resource(
            test_microvm.kernel_file
        )
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Updates to `path_on_host` with an invalid path are not allowed.
    response = test_microvm.drive.put(
        drive_id='rootfs',
        path_on_host='foo.bar',
        is_read_only=True,
        is_root_device=True
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Invalid block device path" in response.text

    # Updates to `is_root_device` that result in two root block devices are not
    # allowed.
    response = test_microvm.drive.put(
        drive_id='scratch',
        path_on_host=test_microvm.get_jailed_resource(fs1.path),
        is_read_only=False,
        is_root_device=True
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "A root block device already exists" in response.text

    # Valid updates to `path_on_host` and `is_read_only` are allowed.
    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'otherscratch')
    )
    response = test_microvm.drive.put(
        drive_id='scratch',
        path_on_host=test_microvm.create_jailed_resource(fs2.path),
        is_read_only=True,
        is_root_device=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Valid updates to all fields in the machine configuration are allowed.
    # The machine configuration has a default value, so all PUTs are updates.
    microvm_config_json = {
        'vcpu_count': 4,
        'ht_enabled': True,
        'mem_size_mib': 256,
        'cpu_template': 'C3'
    }
    response = test_microvm.machine_cfg.put(
        vcpu_count=microvm_config_json['vcpu_count'],
        ht_enabled=microvm_config_json['ht_enabled'],
        mem_size_mib=microvm_config_json['mem_size_mib'],
        cpu_template=microvm_config_json['cpu_template']
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    response = test_microvm.machine_cfg.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    response_json = response.json()

    vcpu_count = microvm_config_json['vcpu_count']
    assert response_json['vcpu_count'] == vcpu_count

    ht_enabled = microvm_config_json['ht_enabled']
    assert response_json['ht_enabled'] == ht_enabled

    mem_size_mib = microvm_config_json['mem_size_mib']
    assert response_json['mem_size_mib'] == mem_size_mib

    cpu_template = str(microvm_config_json['cpu_template'])
    assert response_json['cpu_template'] == cpu_template


def test_net_api_put_update_pre_boot(test_microvm_with_api):
    """Test PUT updates on network configurations before the microvm boots."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    first_if_name = 'first_tap'
    tap1 = net_tools.Tap(first_if_name, test_microvm.jailer.netns)
    response = test_microvm.network.put(
        iface_id='1',
        guest_mac='06:00:00:00:00:01',
        host_dev_name=tap1.name
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Adding new network interfaces is allowed.
    second_if_name = 'second_tap'
    tap2 = net_tools.Tap(second_if_name, test_microvm.jailer.netns)
    response = test_microvm.network.put(
        iface_id='2',
        guest_mac='07:00:00:00:00:01',
        host_dev_name=tap2.name
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Updates to a network interface with an unavailable MAC are not allowed.
    guest_mac = '06:00:00:00:00:01'
    response = test_microvm.network.put(
        iface_id='2',
        host_dev_name=second_if_name,
        guest_mac=guest_mac
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert \
        "The guest MAC address {} is already in use.".format(guest_mac) \
        in response.text

    # Updates to a network interface with an available MAC are allowed.
    response = test_microvm.network.put(
        iface_id='2',
        host_dev_name=second_if_name,
        guest_mac='08:00:00:00:00:01'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Updates to a network interface with an unavailable name are not allowed.
    response = test_microvm.network.put(
        iface_id='1',
        host_dev_name=second_if_name,
        guest_mac='06:00:00:00:00:01'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "The host device name {} is already in use.".\
        format(second_if_name) in response.text

    # Updates to a network interface with an available name are allowed.
    iface_id = '1'
    tapname = test_microvm.id[:8] + 'tap' + iface_id

    tap3 = net_tools.Tap(tapname, test_microvm.jailer.netns)
    response = test_microvm.network.put(
        iface_id=iface_id,
        host_dev_name=tap3.name,
        guest_mac='06:00:00:00:00:01'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)


def test_api_put_machine_config(test_microvm_with_api):
    """Test /machine_config PUT scenarios that unit tests can't cover."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Test invalid vcpu count < 0.
    response = test_microvm.machine_cfg.put(
        vcpu_count='-2'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    # Test invalid mem_size_mib < 0.
    response = test_microvm.machine_cfg.put(
        mem_size_mib='-2'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    # Test invalid type for ht_enabled flag.
    response = test_microvm.machine_cfg.put(
        ht_enabled='random_string'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    # Test invalid CPU template.
    response = test_microvm.machine_cfg.put(
        cpu_template='random_string'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)


def test_api_put_update_post_boot(test_microvm_with_api):
    """Test that PUT updates are rejected after the microvm boots."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM  and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    iface_id = '1'
    tapname = test_microvm.id[:8] + 'tap' + iface_id
    tap1 = net_tools.Tap(tapname, test_microvm.jailer.netns)
    response = test_microvm.network.put(
        iface_id=iface_id,
        host_dev_name=tap1.name,
        guest_mac='06:00:00:00:00:01'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    # Valid updates to `kernel_image_path` are not allowed after boot.
    response = test_microvm.boot.put(
        kernel_image_path=test_microvm.get_jailed_resource(
            test_microvm.kernel_file
        )
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "The update operation is not allowed after boot" in response.text

    # Valid updates to the machine configuration are not allowed after boot.
    response = test_microvm.machine_cfg.patch(
        vcpu_count=4
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "The update operation is not allowed after boot" in response.text

    response = test_microvm.machine_cfg.put(
        vcpu_count=4,
        ht_enabled=False,
        mem_size_mib=128
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "The update operation is not allowed after boot" in response.text

    # Network interface update is not allowed after boot.
    response = test_microvm.network.put(
        iface_id='1',
        host_dev_name=tap1.name,
        guest_mac='06:00:00:00:00:02'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "The update operation is not allowed after boot" in response.text

    # Block device update is not allowed after boot.
    response = test_microvm.drive.put(
        drive_id='rootfs',
        path_on_host=test_microvm.jailer.jailed_path(test_microvm.rootfs_file),
        is_read_only=False,
        is_root_device=True
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "The update operation is not allowed after boot" in response.text


def test_rate_limiters_api_config(test_microvm_with_api):
    """Test the Firecracker IO rate limiter API."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Test the DRIVE rate limiting API.

    # Test drive with bw rate-limiting.
    fs1 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, 'bw'))
    response = test_microvm.drive.put(
        drive_id='bw',
        path_on_host=test_microvm.create_jailed_resource(fs1.path),
        is_read_only=False,
        is_root_device=False,
        rate_limiter={
            'bandwidth': {
                'size': 1000000,
                'refill_time': 100
            }
        }
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Test drive with ops rate-limiting.
    fs2 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, 'ops'))
    response = test_microvm.drive.put(
        drive_id='ops',
        path_on_host=test_microvm.create_jailed_resource(fs2.path),
        is_read_only=False,
        is_root_device=False,
        rate_limiter={
            'ops': {
                'size': 1,
                'refill_time': 100
            }
        }
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Test drive with bw and ops rate-limiting.
    fs3 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'bwops')
    )
    response = test_microvm.drive.put(
        drive_id='bwops',
        path_on_host=test_microvm.create_jailed_resource(fs3.path),
        is_read_only=False,
        is_root_device=False,
        rate_limiter={
            'bandwidth': {
                'size': 1000000,
                'refill_time': 100
            },
            'ops': {
                'size': 1,
                'refill_time': 100
            }
        }
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Test drive with 'empty' rate-limiting (same as not specifying the field)
    fs4 = drive_tools.FilesystemFile(os.path.join(
        test_microvm.fsfiles, 'nada'
    ))
    response = test_microvm.drive.put(
        drive_id='nada',
        path_on_host=test_microvm.create_jailed_resource(fs4.path),
        is_read_only=False,
        is_root_device=False,
        rate_limiter={}
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Test the NET rate limiting API.

    # Test network with tx bw rate-limiting.
    iface_id = '1'
    tapname = test_microvm.id[:8] + 'tap' + iface_id
    tap1 = net_tools.Tap(tapname, test_microvm.jailer.netns)

    response = test_microvm.network.put(
        iface_id=iface_id,
        guest_mac='06:00:00:00:00:01',
        host_dev_name=tap1.name,
        tx_rate_limiter={
            'bandwidth': {
                'size': 1000000,
                'refill_time': 100
            }
        }
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Test network with rx bw rate-limiting.
    iface_id = '2'
    tapname = test_microvm.id[:8] + 'tap' + iface_id
    tap2 = net_tools.Tap(tapname, test_microvm.jailer.netns)
    response = test_microvm.network.put(
        iface_id=iface_id,
        guest_mac='06:00:00:00:00:02',
        host_dev_name=tap2.name,
        rx_rate_limiter={
            'bandwidth': {
                'size': 1000000,
                'refill_time': 100
            }
        }
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Test network with tx and rx bw and ops rate-limiting.
    iface_id = '3'
    tapname = test_microvm.id[:8] + 'tap' + iface_id
    tap3 = net_tools.Tap(tapname, test_microvm.jailer.netns)
    response = test_microvm.network.put(
        iface_id=iface_id,
        guest_mac='06:00:00:00:00:03',
        host_dev_name=tap3.name,
        rx_rate_limiter={
            'bandwidth': {
                'size': 1000000,
                'refill_time': 100
            },
            'ops': {
                'size': 1,
                'refill_time': 100
            }
        },
        tx_rate_limiter={
            'bandwidth': {
                'size': 1000000,
                'refill_time': 100
            },
            'ops': {
                'size': 1,
                'refill_time': 100
            }
        }
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)


def test_api_patch_pre_boot(test_microvm_with_api):
    """Tests PATCH updates before the microvm boots."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Sets up the microVM with 2 vCPUs, 256 MiB of RAM, 1 network iface, a
    # root file system with the rw permission and logging enabled.
    test_microvm.basic_config()

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

    # Configure logging.
    log_fifo_path = os.path.join(test_microvm.path, 'log_fifo')
    metrics_fifo_path = os.path.join(test_microvm.path, 'metrics_fifo')
    log_fifo = log_tools.Fifo(log_fifo_path)
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)

    response = test_microvm.logger.put(
        log_fifo=test_microvm.create_jailed_resource(log_fifo.path),
        metrics_fifo=test_microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    iface_id = '1'
    tapname = test_microvm.id[:8] + 'tap' + iface_id
    tap1 = net_tools.Tap(tapname, test_microvm.jailer.netns)
    response = test_microvm.network.put(
        iface_id=iface_id,
        host_dev_name=tap1.name,
        guest_mac='06:00:00:00:00:01'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Partial updates to the boot source are not allowed.
    response = test_microvm.boot.patch(
        kernel_image_path='otherfile'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Invalid request method" in response.text

    # Partial updates to the machine configuration are allowed before boot.
    response = test_microvm.machine_cfg.patch(vcpu_count=4)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    response_json = test_microvm.machine_cfg.get().json()
    assert response_json['vcpu_count'] == 4

    # Partial updates to the logger configuration are not allowed.
    response = test_microvm.logger.patch(level='Error')
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Invalid request method" in response.text


def test_api_patch_post_boot(test_microvm_with_api):
    """Test PATCH updates after the microvm boots."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Sets up the microVM with 2 vCPUs, 256 MiB of RAM, 1 network iface and
    # a root file system with the rw permission.
    test_microvm.basic_config()

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

    # Configure logging.
    log_fifo_path = os.path.join(test_microvm.path, 'log_fifo')
    metrics_fifo_path = os.path.join(test_microvm.path, 'metrics_fifo')
    log_fifo = log_tools.Fifo(log_fifo_path)
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)

    response = test_microvm.logger.put(
        log_fifo=test_microvm.create_jailed_resource(log_fifo.path),
        metrics_fifo=test_microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    iface_id = '1'
    tapname = test_microvm.id[:8] + 'tap' + iface_id
    tap1 = net_tools.Tap(tapname, test_microvm.jailer.netns)
    response = test_microvm.network.put(
        iface_id=iface_id,
        host_dev_name=tap1.name,
        guest_mac='06:00:00:00:00:01'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    # Partial updates to the boot source are not allowed.
    response = test_microvm.boot.patch(
        kernel_image_path='otherfile'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Invalid request method" in response.text

    # Partial updates to the machine configuration are not allowed after boot.
    response = test_microvm.machine_cfg.patch(vcpu_count=4)
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "The update operation is not allowed after boot." in response.text

    # Partial updates to the logger configuration are not allowed.
    response = test_microvm.logger.patch(level='Error')
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Invalid request method" in response.text


def test_drive_patch(test_microvm_with_api):
    """Test drive PATCH before and after boot."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Sets up the microVM with 2 vCPUs, 256 MiB of RAM and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    # The drive to be patched.
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

    _drive_patch(test_microvm)

    test_microvm.start()

    _drive_patch(test_microvm)


def test_api_actions(test_microvm_with_api):
    """Test PUTs to /actions beyond InstanceStart and InstanceHalt."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Sets up the microVM with 2 vCPUs, 256 MiB of RAM and
    # a root file system with the rw permission.
    test_microvm.basic_config()

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

    # Rescan operations before the guest boots are not allowed.
    response = test_microvm.actions.put(
        action_type='BlockDeviceRescan',
        payload='scratch'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Operation not allowed pre-boot" in response.text

    test_microvm.start()

    # Rescan operations after the guest boots are allowed.
    response = test_microvm.actions.put(
        action_type='BlockDeviceRescan',
        payload='scratch'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Rescan operations on non-existent drives are not allowed.
    response = test_microvm.actions.put(
        action_type='BlockDeviceRescan',
        payload='foobar'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Invalid block device ID" in response.text


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="not yet implemented on aarch64"
)
def test_send_ctrl_alt_del(test_microvm_with_atkbd):
    """Test shutting down the microVM gracefully, by sending CTRL+ALT+DEL.

    This relies on i8042 and AT Keyboard support being present in the guest
    kernel.
    """
    test_microvm = test_microvm_with_atkbd
    test_microvm.spawn()

    test_microvm.basic_config()
    test_microvm.start()

    # Wait around for the guest to boot up and initialize the user space
    time.sleep(2)

    response = test_microvm.actions.put(
        action_type='SendCtrlAltDel'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    firecracker_pid = test_microvm.jailer_clone_pid

    # If everyting goes as expected, the guest OS will issue a reboot,
    # causing Firecracker to exit.
    # We'll keep poking Firecracker for at most 30 seconds, waiting for it
    # to die.
    start_time = time.time()
    shutdown_ok = False
    while time.time() - start_time < 30:
        try:
            os.kill(firecracker_pid, 0)
            time.sleep(0.01)
        except OSError:
            shutdown_ok = True
            break

    assert shutdown_ok


def _drive_patch(test_microvm):
    """Exercise drive patch test scenarios."""
    # Patches without mandatory fields are not allowed.
    response = test_microvm.drive.patch(
        drive_id='scratch'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Required key path_on_host not present in the json." \
           in response.text

    # Cannot patch drive permissions post boot.
    response = test_microvm.drive.patch(
        drive_id='scratch',
        path_on_host='foo.bar',
        is_read_only=True
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Invalid PATCH payload. Only updates on path_on_host are allowed." \
           in response.text

    # Updates to `is_root_device` with a valid value are not allowed.
    response = test_microvm.drive.patch(
        drive_id='scratch',
        path_on_host='foo.bar',
        is_root_device=False
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Invalid PATCH payload. Only updates on path_on_host are allowed." \
           in response.text

    # Updates to `path_on_host` with an invalid path are not allowed.
    response = test_microvm.drive.patch(
        drive_id='scratch',
        path_on_host='foo.bar'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Cannot open block device. Invalid permission/path." \
           in response.text

    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, 'scratch_new')
    )
    # Updates to `path_on_host` with a valid path are allowed.
    response = test_microvm.drive.patch(
        drive_id='scratch',
        path_on_host=test_microvm.create_jailed_resource(fs.path)
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)


def test_api_vsock(test_microvm_with_api):
    """Test vsock related API commands."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()

    response = test_microvm.vsock.put(
        vsock_id='vsock1',
        guest_cid=15,
        uds_path='vsock.sock'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Updating an existing vsock is currently fine.
    response = test_microvm.vsock.put(
        vsock_id='vsock1',
        guest_cid=166,
        uds_path='vsock.sock'
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # No other vsock action is allowed after booting the VM.
    test_microvm.start()

    # Updating an existing vsock should not be fine at this point.
    response = test_microvm.vsock.put(
        vsock_id='vsock1',
        guest_cid=17,
        uds_path='vsock.sock'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    # Attaching a new vsock device should not be fine at this point.
    response = test_microvm.vsock.put(
        vsock_id='vsock3',
        guest_cid=18,
        uds_path='vsock.sock'
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
