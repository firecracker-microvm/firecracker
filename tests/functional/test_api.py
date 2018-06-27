"""
Tests that ensure the correctness of the Firecracker API.

# TODO

- Add many more API tests!
"""
import shutil
import time

import pytest


@pytest.mark.timeout(240)
def test_api_happy_start(test_microvm_with_api):
    """ Tests a regular microvm API start sequence. """

    test_microvm = test_microvm_with_api
    api_responses = test_microvm.basic_config(net_iface_count=2)
    """
    Sets up the microVM with 2 vCPUs, 256 MiB of RAM, and 2 network ifaces.
    """
    for response in api_responses:
        assert(test_microvm.api_session.is_good_response(response.status_code))

    _test_default_block_devices(test_microvm)
    """ Sets up 2 block devices for the microVM: `rootfs` and `scratch`. """

    response = test_microvm.api_session.put(
        test_microvm.actions_url + '/1',
        json={'action_id': '1', 'action_type': 'InstanceStart'}
    )
    """ Issues a power-on command to the microvm. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    time.sleep(1)
    response = test_microvm.api_session.get(
        test_microvm.actions_url + '/1'
    )
    assert(test_microvm.api_session.is_good_response(response.status_code))


def test_api_put_update_pre_boot(test_microvm_with_api):
    """ Tests that PUT updates are allowed before the microvm boots. """

    test_microvm = test_microvm_with_api

    api_responses = test_microvm.basic_config()
    """
    Sets up the microVM with 2 vCPUs, 256 MiB of RAM, and 1 network iface.
    """
    for response in api_responses:
        assert(test_microvm.api_session.is_good_response(response.status_code))

    _test_default_block_devices(test_microvm)
    """ Sets up 2 block devices for the microVM: `rootfs` and `scratch`. """

    response = test_microvm.api_session.put(
        test_microvm.boot_cfg_url,
        json={
            'boot_source_id': '1',
            'source_type': 'LocalImage',
            'local_image': {'kernel_image_path': 'foo.bar'}
        }
    )
    """
    Updates to `kernel_image_path` with an invalid path are not allowed.
    """
    assert(not test_microvm.api_session.is_good_response(response.status_code))

    kernel_copy = test_microvm.slot.kernel_file + '.copy'
    # The copy will be cleaned up by the microvm fixture's teardown() function.
    shutil.copy(test_microvm.slot.kernel_file, kernel_copy)
    response = test_microvm.api_session.put(
        test_microvm.boot_cfg_url,
        json={
            'boot_source_id': '1',
            'source_type': 'LocalImage',
            'local_image': {'kernel_image_path': kernel_copy}
        }
    )
    """ Updates to `kernel_image_path` with a valid path are allowed. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/root',
        json={
            'drive_id': 'root',
            'path_on_host': 'foo.bar',
            'is_root_device': True,
            'permissions': 'ro',
            'state': 'Attached'
        }
    )
    """ Updates to `path_on_host` with an invalid path are not allowed. """
    assert(not test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/otherroot',
        json={
            'drive_id': 'otherroot',
            'path_on_host': test_microvm.slot.make_fsfile(name='otherroot'),
            'is_root_device': True,
            'permissions': 'rw',
            'state': 'Attached'
        }
    )
    """
    Updates to `is_root_device` that result in two root block devices are not
    allowed.
    """
    assert(not test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/scratch',
        json={
            'drive_id': 'scratch',
            'path_on_host': test_microvm.slot.make_fsfile(name='otherscratch'),
            'is_root_device': False,
            'permissions': 'ro',
            'state': 'Attached'
        }
    )
    """ Valid updates to `path_on_host` and `permissions` are allowed. """
    assert(test_microvm.api_session.is_good_response(response.status_code))
    microvm_config_json = {
        'vcpu_count': 4,
        'ht_enabled': True,
        'mem_size_mib': 256,
        'cpu_template': 'C3'
    }
    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json=microvm_config_json
    )
    """
    Valid updates to all fields in the machine configuration are allowed.
    The machine configuration has a default value, so all PUTs are updates.
    """
    assert(response.status_code == 204)

    response = test_microvm.api_session.get(
        test_microvm.microvm_cfg_url,
    )
    response_json = response.json()

    vcpu_count = str(microvm_config_json['vcpu_count'])
    assert(response_json['vcpu_count'] == vcpu_count)

    ht_enabled = str(microvm_config_json['ht_enabled']).lower()
    assert(response_json['ht_enabled'] == ht_enabled)

    mem_size_mib = str(microvm_config_json['mem_size_mib'])
    assert(response_json['mem_size_mib'] == mem_size_mib)

    cpu_template = str(microvm_config_json['cpu_template'])
    assert(response_json['cpu_template'] == cpu_template)

    second_if_name = 'second_tap'
    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url + '/2',
        json={
            'iface_id': '2',
            'host_dev_name': test_microvm.slot.make_tap(name=second_if_name),
            'guest_mac': '07:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    """ Adding new network interfaces is allowed. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url + '/2',
        json={
            'iface_id': '2',
            'host_dev_name': second_if_name,
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    """
    Updates to a network interface with an unavailable MAC are not allowed.
    """
    assert(not test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url + '/2',
        json={
            'iface_id': '2',
            'host_dev_name': second_if_name,
            'guest_mac': '08:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    """ Updates to a network interface with an available MAC are allowed. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url + '/1',
        json={
            'iface_id': '1',
            'host_dev_name': second_if_name,
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    """
    Updates to a network interface with an unavailable name are not allowed.
    """
    assert(not test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url + '/1',
        json={
            'iface_id': '1',
            'host_dev_name': test_microvm.slot.make_tap(),
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    """ Updates to a network interface with an available name are allowed. """
    assert(test_microvm.api_session.is_good_response(response.status_code))


def test_api_put_machine_config(test_microvm_with_api):
    """
    Tests various scenarios for PUT on /machine_config that cannot be covered
    by the unit tests
    """

    """ Test invalid vcpu count < 0 """
    test_microvm = test_microvm_with_api
    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json={'vcpu_count': '-2'}
    )
    assert response.status_code == 400

    """ Test invalid mem_size_mib < 0 """
    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json={'mem_size_mib': '-2'}
    )
    assert response.status_code == 400

    """ Test invalid type for ht_enabled flag """
    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json={'ht_enabled': 'random_string'}
    )
    assert response.status_code == 400

    """ Test invalid CPU template """
    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json={'cpu_template': 'random_string'}
    )
    assert response.status_code == 400


def test_api_put_update_post_boot(test_microvm_with_api):
    """ Tests that PUT updates are rejected after the microvm boots. """

    test_microvm = test_microvm_with_api

    api_responses = test_microvm.basic_config()
    """
    Sets up the microVM with 2 vCPUs, 256 MiB of RAM, and 1 network iface.
    """
    for response in api_responses:
        assert(test_microvm.api_session.is_good_response(response.status_code))

    _test_default_block_devices(test_microvm)
    """ Sets up 2 block devices for the microVM: `rootfs` and `scratch`. """

    response = test_microvm.api_session.put(
        test_microvm.actions_url + '/1',
        json={'action_id': '1', 'action_type': 'InstanceStart'}
    )
    assert(test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.boot_cfg_url,
        json={
            'boot_source_id': '1',
            'source_type': 'LocalImage',
            'local_image': {'kernel_image_path': test_microvm.slot.kernel_file}
        }
    )
    """ Valid updates to `kernel_image_path` are not allowed after boot. """
    assert(not test_microvm.api_session.is_good_response(response.status_code))

    """
    TODO
    Uncomment this block after the block device update is implemented
    properly. Until then, the PUT triggers a rescan.
    """
    # response = uhttp.put(
    #     test_microvm.blk_cfg_url + '/scratch',
    #     json={
    #         'drive_id': 'scratch',
    #         'path_on_host': test_microvm.slot.make_fsfile(name='scratch'),
    #         'is_root_device': False,
    #         'permissions': 'ro',
    #         'state': 'Attached'
    #     }
    # )
    # """ Block device updates are not allowed via PUT after boot."""
    # assert(not uhttp.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json={'vcpu_count': 4}
    )
    """
    Valid updates to the machine configuration are not allowed after boot.
    """
    assert(not test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url + '/1',
        json={
            'iface_id': '1',
            'host_dev_name': test_microvm.slot.make_tap(name='dummytap'),
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    """ Network interface update is not allowed after boot."""
    assert(not test_microvm.api_session.is_good_response(response.status_code))


def _test_default_block_devices(test_microvm):
    """
    Sets up 2 block devices for the microVM:
    - `rootfs`, `ro`, from the MicrovmSlot rootfs image, and
    - `scratch`, `rw`, a newly created FilesystemFile.
    """

    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/rootfs',
        json={
            'drive_id': 'rootfs',
            'path_on_host': test_microvm.slot.rootfs_file,
            'is_root_device': True,
            'permissions': 'ro',
            'state': 'Attached'
        }
    )
    assert(test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/scratch',
        json={
            'drive_id': 'scratch',
            'path_on_host': test_microvm.slot.make_fsfile(name='scratch'),
            'is_root_device': False,
            'permissions': 'rw',
            'state': 'Attached'
        }
    )
    assert(test_microvm.api_session.is_good_response(response.status_code))


def test_rate_limiters_api_config(test_microvm_with_api):
    test_microvm = test_microvm_with_api

    """ Test DRIVE rate limiting API """
    """ Test drive with bw rate-limiting """
    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/bw',
        json={
            'drive_id': 'bw',
            'path_on_host': test_microvm.slot.make_fsfile(),
            'is_root_device': False,
            'permissions': 'rw',
            'rate_limiter': {
                'bandwidth': {
                    'size': 1000000,
                    'refill_time': 100
                }
            },
            'state': 'Attached'
        }
    )
    """ Verify the request succeeded """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    """ Test drive with ops rate-limiting """
    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/ops',
        json={
            'drive_id': 'ops',
            'path_on_host': test_microvm.slot.make_fsfile(),
            'is_root_device': False,
            'permissions': 'rw',
            'rate_limiter': {
                'ops': {
                    'size': 1,
                    'refill_time': 100
                }
            },
            'state': 'Attached'
        }
    )
    """ Verify the request succeeded """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    """ Test drive with bw and ops rate-limiting """
    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/bwops',
        json={
            'drive_id': 'bwops',
            'path_on_host': test_microvm.slot.make_fsfile(),
            'is_root_device': False,
            'permissions': 'rw',
            'rate_limiter': {
                'bandwidth': {
                    'size': 1000000,
                    'refill_time': 100
                },
                'ops': {
                    'size': 1,
                    'refill_time': 100
                }
            },
            'state': 'Attached'
        }
    )
    """ Verify the request succeeded """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    """
    Test drive with 'empty' rate-limiting (same as not specifying the field)
    """
    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/nada',
        json={
            'drive_id': 'nada',
            'path_on_host': test_microvm.slot.make_fsfile(),
            'is_root_device': False,
            'permissions': 'rw',
            'rate_limiter': {
            },
            'state': 'Attached'
        }
    )
    """ Verify the request succeeded """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    """ Test NET rate limiting API """
    """ Test network with tx bw rate-limiting """
    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url + '/1',
        json={
            'iface_id': '1',
            'host_dev_name': test_microvm.slot.make_tap(),
            'guest_mac': '06:00:00:00:00:01',
            'tx_rate_limiter': {
                'bandwidth': {
                    'size': 1000000,
                    'refill_time': 100
                }
            },
            'state': 'Attached'
        }
    )
    """ Verify the request succeeded """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    """ Test network with rx bw rate-limiting """
    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url + '/2',
        json={
            'iface_id': '2',
            'host_dev_name': test_microvm.slot.make_tap(),
            'guest_mac': '06:00:00:00:00:02',
            'rx_rate_limiter': {
                'bandwidth': {
                    'size': 1000000,
                    'refill_time': 100
                }
            },
            'state': 'Attached'
        }
    )
    """ Verify the request succeeded """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    """ Test network with tx and rx bw and ops rate-limiting """
    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url + '/3',
        json={
            'iface_id': '3',
            'host_dev_name': test_microvm.slot.make_tap(),
            'guest_mac': '06:00:00:00:00:03',
            'rx_rate_limiter': {
                'bandwidth': {
                    'size': 1000000,
                    'refill_time': 100
                },
                'ops': {
                    'size': 1,
                    'refill_time': 100
                }
            },
            'tx_rate_limiter': {
                'bandwidth': {
                    'size': 1000000,
                    'refill_time': 100
                },
                'ops': {
                    'size': 1,
                    'refill_time': 100
                }
            },
            'state': 'Attached'
        }
    )
    """ Verify the request succeeded """
    assert(test_microvm.api_session.is_good_response(response.status_code))


@pytest.mark.timeout(100)
def test_api_unknown_fields(test_microvm_with_api):
    """ Tests that requests with unknown fields result in error 400 """

    test_microvm = test_microvm_with_api

    """ Test invalid field for APILoggerDescription """
    """ path -> pth """
    response = test_microvm.api_session.put(
        test_microvm.logger_url,
        json={
            'pth': 'firecracker.log',
            'level': 'Info',
            'show_level': True,
            'show_log_origin': True
        }
    )
    assert response.status_code == 400

    """ Test invalid field for BootSourceBody """
    """ source_type -> source-type """
    response = test_microvm.api_session.put(
        test_microvm.boot_cfg_url,
        json={
            'boot_source_id': 'alinux_kernel',
            'source-type': 'LocalImage',
            'local_image': {
                'kernel-image_path': test_microvm.slot.kernel_file
            },
        }
    )
    assert response.status_code == 400

    """ Test invalid field for LocalImage """
    """ kernel_image_path ->  kernel-image_path """
    response = test_microvm.api_session.put(
        test_microvm.boot_cfg_url,
        json={
            'boot_source_id': 'alinux_kernel',
            'source_type': 'LocalImage',
            'local_image': {
                'kernel-image_path': test_microvm.slot.kernel_file
            },
        }
    )
    assert response.status_code == 400

    """ Test invalid field for DriveDescription """
    """ drive_id -> drive-id """
    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url,
        json={
            'drive-id': 'root',
            'path_on_host': test_microvm.slot.rootfs_file,
            'is_root_device': True,
            'permissions': 'rw',
            'state': 'Attached'
        }
    )
    assert response.status_code == 400

    """ Test invalid field for MachineConfiguration """
    """ vcpu_count -> vcpu-count """
    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json={'vcpu-count': 4, 'mem_size_mib': 256}
    )
    assert response.status_code == 400

    """ Test invalid field for NetworkInterfaceBody """
    """ iface_id -> iface-id """
    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url,
        json={
            'iface-id': 1,
            'host_dev_name': 'vmtap33',
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    assert response.status_code == 400

    """ Test invalid field for TokenBucketDescription """
    """ size -> siz """
    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url,
        json={
            'iface_id': 1,
            'host_dev_name': 'vmtap33',
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached',
            'rx_rate_limiter': {
                'bandwidth': {'siz': 1000000, 'refill_time': 1000}
            }
        }
    )
    assert response.status_code == 400

    """ Test invalid field for RateLimiterDescription """
    """ ops -> op """
    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url,
        json={
            'iface_id': 1,
            'host_dev_name': 'vmtap33',
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached',
            'rx_rate_limiter': {
                'op': {'size': 1000000, 'refill_time': 1000}
            }
        }
    )
    assert response.status_code == 400

    """ Test invalid field for AsyncRequestBody """
    """ action_id -> action-id """
    response = test_microvm.api_session.put(
        test_microvm.actions_url,
        json={
            'action_di': 'start',
            'action_type': 'InstanceStart',
        }
    )
    assert response.status_code == 400

    """ Test invalid field for InstanceDeviceDetachAction """
    """ device_resource_id -> device_resource_di """
    response = test_microvm.api_session.put(
        test_microvm.actions_url,
        json={
            'action_id': 'start3',
            'action_type': 'InstanceStart',
            'instance_device_detach_action': {
                'device_type': 'Drive',
                'device_resource_di': 1,
                'force': True
            }
        }
    )
    assert response.status_code == 400
