"""
Tests that ensure the correctness of the Firecracker API.

# TODO

- Add many more API tests!
"""
import shutil

import pytest


@pytest.mark.timeout(240)
def test_api_happy_start(test_microvm_with_api):
    """ Tests a regular microvm API start sequence. """

    test_microvm = test_microvm_with_api
    test_microvm.basic_config(net_iface_count=2)
    """
    Sets up the microVM with 2 vCPUs, 256 MiB of RAM, 2 network ifaces and
    a root file system with the rw permission.
    """

    test_microvm.start()


def test_api_put_update_pre_boot(test_microvm_with_api):
    """ Tests that PUT updates are allowed before the microvm boots. """

    test_microvm = test_microvm_with_api

    test_microvm.basic_config()
    """
    Sets up the microVM with 2 vCPUs, 256 MiB of RAM, 1 network iface and
    a root file system with the rw permission.
    """

    test_microvm.put_default_scratch_device()

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
            'is_read_only': True
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
            'is_read_only': False
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
            'is_read_only': True
        }
    )
    """ Valid updates to `path_on_host` and `is_read_only` are allowed. """
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

    test_microvm.basic_config()
    """
    Sets up the microVM with 2 vCPUs, 256 MiB of RAM, 1 network iface and
    a root file system with the rw permission.
    """

    test_microvm.start()

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

    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/rootfs',
        json={
            'drive_id': 'rootfs',
            'path_on_host': test_microvm.slot.rootfs_file,
            'is_root_device': True,
            'is_read_only': False
        }
    )
    """ Block device update is not allowed after boot."""
    assert(not test_microvm.api_session.is_good_response(response.status_code))


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
            'is_read_only': False,
            'rate_limiter': {
                'bandwidth': {
                    'size': 1000000,
                    'refill_time': 100
                }
            },
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
            'is_read_only': False,
            'rate_limiter': {
                'ops': {
                    'size': 1,
                    'refill_time': 100
                }
            },
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
            'is_read_only': False,
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
            'is_read_only': False,
            'rate_limiter': {
            },
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


def test_mmds(test_microvm_with_api):
    test_microvm = test_microvm_with_api

    response = test_microvm.api_session.get(test_microvm.mmds_url)
    assert(test_microvm.api_session.is_good_response(response.status_code))
    assert(response.json() == {})

    # Test that patch return NotFound when the MMDS is not initialized.
    dummy_json = {
        'latest': {
            'meta-data': {
                'ami-id': 'dummy'
            }
        }
    }
    response = test_microvm.api_session.patch(
        test_microvm.mmds_url,
        json = dummy_json
    )
    assert(response.status_code == 404)
    fault_json = {
        "fault_message": "The MMDS resource does not exist."
    }
    assert(response.json() == fault_json)

    # Test that using the same json with a PUT request, the MMDS data-store is
    # created.
    response = test_microvm.api_session.put(
        test_microvm.mmds_url,
        json = dummy_json
    )
    assert(response.status_code == 201)
    response = test_microvm.api_session.get(test_microvm.mmds_url)
    assert(response.json() == dummy_json)

    # PUT only allows full updates.
    # The json used in MMDS is based on the one from the Instance Meta-data
    # online documentation.
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
    data_store = {
        'latest': {
            'meta-data': {
                'ami-id': 'ami-12345678',
                'reservation-id': 'r-fea54097',
                'local-hostname': 'ip-10-251-50-12.ec2.internal',
                'public-hostname': 'ec2-203-0-113-25.compute-1.amazonaws.com',
                'network': {
                    'interfaces': {
                        'macs': {
                            '02:29:96:8f:6a:2d': {
                                'device-number': '13345342',
                                'local-hostname': 'localhost',
                                'subnet-id': 'subnet-be9b61d'
                            }
                        }
                    }
                }
            }
        }
    }
    response = test_microvm.api_session.put(
        test_microvm.mmds_url,
        json = data_store
    )

    assert(response.status_code == 204)

    response = test_microvm.api_session.get(test_microvm.mmds_url)
    assert(response.json() == data_store)

    # Change only the subnet id using PATCH method.
    patch_json = {
        'latest': {
            'meta-data': {
                'network': {
                    'interfaces': {
                        'macs': {
                            '02:29:96:8f:6a:2d': {
                                'subnet-id': 'subnet-12345'
                            }
                        }
                    }
                }
            }
        }
    }

    response = test_microvm.api_session.patch(
        test_microvm.mmds_url,
        json = patch_json
    )
    assert(response.status_code == 204)
    data_store['latest']['meta-data']['network']['interfaces']['macs']\
        ['02:29:96:8f:6a:2d']['subnet-id'] = 'subnet-12345'

    response = test_microvm.api_session.get(test_microvm.mmds_url)
    assert(response.json() == data_store)


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
            'is_read_only': False
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


def test_api_actions(test_microvm_with_api):
    """
    Tests PUT requests to /actions, other than InstanceStart and InstanceHalt.
    """

    test_microvm = test_microvm_with_api
    test_microvm.basic_config()
    """
    Sets up the microVM with 2 vCPUs, 256 MiB of RAM, 1 network iface and
    a root file system with the rw permission.
    """

    test_microvm.put_default_scratch_device()

    response = test_microvm.api_session.put(
        test_microvm.actions_url,
        json={
            'action_type': 'BlockDeviceRescan',
            'payload': 'scratch',
        }
    )
    """ Rescan operations before the guest boots are not allowed. """
    assert(not test_microvm.api_session.is_good_response(response.status_code))

    test_microvm.start()

    response = test_microvm.api_session.put(
        test_microvm.actions_url,
        json={
            'action_type': 'BlockDeviceRescan',
            'payload': 'scratch',
        }
    )
    """ Rescan operations after the guest boots are allowed. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.actions_url,
        json={
            'action_type': 'BlockDeviceRescan',
            'payload': 'foobar',
        }
    )
    """ Rescan operations on non-existent drives are not allowed. """
    assert(not test_microvm.api_session.is_good_response(response.status_code))
