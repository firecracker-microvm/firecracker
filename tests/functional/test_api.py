"""
Tests that ensure the corectness of the Firecracker API.

# TODO

- Add many more API tests!
"""

import pytest


@pytest.mark.timeout(120)
def test_api_happy_start(test_microvm_any, uhttp):
    """ Tests a regular microvm API start sequence. """

    test_microvm = test_microvm_any

    response = uhttp.put(test_microvm.microvm_cfg_url, json={'vcpu_count': 2})
    assert(uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.microvm_cfg_url,
        json={'mem_size_mib': 256}
    )
    assert(uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.net_cfg_url + '/1',
        json={
            'iface_id': '1',
            'host_dev_name': test_microvm.slot.make_tap(),
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    """ Maps the passed host network device into the microVM. """
    assert(uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm_any.net_cfg_url + '/2',
        json={
            'iface_id': '2',
            'host_dev_name': test_microvm.slot.make_tap(),
            'guest_mac': '06:00:00:00:00:02',
            'state': 'Attached'
        }
    )
    """ Maps the passed host network device into the microVM. """
    assert(uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.blk_cfg_url + '/root',
        json={
            'drive_id': 'root',
            'path_on_host': test_microvm.slot.rootfs_file,
            'is_root_device': True,
            'permissions': 'ro',
            'state': 'Attached'
        }
    )
    """ Maps the passed block device into the microVM. This is the rootfs. """
    assert(uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.blk_cfg_url + '/scratch',
        json={
            'drive_id': 'scratch',
            'path_on_host': test_microvm.slot.make_fsfile(name='scratch'),
            'is_root_device': False,
            'permissions': 'rw',
            'state': 'Attached'
        }
    )
    """ Maps the passed block device into the microVM. This is scratch. """
    assert(uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.boot_cfg_url,
        json={
            'boot_source_id': '1',
            'source_type': 'LocalImage',
            'local_image': {'kernel_image_path': test_microvm.slot.kernel_file}
        }
    )
    """ Adds a kernel to start booting from. """
    assert(uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.actions_url + '/1',
        json={'action_id': '1', 'action_type': 'InstanceStart'}
    )
    """ Issues a power-on command to the microvm. """
    assert(uhttp.is_good_response(response.status_code))
