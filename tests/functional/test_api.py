"""
Tests that ensure the correctness of the Firecracker API.

# TODO

- Add many more API tests!
"""

import pytest
import shutil

@pytest.mark.timeout(240)
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


def test_api_put_update_pre_boot(test_microvm_any, uhttp):
    """ Tests that PUT updates are allowed before the microvm boots. """

    test_microvm = test_microvm_any

    _setup_microvm(test_microvm, uhttp)

    response = uhttp.put(
        test_microvm.boot_cfg_url,
        json={
            'boot_source_id': '1',
            'source_type': 'LocalImage',
            'local_image': {'kernel_image_path': 'foo.bar'}
        }
    )
    """ Updating the kernel with an invalid path is not allowed. """
    assert(not uhttp.is_good_response(response.status_code))

    kernel_copy = test_microvm.slot.kernel_file + '.copy'
    # The copy will be cleaned up by the microvm fixture's teardown() function.
    shutil.copy(test_microvm.slot.kernel_file, kernel_copy)
    response = uhttp.put(
        test_microvm.boot_cfg_url,
        json={
            'boot_source_id': '1',
            'source_type': 'LocalImage',
            'local_image': {'kernel_image_path': kernel_copy}
        }
    )
    """ Updates the kernel. """
    assert(uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.blk_cfg_url + '/root',
        json={
            'drive_id': 'root',
            'path_on_host': 'foo.bar',
            'is_root_device': True,
            'permissions': 'ro',
            'state': 'Attached'
        }
    )
    """ Updating a block device with an invalid path is not allowed. """
    assert(not uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.blk_cfg_url + '/scratch',
        json={
            'drive_id': 'scratch',
            'path_on_host': test_microvm.slot.make_fsfile(name='scratch'),
            'is_root_device': True,
            'permissions': 'rw',
            'state': 'Attached'
        }
    )
    """ An update that would result in two root block devices is not allowed."""
    assert(not uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.blk_cfg_url + '/scratch',
        json={
            'drive_id': 'scratch',
            'path_on_host': test_microvm.slot.make_fsfile(name='scratch'),
            'is_root_device': False,
            'permissions': 'ro',
            'state': 'Attached'
        }
    )
    """ Updates a block device."""
    assert(uhttp.is_good_response(response.status_code))

    response = uhttp.put(test_microvm.microvm_cfg_url, json={'vcpu_count': 2})
    """ Updates the vcpu count in the machine configuration.
    The machine configuration has a default value, so all PUTs are updates.
    """
    assert(uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.net_cfg_url + '/1',
        json={
            'iface_id': '1',
            'host_dev_name': test_microvm.slot.make_tap(name='dummytap'),
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    """ Updates the network interface."""
    assert(uhttp.is_good_response(response.status_code))


def test_api_put_update_post_boot(test_microvm_any, uhttp):
    """ Tests that PUT updates are rejected after the microvm boots. """

    test_microvm = test_microvm_any

    _setup_microvm(test_microvm, uhttp)

    uhttp.put(
        test_microvm.actions_url + '/1',
        json={'action_id': '1', 'action_type': 'InstanceStart'}
    )

    response = uhttp.put(
        test_microvm.boot_cfg_url,
        json={
            'boot_source_id': '1',
            'source_type': 'LocalImage',
            'local_image': {'kernel_image_path': test_microvm.slot.kernel_file}
        }
    )
    """ Kernel update is not allowed after boot. """
    assert(not uhttp.is_good_response(response.status_code))

    """ TODO
    Uncomment this block after the block device update is implemented properly. Until then, the PUT triggers a rescan.
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

    response = uhttp.put(test_microvm.microvm_cfg_url, json={'vcpu_count': 2})
    """ Machine configuration update is not allowed after boot."""
    assert(not uhttp.is_good_response(response.status_code))

    response = uhttp.put(
        test_microvm.net_cfg_url + '/1',
        json={
            'iface_id': '1',
            'host_dev_name': test_microvm.slot.make_tap(name='dummytap'),
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    """ Network interface update is not allowed after boot."""
    assert(not uhttp.is_good_response(response.status_code))


def _setup_microvm(test_microvm_any, uhttp):
    """ Sets up a microvm with a kernel, 2 block devices and a network interface. """

    test_microvm = test_microvm_any

    uhttp.put(
        test_microvm.boot_cfg_url,
        json={
            'boot_source_id': '1',
            'source_type': 'LocalImage',
            'local_image': {'kernel_image_path': test_microvm.slot.kernel_file}
        }
    )

    uhttp.put(
        test_microvm.blk_cfg_url + '/root',
        json={
            'drive_id': 'root',
            'path_on_host': test_microvm.slot.rootfs_file,
            'is_root_device': True,
            'permissions': 'ro',
            'state': 'Attached'
        }
    )

    uhttp.put(
        test_microvm.blk_cfg_url + '/scratch',
        json={
            'drive_id': 'scratch',
            'path_on_host': test_microvm.slot.make_fsfile(name='scratch'),
            'is_root_device': False,
            'permissions': 'rw',
            'state': 'Attached'
        }
    )

    uhttp.put(
        test_microvm.net_cfg_url + '/1',
        json={
            'iface_id': '1',
            'host_dev_name': test_microvm.slot.make_tap(),
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached'
        }
    )
