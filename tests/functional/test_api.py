"""
Tests that ensure the correctness of the Firecracker API.

# TODO

- Add many more API tests!
"""

import shutil
import time

import pytest


@pytest.mark.timeout(240)
def test_api_happy_start(test_microvm_any):
    """ Tests a regular microvm API start sequence. """

    test_microvm = test_microvm_any
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


def test_api_put_update_pre_boot(test_microvm_any):
    """ Tests that PUT updates are allowed before the microvm boots. """

    test_microvm = test_microvm_any

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

    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json={'vcpu_count': 4}
    )
    """
    Valid updates to the vcpu count in the machine configuration are allowed.
    The machine configuration has a default value, so all PUTs are updates.
    """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    response = test_microvm.api_session.put(
        test_microvm.net_cfg_url + '/1',
        json={
            'iface_id': '1',
            'host_dev_name': test_microvm.slot.make_tap(name='newtap'),
            'guest_mac': '06:00:00:00:00:01',
            'state': 'Attached'
        }
    )
    """ Valid updates to the network `host_dev_name` are allowed. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

def test_api_put_machine_config(test_microvm_any):
    """Tests various scenarios for PUT on /machine_config that cannot be covered by the unit tests"""

    """ Test invalid vcpu count < 0 """
    test_microvm = test_microvm_any
    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json = {'vcpu_count': '-2'}
    )
    assert response.status_code == 400

    """ Test invalid mem_size_mib < 0 """
    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json = {'mem_size_mib': '-2'}
    )
    assert response.status_code == 400

    """ Test invalid type for ht_enabled flag """
    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json = {'ht_enabled': 'random_string'}
    )
    assert response.status_code == 400

    """ Test invalid CPU template """
    response = test_microvm.api_session.put(
        test_microvm.microvm_cfg_url,
        json = {'cpu_template': 'random_string'}
    )
    assert response.status_code == 400

def test_api_put_update_post_boot(test_microvm_any):
    """ Tests that PUT updates are rejected after the microvm boots. """

    test_microvm = test_microvm_any

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
