# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify MMDS related functionality."""

import json
import random
import string
import time
import pytest
from framework.artifacts import DEFAULT_DEV_NAME, NetIfaceConfig
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.utils import generate_mmds_session_token, \
    generate_mmds_v2_get_request

import host_tools.network as net_tools

# Minimum lifetime of token.
MIN_TOKEN_TTL_SECONDS = 1
# Maximum lifetime of token.
MAX_TOKEN_TTL_SECONDS = 21600
# Default IPv4 value for MMDS.
DEFAULT_IPV4 = '169.254.169.254'
# MMDS versions supported.
MMDS_VERSIONS = ['V2', 'V1']


def _assert_out(stdout, stderr, expected):
    assert stderr.read() == ''
    assert stdout.read() == expected


def _populate_data_store(test_microvm, data_store):
    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == {}

    response = test_microvm.mmds.put(json=data_store)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == data_store


def _configure_mmds(test_microvm, iface_id, version, ipv4_address=None):
    mmds_config = {
        'version': version,
        'network_interfaces': [iface_id]
    }

    if ipv4_address:
        mmds_config['ipv4_address'] = ipv4_address

    response = test_microvm.mmds.put_config(json=mmds_config)
    assert test_microvm.api_session.is_status_no_content(response.status_code)


@pytest.mark.parametrize(
    "version",
    MMDS_VERSIONS
)
def test_custom_ipv4(test_microvm_with_api, network_config, version):
    """
    Test the API for MMDS custom ipv4 support.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

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
    _populate_data_store(test_microvm, data_store)

    # Attach network device.
    _tap = test_microvm.ssh_network_config(network_config, '1')

    # Invalid values IPv4 address.
    response = test_microvm.mmds.put_config(json={
        'ipv4_address': '',
        'network_interfaces': ['1']
    })
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    response = test_microvm.mmds.put_config(json={
        'ipv4_address': '1.1.1.1',
        'network_interfaces': ['1']
    })
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    ipv4_address = '169.254.169.250'
    # Configure MMDS with custom IPv4 address.
    _configure_mmds(
        test_microvm,
        iface_id='1',
        version=version,
        ipv4_address=ipv4_address
    )

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    cmd = 'ip route add {} dev eth0'.format(ipv4_address)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    if version == 'V2':
        # Generate token.
        token = generate_mmds_session_token(
            ssh_connection,
            ipv4_address=ipv4_address,
            token_ttl=60
        )

        pre = generate_mmds_v2_get_request(
            ipv4_address=ipv4_address,
            token=token
        )
    else:
        pre = 'curl -s -H "Accept: application/json" ' \
                'http://{}/'.format(ipv4_address)

    cmd = pre + 'latest/meta-data/ami-id'
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == 'ami-12345678'

    # The request is still valid if we append a
    # trailing slash to a leaf node.
    cmd = pre + 'latest/meta-data/ami-id/'
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == 'ami-12345678'

    cmd = pre + 'latest/meta-data/network/interfaces/macs/' \
                '02:29:96:8f:6a:2d/subnet-id'
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == 'subnet-be9b61d'

    # Test reading a non-leaf node WITHOUT a trailing slash.
    cmd = pre + 'latest/meta-data'
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == data_store['latest']['meta-data']

    # Test reading a non-leaf node with a trailing slash.
    cmd = pre + 'latest/meta-data/'
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == data_store['latest']['meta-data']


@pytest.mark.parametrize(
    "version",
    MMDS_VERSIONS
)
def test_json_response(test_microvm_with_api, network_config, version):
    """
    Test the MMDS json response.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    data_store = {
        'latest': {
            'meta-data': {
                'ami-id': 'ami-12345678',
                'reservation-id': 'r-fea54097',
                'local-hostname': 'ip-10-251-50-12.ec2.internal',
                'public-hostname': 'ec2-203-0-113-25.compute-1.amazonaws.com',
                'dummy_res': ['res1', 'res2']
            },
            "Limits": {
                "CPU": 512,
                "Memory": 512
            },
            "Usage": {
                "CPU": 12.12
            }
        }
    }

    # Attach network device.
    _tap = test_microvm.ssh_network_config(network_config, '1')

    # Configure MMDS version.
    _configure_mmds(test_microvm, iface_id='1', version=version)

    # Populate data store with contents.
    _populate_data_store(test_microvm, data_store)

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    cmd = 'ip route add {} dev eth0'.format(DEFAULT_IPV4)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    if version == 'V2':
        # Generate token.
        token = generate_mmds_session_token(
                ssh_connection,
                ipv4_address=DEFAULT_IPV4,
                token_ttl=60
        )

        pre = generate_mmds_v2_get_request(DEFAULT_IPV4, token)
    else:
        pre = 'curl -s -H "Accept: application/json"' \
                ' http://{}/'.format(DEFAULT_IPV4)

    cmd = pre + 'latest/meta-data/'
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == data_store['latest']['meta-data']

    cmd = pre + 'latest/meta-data/ami-id/'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == 'ami-12345678'

    cmd = pre + 'latest/meta-data/dummy_res/0'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == 'res1'

    cmd = pre + 'latest/Usage/CPU'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == 12.12

    cmd = pre + 'latest/Limits/CPU'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == 512


@pytest.mark.parametrize(
    "version",
    MMDS_VERSIONS
)
def test_mmds_response(test_microvm_with_api, network_config, version):
    """
    Test MMDS responses to various datastore requests.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    data_store = {
        'latest': {
            'meta-data': {
                'ami-id': 'ami-12345678',
                'reservation-id': 'r-fea54097',
                'local-hostname': 'ip-10-251-50-12.ec2.internal',
                'public-hostname': 'ec2-203-0-113-25.compute-1.amazonaws.com',
                'dummy_obj': {
                    'res_key': 'res_value',
                },
                'dummy_array': [
                    'arr_val1',
                    'arr_val2'
                ]
            },
            "Limits": {
                "CPU": 512,
                "Memory": 512
            },
            "Usage": {
                "CPU": 12.12
            }
        }
    }

    # Attach network device.
    _tap = test_microvm.ssh_network_config(network_config, '1')

    # Configure MMDS version.
    _configure_mmds(test_microvm, iface_id='1', version=version)
    # Populate data store with contents.
    _populate_data_store(test_microvm, data_store)

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    cmd = 'ip route add {} dev eth0'.format(DEFAULT_IPV4)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    if version == 'V2':
        # Generate token.
        token = generate_mmds_session_token(
            ssh_connection,
            ipv4_address=DEFAULT_IPV4,
            token_ttl=60
        )

        pre = generate_mmds_v2_get_request(
            ipv4_address=DEFAULT_IPV4,
            token=token,
            app_json=False
        )
    else:
        pre = 'curl -s http://{}/'.format(DEFAULT_IPV4)

    cmd = pre + 'latest/meta-data/'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    expected = "ami-id\n" \
               "dummy_array\n" \
               "dummy_obj/\n" \
               "local-hostname\n" \
               "public-hostname\n" \
               "reservation-id"

    _assert_out(stdout, stderr, expected)

    cmd = pre + 'latest/meta-data/ami-id/'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, 'ami-12345678')

    cmd = pre + 'latest/meta-data/dummy_array/0'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, 'arr_val1')

    cmd = pre + 'latest/Usage/CPU'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, 'Cannot retrieve value. The value has an'
                                ' unsupported type.')

    cmd = pre + 'latest/Limits/CPU'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, 'Cannot retrieve value. The value has an'
                                ' unsupported type.')


@pytest.mark.parametrize(
    "version",
    MMDS_VERSIONS
)
def test_larger_than_mss_payloads(
        test_microvm_with_api,
        network_config,
        version):
    """
    Test MMDS content for payloads larger than MSS.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Attach network device.
    _tap = test_microvm.ssh_network_config(network_config, '1')
    # Configure MMDS version.
    _configure_mmds(test_microvm, iface_id='1', version=version)

    # The MMDS is empty at this point.
    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == {}

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()

    # Make sure MTU is 1500 bytes.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    cmd = 'ip link set dev eth0 mtu 1500'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, "")

    cmd = 'ip a s eth0 | grep -i mtu | tr -s " " | cut -d " " -f 4,5'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, "mtu 1500\n")

    # These values are usually used by booted up guest network interfaces.
    mtu = 1500
    ipv4_packet_headers_len = 20
    tcp_segment_headers_len = 20
    mss = mtu - ipv4_packet_headers_len - tcp_segment_headers_len

    # Generate a random MMDS content, double of MSS.
    letters = string.ascii_lowercase
    larger_than_mss = ''.join(random.choice(letters) for i in range(2 * mss))
    mss_equal = ''.join(random.choice(letters) for i in range(mss))
    lower_than_mss = ''.join(random.choice(letters) for i in range(mss - 2))
    data_store = {
        'larger_than_mss': larger_than_mss,
        'mss_equal': mss_equal,
        'lower_than_mss': lower_than_mss
    }
    response = test_microvm.mmds.put(json=data_store)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == data_store

    cmd = 'ip route add {} dev eth0'.format(DEFAULT_IPV4)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    if version == 'V2':
        # Generate token.
        token = generate_mmds_session_token(
            ssh_connection,
            ipv4_address=DEFAULT_IPV4,
            token_ttl=60
        )

        pre = generate_mmds_v2_get_request(
            ipv4_address=DEFAULT_IPV4,
            token=token,
            app_json=False
        )
    else:
        pre = 'curl -s http://{}/'.format(DEFAULT_IPV4)

    cmd = pre + 'larger_than_mss'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, larger_than_mss)

    cmd = pre + 'mss_equal'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, mss_equal)

    cmd = pre + 'lower_than_mss'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, lower_than_mss)


@pytest.mark.parametrize(
    "version",
    MMDS_VERSIONS
)
def test_mmds_dummy(test_microvm_with_api, network_config, version):
    """
    Test the API and guest facing features of the microVM MetaData Service.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Attach network device.
    _tap = test_microvm.ssh_network_config(network_config, '1')
    # Configure MMDS version.
    _configure_mmds(test_microvm, iface_id='1', version=version)

    # The MMDS is empty at this point.
    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == {}

    # Test that patch return NotInitialized when the MMDS is not initialized.
    dummy_json = {
        'latest': {
            'meta-data': {
                'ami-id': 'dummy'
            }
        }
    }
    response = test_microvm.mmds.patch(json=dummy_json)
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    fault_json = {
        "fault_message": "The MMDS data store is not initialized."
    }
    assert response.json() == fault_json

    # Test that using the same json with a PUT request, the MMDS data-store is
    # created.
    response = test_microvm.mmds.put(json=dummy_json)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == dummy_json

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == dummy_json

    dummy_json = {
        'latest': {
            'meta-data': {
                'ami-id': 'another_dummy',
                'secret_key': 'eaasda48141411aeaeae'
            }
        }
    }
    response = test_microvm.mmds.patch(json=dummy_json)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == dummy_json


@pytest.mark.parametrize(
    "version",
    MMDS_VERSIONS
)
def test_guest_mmds_hang(test_microvm_with_api, network_config, version):
    """
    Test the MMDS json endpoint when Content-Length larger than actual length.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Attach network device.
    _tap = test_microvm.ssh_network_config(network_config, '1')
    # Configure MMDS version.
    _configure_mmds(test_microvm, iface_id='1', version=version)

    data_store = {
        'latest': {
            'meta-data': {
                'ami-id': 'ami-12345678'
            }
        }
    }
    _populate_data_store(test_microvm, data_store)

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    cmd = 'ip route add {} dev eth0'.format(DEFAULT_IPV4)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    get_cmd = 'curl -m 2 -s'
    get_cmd += ' -X GET'
    get_cmd += ' -H  "Content-Length: 100"'
    get_cmd += ' -H "Accept: application/json"'
    get_cmd += ' -d "some body"'
    get_cmd += ' http://{}/'.format(DEFAULT_IPV4)

    if version == 'V1':
        _, stdout, _ = ssh_connection.execute_command(get_cmd)
        assert 'Invalid request' in stdout.read()
    else:
        # Generate token.
        token = generate_mmds_session_token(
            ssh_connection,
            ipv4_address=DEFAULT_IPV4,
            token_ttl=60
        )

        get_cmd += ' -H  "X-metadata-token: {}"'.format(token)
        _, stdout, _ = ssh_connection.execute_command(get_cmd)
        assert 'Invalid request' in stdout.read()

        # Do the same for a PUT request.
        cmd = 'curl -m 2 -s'
        cmd += ' -X PUT'
        cmd += ' -H  "Content-Length: 100"'
        cmd += ' -H  "X-metadata-token: {}"'.format(token)
        cmd += ' -H "Accept: application/json"'
        cmd += ' -d "some body"'
        cmd += ' http://{}/'.format(DEFAULT_IPV4)

        _, stdout, _ = ssh_connection.execute_command(cmd)
        assert 'Invalid request' in stdout.read()


@pytest.mark.parametrize(
    "version",
    MMDS_VERSIONS
)
def test_patch_dos_scenario(test_microvm_with_api, network_config, version):
    """
    Test the MMDS json endpoint when data store size reaches the limit.

    @type: negative
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Attach network device.
    _tap = test_microvm.ssh_network_config(network_config, '1')
    # Configure MMDS version.
    _configure_mmds(test_microvm, iface_id='1', version=version)

    dummy_json = {
        'latest': {
            'meta-data': {
                'ami-id': 'dummy'
            }
        }
    }

    # Populate data-store.
    response = test_microvm.mmds.put(json=dummy_json)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Send a request that will fill the data store.
    aux = "a" * 51137
    dummy_json = {
        'latest': {
            'meta-data': {
                'ami-id': "smth",
                'secret_key': aux
            }
        }
    }
    response = test_microvm.mmds.patch(json=dummy_json)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Try to send a new patch thaw will increase the data store size. Since the
    # actual size is equal with the limit this request should fail with
    # PayloadTooLarge.
    aux = "b" * 10
    dummy_json = {
        'latest': {
            'meta-data': {
                'ami-id': "smth",
                'secret_key2': aux
            }
        }
    }
    response = test_microvm.mmds.patch(json=dummy_json)
    assert test_microvm.api_session.\
        is_status_payload_too_large(response.status_code)
    # Check that the patch actually failed and the contents of the data store
    # has not changed.
    response = test_microvm.mmds.get()
    assert str(response.json()).find(aux) == -1

    # Delete something from the mmds so we will be able to send new data.
    dummy_json = {
        'latest': {
            'meta-data': {
                'ami-id': "smth",
                'secret_key': "a"
            }
        }
    }
    response = test_microvm.mmds.patch(json=dummy_json)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Check that the size has shrunk.
    response = test_microvm.mmds.get()
    assert len(str(response.json()).replace(" ", "")) == 59

    # Try to send a new patch, this time the request should succeed.
    aux = "a" * 100
    dummy_json = {
        'latest': {
            'meta-data': {
                'ami-id': "smth",
                'secret_key': aux
            }
        }
    }
    response = test_microvm.mmds.patch(json=dummy_json)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Check that the size grew as expected.
    response = test_microvm.mmds.get()
    assert len(str(response.json()).replace(" ", "")) == 158


def test_mmds_snapshot(bin_cloner_path):
    """
    Exercise MMDS behavior with snapshots.

    Ensures that MMDS V2 behavior is not affected by taking a snapshot
    and that MMDS V2 is not available after snapshot load.

    @type: functional
    """
    vm_builder = MicrovmBuilder(bin_cloner_path)
    net_iface = NetIfaceConfig()
    vm_instance = vm_builder.build_vm_nano(
        net_ifaces=[net_iface],
        diff_snapshots=True
    )
    test_microvm = vm_instance.vm
    root_disk = vm_instance.disks[0]
    ssh_key = vm_instance.ssh_key

    ipv4_address = '169.254.169.250'
    # Configure MMDS version with custom IPv4 address.
    _configure_mmds(
        test_microvm,
        version='V2',
        iface_id=DEFAULT_DEV_NAME,
        ipv4_address=ipv4_address
    )

    data_store = {
        'latest': {
            'meta-data': {
                'ami-id': 'ami-12345678'
            }
        }
    }
    _populate_data_store(test_microvm, data_store)

    test_microvm.start()

    snapshot_builder = SnapshotBuilder(test_microvm)
    disks = [root_disk.local_path()]

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    cmd = 'ip route add {} dev eth0'.format(ipv4_address)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    # Generate token.
    token = generate_mmds_session_token(
        ssh_connection,
        ipv4_address=ipv4_address,
        token_ttl=60
    )

    pre = 'curl -m 2 -s'
    pre += ' -X GET'
    pre += ' -H  "X-metadata-token: {}"'.format(token)
    pre += ' http://{}/'.format(ipv4_address)

    # Fetch metadata.
    cmd = pre + 'latest/meta-data/'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, "ami-id")

    # Create diff snapshot.
    snapshot = snapshot_builder.create(disks,
                                       ssh_key,
                                       SnapshotType.DIFF)

    # Resume microVM and ensure session token is still valid on the base.
    response = test_microvm.vm.patch(state='Resumed')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    _, stdout, stderr = ssh_connection.execute_command(
        pre + 'latest/meta-data/'
    )
    _assert_out(stdout, stderr, "ami-id")

    # Kill base microVM.
    test_microvm.kill()

    # Load microVM clone from snapshot.
    test_microvm, _ = vm_builder.build_from_snapshot(snapshot,
                                                     resume=True,
                                                     diff_snapshots=True)
    _populate_data_store(test_microvm, data_store)
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Mmds V2 is not available with snapshots.
    # Test that `PUT` requests are not allowed.
    cmd = 'curl -m 2 -s'
    cmd += ' -X PUT'
    cmd += ' -H  "X-metadata-token-ttl-seconds: 1"'
    cmd += ' http://{}/latest/api/token'.format(ipv4_address)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    expected = "Not allowed HTTP method."
    _assert_out(stdout, stderr, expected)

    # Fetch metadata using V1 requests and ensure IPv4 configuration
    # is persistent between snapshots.
    cmd = 'curl -s http://{}/latest/meta-data/ami-id/'.format(ipv4_address)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, 'ami-12345678')


def test_mmds_v2_negative(test_microvm_with_api, network_config):
    """
    Test invalid MMDS GET/PUT requests when using V2.

    @type: negative
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Attach network device.
    _tap = test_microvm.ssh_network_config(network_config, '1')
    # Configure MMDS version.
    _configure_mmds(test_microvm, version='V2', iface_id='1')

    data_store = {
        'latest': {
            'meta-data': {
                'ami-id': 'ami-12345678',
                'reservation-id': 'r-fea54097',
                'local-hostname': 'ip-10-251-50-12.ec2.internal',
                'public-hostname': 'ec2-203-0-113-25.compute-1.amazonaws.com'
            }
        }
    }
    _populate_data_store(test_microvm, data_store)

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    cmd = 'ip route add 169.254.169.254 dev eth0'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    # Check `GET` request fails when token is not provided.
    cmd = 'curl -s http://169.254.169.254/latest/meta-data/'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    expected = "No MMDS token provided. Use `X-metadata-token` header " \
               "to specify the session token."
    _assert_out(stdout, stderr, expected)

    # Generic `GET` request.
    get_cmd = 'curl -m 2 -s'
    get_cmd += ' -X GET'
    get_cmd += ' -H  "X-metadata-token: {}"'
    get_cmd += ' http://169.254.169.254/latest/meta-data'

    # Check `GET` request fails when token is not valid.
    _, stdout, stderr = ssh_connection.execute_command(get_cmd.format("foo"))
    _assert_out(stdout, stderr, "MMDS token not valid.")

    # Check `PUT` request fails when token TTL is not provided.
    _, stdout, stderr = ssh_connection.execute_command(
        'curl -m 2 -s -X PUT http://169.254.169.254/latest/api/token'
    )
    expected = "Token time to live value not found. Use " \
               "`X-metadata-token-ttl_seconds` header to specify " \
               "the token's lifetime."
    _assert_out(stdout, stderr, expected)

    # Check `PUT` request fails when `X-Forwarded-For` header is provided.
    cmd = 'curl -m 2 -s'
    cmd += ' -X PUT'
    cmd += ' -H  "X-Forwarded-For: foo"'
    cmd += ' http://169.254.169.254'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    expected = "Invalid header. Reason: Unsupported header name. " \
               "Key: X-Forwarded-For"
    _assert_out(stdout, stderr, expected)

    # Generic `PUT` request.
    put_cmd = 'curl -m 2 -s'
    put_cmd += ' -X PUT'
    put_cmd += ' -H  "X-metadata-token-ttl-seconds: {}"'
    put_cmd += ' http://169.254.169.254/latest/api/token'

    # Check `PUT` request fails when path is invalid.
    # Path is invalid because we remove the last character
    # at the end of the valid uri.
    _, stdout, stderr = ssh_connection.execute_command(put_cmd[:-1].format(60))
    _assert_out(stdout, stderr, "Resource not found: /latest/api/toke.")

    # Check `PUT` request fails when token TTL is not valid.
    ttl_values = [MIN_TOKEN_TTL_SECONDS - 1, MAX_TOKEN_TTL_SECONDS + 1]
    for ttl in ttl_values:
        _, stdout, stderr = ssh_connection.execute_command(put_cmd.format(ttl))
        expected = "Invalid time to live value provided for token: {}. " \
                   "Please provide a value between {} and {}." \
            .format(ttl, MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS)
        _assert_out(stdout, stderr, expected)

    # Valid `PUT` request to generate token.
    _, stdout, stderr = ssh_connection.execute_command(put_cmd.format(1))
    token = stdout.read()
    assert len(token) > 0

    # Wait for token to expire.
    time.sleep(1)
    # Check `GET` request fails when expired token is provided.
    _, stdout, stderr = ssh_connection.execute_command(get_cmd.format(token))
    _assert_out(stdout, stderr, "MMDS token not valid.")
