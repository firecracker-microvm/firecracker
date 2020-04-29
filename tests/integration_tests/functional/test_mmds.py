# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify MMDS related functionality."""

import json
import host_tools.network as net_tools


def _assert_out(stdout, stderr, expected):
    assert stderr.read() == ''
    assert stdout.read() == expected


def test_custom_ipv4(test_microvm_with_ssh, network_config):
    """Test the API for MMDS custom ipv4 support."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == {}

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
    response = test_microvm.mmds.put(json=data_store)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == data_store

    config_data = {
        'ipv4_address': ''
    }
    response = test_microvm.mmds.put_config(json=config_data)
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    config_data = {
        'ipv4_address': '1.1.1.1'
    }
    response = test_microvm.mmds.put_config(json=config_data)
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    config_data = {
        'ipv4_address': '169.254.169.250'
    }
    response = test_microvm.mmds.put_config(json=config_data)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.basic_config(vcpu_count=1)
    _tap = test_microvm.ssh_network_config(
         network_config,
         '1',
         allow_mmds_requests=True
    )

    test_microvm.start()
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    response = test_microvm.mmds.put_config(json=config_data)
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    cmd = 'ip route add 169.254.169.250 dev eth0'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    pre = 'curl -s -H "Accept: application/json" http://169.254.169.250/'

    cmd = pre + 'latest/meta-data/ami-id'
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == 'ami-12345678'

    # The request is still valid if we append a
    # trailing slash to a leaf node.
    cmd = pre + 'latest/meta-data/ami-id/'
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == 'ami-12345678'

    cmd = pre + 'latest/meta-data/network/interfaces/macs/'\
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


def test_json_response(test_microvm_with_ssh, network_config):
    """Test the MMDS json response."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == {}

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
    response = test_microvm.mmds.put(json=data_store)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == data_store

    test_microvm.basic_config(vcpu_count=1)
    _tap = test_microvm.ssh_network_config(
         network_config,
         '1',
         allow_mmds_requests=True
    )

    test_microvm.start()
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    cmd = 'ip route add 169.254.169.254 dev eth0'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    pre = 'curl -s -H "Accept: application/json" http://169.254.169.254/'

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


def test_imds_response(test_microvm_with_ssh, network_config):
    """Test the MMDS IMDS response."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == {}

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
    response = test_microvm.mmds.put(json=data_store)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == data_store

    test_microvm.basic_config(vcpu_count=1)
    _tap = test_microvm.ssh_network_config(
        network_config,
        '1',
        allow_mmds_requests=True
    )

    test_microvm.start()
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    cmd = 'ip route add 169.254.169.254 dev eth0'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    pre = 'curl -s http://169.254.169.254/'

    cmd = pre + 'latest/meta-data/'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    expected = "ami-id\n" \
               "dummy_array\n"\
               "dummy_obj/\n"\
               "local-hostname\n"\
               "public-hostname\n"\
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


def test_mmds_dummy(test_microvm_with_ssh):
    """Test the API and guest facing features of the Micro MetaData Service."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

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
