"""Tests that verify MMDS related functionality."""

import host_tools.network as net_tools


def _assert_out(stdout, stderr, expected):
    assert stderr.read().decode('utf-8') == ''
    assert stdout.read().decode('utf-8') == expected


# Used when the output consists of a set of lines in no particular order, and
# thus may differ from one run to another.
def _assert_out_multiple(stdout, stderr, lines):
    assert stderr.read().decode('utf-8') == ''
    out = stdout.read().decode('utf-8')
    assert sorted(out.split('\n')) == sorted(lines)


def test_mmds(test_microvm_with_ssh, network_config):
    """Test the API and guest facing features of the Micro MetaData Service."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # The MMDS is empty at this point.
    response = test_microvm.mmds.get()
    assert response.status_code == 200
    assert response.json() == {}

    # Test that patch return NotFound when the MMDS is not initialized.
    dummy_json = {
        'latest': {
            'meta-data': {
                'ami-id': 'dummy'
            }
        }
    }
    response = test_microvm.mmds.patch(json=dummy_json)
    assert response.status_code == 404
    fault_json = {
        "fault_message": "The MMDS resource does not exist."
    }
    assert response.json() == fault_json

    # Test that using the same json with a PUT request, the MMDS data-store is
    # created.
    response = test_microvm.mmds.put(json=dummy_json)
    assert response.status_code == 201

    response = test_microvm.mmds.get()
    assert response.json() == dummy_json

    # PUT only allows full updates.
    # The json used in MMDS is based on the one from the Instance Meta-data
    # online documentation.
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/
    #                                                ec2-instance-metadata.html
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
    assert response.status_code == 204

    response = test_microvm.mmds.get()
    assert response.json() == data_store

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

    response = test_microvm.mmds.patch(json=patch_json)
    assert response.status_code == 204

    net_ifaces = data_store['latest']['meta-data']['network']['interfaces']
    net_ifaces['macs']['02:29:96:8f:6a:2d']['subnet-id'] = 'subnet-12345'
    response = test_microvm.mmds.get()
    assert response.json() == data_store

    # Now we start the guest and attempt to read some MMDS contents.

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, no network ifaces, and
    # a root file system with the rw permission. The network interface is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config(vcpu_count=1)
    _tap = test_microvm.ssh_network_config(
        network_config,
        '1',
        allow_mmds_requests=True
    )

    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Adding a route like this also tests the ARP implementation within the
    # MMDS. We hard code the interface name to `eth0`. The naming is unlikely
    # to change, especially while we keep using VIRTIO net. At some point we
    # could add some functionality to retrieve the interface name based on the
    # MAC address (which we already know) or smt.
    cmd = 'ip route add 169.254.169.254 dev eth0'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    pre = 'curl -s http://169.254.169.254/'

    cmd = pre + 'latest/meta-data/ami-id'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, 'ami-12345678')

    # The request is still valid if we append a trailing slash to a leaf node.
    cmd = pre + 'latest/meta-data/ami-id/'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, 'ami-12345678')

    cmd = pre + 'latest/meta-data/network/interfaces/macs/'\
        '02:29:96:8f:6a:2d/subnet-id'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, 'subnet-12345')

    # Test reading a non-leaf node WITHOUT a trailing slash.
    cmd = pre + 'latest/meta-data'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out(stdout, stderr, '')

    # Test reading a non-leaf node with a trailing slash.
    cmd = pre + 'latest/meta-data/'
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    _assert_out_multiple(
        stdout,
        stderr,
        ['ami-id', 'reservation-id', 'local-hostname', 'public-hostname',
         'network/']
    )
