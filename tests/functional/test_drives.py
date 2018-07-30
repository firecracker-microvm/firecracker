"""
Tests that ensure the correctness of operations on /drives resources from the
guest side.
"""

from host_tools.network import SSHConnection


def test_rescan(test_microvm_with_ssh, network_config):
    """
    Tests that triggering a block device rescan makes the guest pick up any
    changes to the block device's size.
    """

    test_microvm = test_microvm_with_ssh

    test_microvm.basic_config(net_iface_count=0)
    """
    Sets up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    a root file system with the rw permission. The network interface is
    added after we get an unique MAC and IP.
    """
    test_microvm.basic_network_config(network_config)

    """ Adds a scratch block device. """
    test_microvm.put_default_scratch_device()

    test_microvm.start()

    ssh_connection = SSHConnection(test_microvm.slot.ssh_config)

    _check_scratch_size(ssh_connection, test_microvm.slot.sizeof_fsfile('scratch'))

    test_microvm.slot.resize_fsfile('scratch', 512)
    """ Resizes the filesystem file from 256 MiB (default) to 512 MiB."""

    response = test_microvm.api_session.put(
        test_microvm.actions_url,
        json={
            'action_type': 'BlockDeviceRescan',
            'payload': 'scratch',
        }
    )
    """ Rescan operations after the guest boots are allowed. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    _check_scratch_size(ssh_connection, test_microvm.slot.sizeof_fsfile('scratch'))

    ssh_connection.close()


def _check_scratch_size(ssh_connection, size):
    _, stdout, stderr = ssh_connection.execute_command(
        "blockdev --getsize64 /dev/vdb"
    )
    """ The scratch block device is /dev/vdb in the guest. """
    assert(stderr.read().decode("utf-8") == '')
    assert(stdout.readline().strip() == str(size))
