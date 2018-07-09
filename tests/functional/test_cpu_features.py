import time

import pytest

from host_tools.network import SSHConnection


def check_cpu_topology(test_microvm, expected_cpu_topology):
    """
    Different topologies can be tested the same way once the microvm is
    started. This is a wrapper function for calling lscpu and checking if the
    command returns the expected cpu topology.
    """
    ssh_connection = SSHConnection(test_microvm.slot.ssh_config)

    # Execute the lscpu command to check the guest topology
    _, stdout, stderr = ssh_connection.execute_command("lscpu")
    assert (stderr.read().decode("utf-8") == '')
    # Read Line by line the stdout of lscpu to check the relevant information
    # regarding the CPU topology
    while True:
        line = stdout.readline()
        if line != '':
            [key, value] = list(map(lambda x: x.strip(), line.split(':')))
            if key in expected_cpu_topology.keys():
                assert value == expected_cpu_topology[key],\
                    "%s does not have the expected value" % key
        else:
            break

    ssh_connection.close()


@pytest.mark.timeout(500)
def test_2vcpu_ht_disabled(test_microvm_with_ssh):
    test_microvm = test_microvm_with_ssh

    api_responses = test_microvm.basic_config(
        vcpu_count=2,
        ht_enable=False,
        net_iface_count=0
    )
    """
    Sets up the microVM with 2 vCPUs, 256 MiB of RAM, 0 network ifaces and
    a root file system with the rw permission. The network interfaces is
    added after we get an unique MAC and IP.
    """
    for response in api_responses:
        assert (
            test_microvm.api_session.is_good_response(response.status_code))

    # Configure the tap device and add the network interface
    tap_name = test_microvm.slot.make_tap(ip="192.168.241.1/30")
    # We have to make sure that the microvm will be in the same
    # subnet as the tap device. The IP of the microvm is computed from the
    # mac address. To set the IP of the microvm to 192.168.241.2, we
    # need to set the mac to XX:XX:C0:A8:F1:02, where the first 2 bytes
    # are ignored and the next 4 bytes form the IP
    iface_id = "1"
    response = test_microvm.api_session.put(
        "{}/{}".format(test_microvm.net_cfg_url, iface_id),
        json={
            "iface_id": iface_id,
            "host_dev_name": tap_name,
            "guest_mac": "06:00:C0:A8:F1:02",
            "state": "Attached"
        }
    )
    assert (test_microvm.api_session.is_good_response(response.status_code))

    # we can now update the ssh_config dictionary with the IP of the VM
    test_microvm.slot.ssh_config['hostname'] = "192.168.241.2"

    # Start the microvm.
    response = test_microvm.api_session.put(
        test_microvm.actions_url + '/1',
        json={'action_id': '1', 'action_type': 'InstanceStart'}
    )
    assert(test_microvm.api_session.is_good_response(response.status_code))

    # Wait for the microvm to start.
    time.sleep(1)
    # Check that the Instance Start was successful
    response = test_microvm.api_session.get(test_microvm.actions_url + '/1')
    assert (test_microvm.api_session.is_good_response(response.status_code))

    expected_cpu_topology = {
        "CPU(s)": "2",
        "On-line CPU(s) list": "0,1",
        "Thread(s) per core": "1",
        "Core(s) per socket": "2",
        "Socket(s)": "1",
        "NUMA node(s)": "1"
    }
    check_cpu_topology(test_microvm, expected_cpu_topology)
