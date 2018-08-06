"""Tests for the CPU topology emulation feature."""

import host_tools.network as host  # pylint: disable=import-error


def test_1vcpu(test_microvm_with_ssh, network_config):
    """Test CPU feature emulation with 1 vCPU."""

    test_microvm = test_microvm_with_ssh

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces, and
    # a root file system with the rw permission. The network interfaces is
    # added after we get an unique MAC and IP.
    test_microvm.basic_config(vcpu_count=1, net_iface_count=0)

    test_microvm.basic_network_config(network_config)

    test_microvm.start()

    expected_cpu_topology = {
        "CPU(s)": "1",
        "On-line CPU(s) list": "0",
        "Thread(s) per core": "1",
        "Core(s) per socket": "1",
        "Socket(s)": "1",
        "NUMA node(s)": "1"
    }
    _check_cpu_topology(test_microvm, expected_cpu_topology)


def test_2vcpu_ht_disabled(test_microvm_with_ssh, network_config):
    """Test CPU feature emulation with 2 vCPUs, and no hyperthreading."""

    test_microvm = test_microvm_with_ssh

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM, 0 network ifaces, and
    # a root file system with the rw permission. The network interfaces is
    # added after we get an unique MAC and IP.
    test_microvm.basic_config(vcpu_count=2, ht_enable=False, net_iface_count=0)

    test_microvm.basic_network_config(network_config)

    test_microvm.start()

    expected_cpu_topology = {
        "CPU(s)": "2",
        "On-line CPU(s) list": "0,1",
        "Thread(s) per core": "1",
        "Core(s) per socket": "2",
        "Socket(s)": "1",
        "NUMA node(s)": "1"
    }
    _check_cpu_topology(test_microvm, expected_cpu_topology)


def _check_cpu_topology(test_microvm, expected_cpu_topology):
    """"Perform common microvm setup for different CPU topology tests.

    This is a wrapper function for calling lscpu and checking if the
    command returns the expected cpu topology.
    """
    ssh_connection = host.SSHConnection(test_microvm.slot.ssh_config)

    # Execute the lscpu command to check the guest topology
    _, stdout, stderr = ssh_connection.execute_command("lscpu")
    assert stderr.read().decode("utf-8") == ''
    # Read the stdout of lscpu line by line to check the relevant information.
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
