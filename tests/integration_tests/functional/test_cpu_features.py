# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CPU topology emulation feature."""

import re

import host_tools.network as net_tools  # pylint: disable=import-error


def test_1vcpu(test_microvm_with_ssh, network_config):
    """Test CPU feature emulation with 1 vCPU."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, no network ifaces, and
    # a root file system with the rw permission. The network interfaces is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config(vcpu_count=1)

    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
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
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM, 0 network ifaces, and
    # a root file system with the rw permission. The network interfaces is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config(vcpu_count=2, ht_enabled=False)

    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')

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
    """Perform common microvm setup for different CPU topology tests.

    This is a wrapper function for calling lscpu and checking if the
    command returns the expected cpu topology.
    """
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Execute the lscpu command to check the guest topology
    _, stdout, stderr = ssh_connection.execute_command("lscpu")
    assert stderr.read().decode("utf-8") == ''
    # Read the stdout of lscpu line by line to check the relevant information.
    while True:
        line = stdout.readline().decode('utf-8')
        if line != '':
            [key, value] = list(map(lambda x: x.strip(), line.split(':')))
            if key in expected_cpu_topology.keys():
                assert value == expected_cpu_topology[key],\
                    "%s does not have the expected value" % key
        else:
            break


def test_brand_string(test_microvm_with_ssh, network_config):
    """Ensure good formatting for the guest band string.

    * For Intel CPUs, the guest brand string should be:
        Intel(R) Xeon(R) Processor @ {host frequency}
    where {host frequency} is the frequency reported by the host CPUID
    (e.g. 4.01GHz)
    * For non-Intel CPUs, the guest brand string should be:
        Intel(R) Xeon(R) Processor
    """
    cif = open('/proc/cpuinfo', 'r')
    host_brand_string = None
    while True:
        line = cif.readline()
        if line == '':
            break
        mo = re.search("^model name\\s+:\\s+(.+)$", line)
        if mo:
            host_brand_string = mo.group(1)
            break
    cif.close()
    assert host_brand_string is not None

    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    test_microvm.basic_config(vcpu_count=1)
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    guest_cmd = "cat /proc/cpuinfo | grep 'model name' | head -1"
    _, stdout, stderr = ssh_connection.execute_command(guest_cmd)
    assert stderr.read().decode("utf-8") == ''

    line = stdout.readline().decode('utf-8').rstrip()
    mo = re.search("^model name\\s+:\\s+(.+)$", line)
    assert mo
    guest_brand_string = mo.group(1)
    assert guest_brand_string

    expected_guest_brand_string = "Intel(R) Xeon(R) Processor"
    if host_brand_string.startswith("Intel"):
        mo = re.search("[.0-9]+[MG]Hz", host_brand_string)
        if mo:
            expected_guest_brand_string += " @ " + mo.group(0)

    assert guest_brand_string == expected_guest_brand_string
