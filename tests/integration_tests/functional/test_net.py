# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the net device."""
import time

from framework import decorators
from framework.microvm import Serial

import framework.utils as utils
import host_tools.network as net_tools

# The iperf version to run this tests with
IPERF_BINARY = 'iperf3'
NO_OF_VMS = 2


def test_high_ingress_traffic(test_microvm_with_ssh, network_config):
    """Run iperf rx with high UDP traffic."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    test_microvm.basic_config()

    # Create tap before configuring interface.
    tap, _host_ip, guest_ip = test_microvm.ssh_network_config(
        network_config,
        '1'
    )
    # Set the tap's tx queue len to 5. This increases the probability
    # of filling the tap under high ingress traffic.
    tap.set_tx_queue_len(5)

    # Start the microvm.
    test_microvm.start()

    # Start iperf3 server on the guest.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    ssh_connection.execute_command('{} -sD\n'.format(IPERF_BINARY))
    time.sleep(1)

    # Start iperf3 client on the host. Send 1Gbps UDP traffic.
    # If the net device breaks, iperf will freeze. We have to use a timeout.
    utils.run_cmd(
        'timeout 30 {} {} -c {} -u -V -b 1000000000 -t 30'.format(
            test_microvm.jailer.netns_cmd_prefix(),
            IPERF_BINARY,
            guest_ip,
        ),
        ignore_return_code=True
    )

    # Check if the high ingress traffic broke the net interface.
    # If the net interface still works we should be able to execute
    # ssh commands.
    exit_code, _, _ = ssh_connection.execute_command('echo success\n')
    assert exit_code == 0


@decorators.test_context('ssh_and_balloon', NO_OF_VMS)
def test_macvtaps(test_multiple_microvms):
    """Check the MacVTap functionality."""
    microvms = test_multiple_microvms
    # Creating a bridge for the macvtap interfaces.
    bridge = net_tools.Bridge("dummy_bridge")

    try:
        _test_macvtaps(microvms, bridge)
    except Exception as err:
        bridge.__del__()
        raise Exception from err


def _test_macvtaps(microvms, bridge):
    # We create an aux function for being able to delete the
    # bridge in case any error is returned by this function.
    for i in range(NO_OF_VMS):
        microvm = microvms[i]
        # We need to add the network namespace before the jailer.setup()
        # does cause we need to add the interfaces beforehand.
        utils.run_cmd('ip netns add {}'.format(microvm.jailer.netns))
        _configure_and_run(microvm, bridge, str(i))

    # We now try to test that the 2 microVMs we configured can indeed
    # talk through the macvtaps that we set up.
    # We use the serial for that since we did not establish a connection
    # between the guests and the host.
    for i in range(NO_OF_VMS):
        serial = Serial(microvms[i])
        serial.open()
        serial.rx(token='login: ')
        serial.tx("root")

        serial.rx(token='Password: ')
        serial.tx("root")

        serial.rx(token='# ')
        ip = "172.16.0.{}".format(str(i+2))
        serial.tx("ip addr add {}/24 dev eth0".format(ip))
        if i == 1:
            serial.tx("ping -c 2 172.16.0.2")
            serial.rx("2 received")


def _configure_and_run(microvm, bridge, iface_id):
    """Auxiliary function for configuring and running a microVM."""
    microvm.jailer.daemonize = False

    vtap_name = "macvtap{}".format(iface_id)
    microvm.jailer.macvtaps = [vtap_name]
    guest_mac = bridge.add_macvtap(vtap_name, microvm.jailer.netns)
    microvm.spawn(create_netns=False)

    microvm.basic_config(
        boot_args='console=ttyS0 reboot=k panic=1 pci=off',
    )
    microvm.put_network(iface_id, vtap_name, guest_mac)

    microvm.start()
