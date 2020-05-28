# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the net device."""
import time

import framework.utils as utils
import host_tools.network as net_tools

# The iperf version to run this tests with
IPERF_BINARY = 'iperf3'


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
