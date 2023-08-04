# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the net device."""

import re
import time

import pytest

from framework import utils

# The iperf version to run this tests with
IPERF_BINARY = "iperf3"


def test_high_ingress_traffic(test_microvm_with_api):
    """
    Run iperf rx with high UDP traffic.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()

    # Create tap before configuring interface.
    test_microvm.add_net_iface()
    tap = test_microvm.iface["eth0"]["tap"]
    guest_ip = test_microvm.iface["eth0"]["iface"].guest_ip
    # Set the tap's tx queue len to 5. This increases the probability
    # of filling the tap under high ingress traffic.
    tap.set_tx_queue_len(5)

    # Start the microvm.
    test_microvm.start()

    # Start iperf3 server on the guest.
    test_microvm.ssh.run("{} -sD\n".format(IPERF_BINARY))
    time.sleep(1)

    # Start iperf3 client on the host. Send 1Gbps UDP traffic.
    # If the net device breaks, iperf will freeze. We have to use a timeout.
    utils.run_cmd(
        "timeout 30 {} {} -c {} -u -V -b 1000000000 -t 30".format(
            test_microvm.jailer.netns_cmd_prefix(),
            IPERF_BINARY,
            guest_ip,
        ),
        ignore_return_code=True,
    )

    # Check if the high ingress traffic broke the net interface.
    # If the net interface still works we should be able to execute
    # ssh commands.
    exit_code, _, _ = test_microvm.ssh.run("echo success\n")
    assert exit_code == 0


def test_multi_queue_unsupported(test_microvm_with_api):
    """
    Creates multi-queue tap device and tries to add it to firecracker.
    """
    microvm = test_microvm_with_api
    microvm.spawn()
    microvm.basic_config()

    tapname = microvm.id[:8] + "tap1"

    utils.run_cmd(f"ip tuntap add name {tapname} mode tap multi_queue")
    utils.run_cmd(f"ip link set {tapname} netns {microvm.jailer.netns}")

    expected_msg = re.escape(
        "Could not create the network device: Open tap device failed:"
        " Error while creating ifreq structure: Invalid argument (os error 22)."
        f" Invalid TUN/TAP Backend provided by {tapname}. Check our documentation on setting"
        " up the network devices."
    )

    with pytest.raises(RuntimeError, match=expected_msg):
        microvm.api.network.put(
            iface_id="eth0",
            host_dev_name=tapname,
            guest_mac="AA:FC:00:00:00:01",
        )
