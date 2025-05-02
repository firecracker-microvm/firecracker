# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the net device."""

import re
import time

import pytest
from tenacity import Retrying, stop_after_attempt, wait_fixed

from framework import utils

# The iperf version to run this tests with
IPERF_BINARY_GUEST = "iperf3"
# We are using iperf3-vsock instead of a regular iperf3,
# because iperf3 3.16+ crashes on aarch64 sometimes
# when running this test.
IPERF_BINARY_HOST = "iperf3-vsock"


def test_high_ingress_traffic(uvm_plain_any):
    """
    Run iperf rx with high UDP traffic.
    """
    test_microvm = uvm_plain_any
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
    test_microvm.ssh.check_output("{} -sD\n".format(IPERF_BINARY_GUEST))
    time.sleep(1)

    # Start iperf3 client on the host. Send 1Gbps UDP traffic.
    # If the net device breaks, iperf will freeze, and we'll hit the pytest timeout
    utils.check_output(
        "{} {} -c {} -u -V -b 1000000000 -t 30".format(
            test_microvm.netns.cmd_prefix(),
            IPERF_BINARY_HOST,
            guest_ip,
        ),
    )

    # Check if the high ingress traffic broke the net interface.
    # If the net interface still works we should be able to execute
    # ssh commands.
    test_microvm.ssh.check_output("echo success\n")


def test_multi_queue_unsupported(uvm_plain):
    """
    Creates multi-queue tap device and tries to add it to firecracker.
    """
    microvm = uvm_plain
    microvm.spawn()
    microvm.basic_config()

    tapname = microvm.id[:8] + "tap1"

    utils.check_output(f"ip tuntap add name {tapname} mode tap multi_queue")
    utils.check_output(f"ip link set {tapname} netns {microvm.netns.id}")

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

    # clean TAP device
    utils.run_cmd(f"{microvm.netns.cmd_prefix()} ip link del name {tapname}")


@pytest.fixture
def uvm_any(microvm_factory, uvm_ctor, guest_kernel, rootfs):
    """Return booted and restored uvm with no CPU templates"""
    return uvm_ctor(microvm_factory, guest_kernel, rootfs, None)


def test_tap_offload(uvm_any):
    """
    Verify that tap offload features are configured for a booted/restored VM.

    - Start a socat UDP server in the guest.
    - Try to send a UDP message with UDP offload enabled.

    If tap offload features are not configured, an attempt to send a message will fail with EIO "Input/output error".
    More info (search for "TUN_F_CSUM is a must"): https://blog.cloudflare.com/fr-fr/virtual-networking-101-understanding-tap/
    """
    vm = uvm_any
    port = "81"
    out_filename = "/tmp/out.txt"
    message = "x"

    # Start a UDP server in the guest
    # vm.ssh.check_output(f"nohup socat UDP-LISTEN:{port} - > {out_filename} &")
    vm.ssh.check_output(
        f"nohup socat UDP4-LISTEN:{port} OPEN:{out_filename},creat > /dev/null 2>&1 &"
    )

    # Try to send a UDP message from host with UDP offload enabled
    vm.netns.check_output(f"python3 ./host_tools/udp_offload.py {vm.ssh.host} {port}")

    # Check that the server received the message
    # Allow for some delay due to the asynchronous nature of the test
    for attempt in Retrying(
        stop=stop_after_attempt(10),
        wait=wait_fixed(0.1),
        reraise=True,
    ):
        with attempt:
            ret = vm.ssh.check_output(f"sync; cat {out_filename}")
            assert ret.stdout == message, f"{ret.stdout=} {ret.stderr=}"
