# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the net device."""

import re
import time

import pytest
from tenacity import Retrying, stop_after_attempt, wait_fixed

import host_tools.network as net_tools
from framework import utils

# The iperf version to run this tests with
IPERF_BINARY = "iperf3"

# VIRTIO_NET_F_MTU feature bit index (virtio spec 5.1.3)
VIRTIO_NET_F_MTU_BIT = 3


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
    test_microvm.ssh.check_output("{} -sD\n".format(IPERF_BINARY))
    time.sleep(1)

    # Start iperf3 client on the host. Send 1Gbps UDP traffic.
    # If the net device breaks, iperf will freeze, and we'll hit the pytest timeout
    utils.check_output(
        "{} {} -c {} -u -V -b 1000000000 -t 30".format(
            test_microvm.netns.cmd_prefix(),
            IPERF_BINARY,
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
def uvm_any(microvm_factory, uvm_ctor, guest_kernel, rootfs, pci_enabled):
    """Return booted and restored uvm with no CPU templates"""
    return uvm_ctor(microvm_factory, guest_kernel, rootfs, None, pci_enabled)


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
        f"nohup socat UDP4-LISTEN:{port} CREATE:{out_filename} > /dev/null 2>&1 &"
    )

    # wait for socat server to spin up
    time.sleep(1)

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


def test_tap_mtu_advertised_to_guest(uvm_plain_any):
    """
    Verify that VIRTIO_NET_F_MTU correctly advertises the TAP MTU to the guest.

    Configures multiple TAP interfaces with distinct MTU values and checks that
    each guest network interface reports the MTU matching its host TAP.
    """
    vm = uvm_plain_any
    vm.spawn()
    vm.basic_config()

    # (interface index, MTU) pairs with varied values
    iface_mtus = [(0, 1450), (1, 1500), (2, 8935)]

    for idx, mtu in iface_mtus:
        iface = net_tools.NetIfaceConfig.with_id(idx)
        vm.add_net_iface(iface, api=False)
        vm.api.network.put(
            iface_id=iface.dev_name,
            host_dev_name=iface.tap_name,
            guest_mac=iface.guest_mac,
            mtu=mtu,
        )

    vm.start()

    # Verify each guest interface carries the expected MTU and has the feature flag set.
    # SSH runs over eth0; we can still query other interfaces from there.
    # /sys/class/net/{if}/device/features is a bitstring where index i is '1'
    # when feature bit i is negotiated.
    for idx, mtu in iface_mtus:
        iface_name = f"eth{idx}"
        guest_ip = vm.iface[iface_name]["iface"].guest_ip
        guest_if = net_tools.get_guest_net_if_name(vm.ssh, guest_ip)
        assert (
            guest_if is not None
        ), f"Could not find guest interface for {iface_name} ({guest_ip})"
        mtu_out = vm.ssh.check_output(f"cat /sys/class/net/{guest_if}/mtu")
        assert (
            int(mtu_out.stdout.strip()) == mtu
        ), f"{iface_name} (guest: {guest_if}): expected MTU {mtu}, got {mtu_out.stdout.strip()}"
        features = vm.ssh.check_output(
            f"cat /sys/class/net/{guest_if}/device/features"
        ).stdout
        assert features[VIRTIO_NET_F_MTU_BIT] == "1", (
            f"{iface_name} (guest: {guest_if}): VIRTIO_NET_F_MTU (bit {VIRTIO_NET_F_MTU_BIT})"
            f" not set in negotiated features: {features!r}"
        )
