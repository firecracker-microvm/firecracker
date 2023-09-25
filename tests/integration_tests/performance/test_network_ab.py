# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network latency of a Firecracker guest."""

import re
import statistics

import pytest

from framework.utils import CpuMap

# each iteration is 30 * 0.2s = 6s
# Thus 30 iterations are 6s * 30 = 5min
REQUEST_PER_ITERATION = 30
ITERATIONS = 30
DELAY = 0.2

#  MicroVM configuration
GUEST_MEM_MIB = 1024
GUEST_VCPUS = 1


def consume_ping_output(ping_putput):
    """Consume ping output.

    Output example:
    PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
    64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=17.7 ms
    64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=17.7 ms
    64 bytes from 8.8.8.8: icmp_seq=3 ttl=118 time=17.4 ms
    64 bytes from 8.8.8.8: icmp_seq=4 ttl=118 time=17.8 ms

    --- 8.8.8.8 ping statistics ---
    4 packets transmitted, 4 received, 0% packet loss, time 3005ms
    rtt min/avg/max/mdev = 17.478/17.705/17.808/0.210 ms
    """
    output = ping_putput.strip().split("\n")
    assert len(output) > 2

    # Compute percentiles.
    seqs = output[1 : REQUEST_PER_ITERATION + 1]
    pattern_time = ".+ bytes from .+: icmp_seq=.+ ttl=.+ time=(.+) ms"
    for seq in seqs:
        time = re.findall(pattern_time, seq)
        assert len(time) == 1
        yield float(time[0])


@pytest.mark.nonci
@pytest.mark.timeout(3600)
def test_network_latency(microvm_factory, guest_kernel, rootfs, metrics):
    """
    Test network latency for multiple vm configurations.

    Send a ping from the guest to the host.
    """

    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.basic_config(vcpu_count=GUEST_VCPUS, mem_size_mib=GUEST_MEM_MIB)
    iface = vm.add_net_iface()
    vm.start()

    # Check if the needed CPU cores are available. We have the API thread, VMM
    # thread and then one thread for each configured vCPU.
    assert CpuMap.len() >= 2 + vm.vcpus_count

    # Pin uVM threads to physical cores.
    assert vm.pin_vmm(0), "Failed to pin firecracker thread."
    assert vm.pin_api(1), "Failed to pin fc_api thread."
    for i in range(vm.vcpus_count):
        assert vm.pin_vcpu(i, i + 2), f"Failed to pin fc_vcpu {i} thread."

    samples = []

    for _ in range(ITERATIONS):
        rc, ping_output, stderr = vm.ssh.run(
            f"ping -c {REQUEST_PER_ITERATION} -i {DELAY} {iface.host_ip}"
        )
        assert rc == 0, stderr

        samples.extend(consume_ping_output(ping_output))

    metrics.set_dimensions(
        {"performance_test": "test_network_latency", **vm.dimensions}
    )

    metrics.put_metric("latency_Avg", statistics.mean(samples), "Milliseconds")

    for sample in samples:
        metrics.put_metric("latency", sample, "Milliseconds")
