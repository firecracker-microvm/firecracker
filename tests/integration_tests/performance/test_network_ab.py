# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network latency of a Firecracker guest."""

import re

import pytest

from framework.utils_iperf import IPerf3Test, emit_iperf3_metrics
from host_tools.fcmetrics import FCMetricsMonitor

# each iteration is 15 * 30 * 0.2s = 90s
ROUNDS = 15
REQUEST_PER_ROUND = 30
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
    seqs = output[1 : REQUEST_PER_ROUND + 1]
    pattern_time = ".+ bytes from .+: icmp_seq=.+ ttl=.+ time=(.+) ms"
    for seq in seqs:
        time = re.findall(pattern_time, seq)
        assert len(time) == 1
        yield float(time[0])


@pytest.fixture
def network_microvm(request, microvm_factory, guest_kernel, rootfs):
    """Creates a microvm with the networking setup used by the performance tests in this file.

    This fixture receives its vcpu count via indirect parameterization"""
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.basic_config(vcpu_count=request.param, mem_size_mib=GUEST_MEM_MIB)
    vm.add_net_iface()
    vm.start()
    vm.pin_threads(0)

    return vm


@pytest.mark.nonci
@pytest.mark.parametrize("network_microvm", [1], indirect=True)
@pytest.mark.parametrize("iteration", [1, 2])
def test_network_latency(network_microvm, metrics, iteration):
    """
    Test network latency by sending pings from the guest to the host.

    This test is split into multiple iterations. The rationale behind
    this is that we have very little network latency test cases (only 2,
    which is the number of guest kernels), which means that the A/B-testing
    framework does not have enough data to meaningfully correct for outliers
    (it has only 2 data points). This change increases the number of data
    points it can work with to 4, which should hopefully help with the high
    false-positive rate we have been seeing from this test.
    """

    metrics.set_dimensions(
        {
            "performance_test": "test_network_latency",
            **network_microvm.dimensions,
            "iteration": str(iteration),
        }
    )
    fcmetrics = FCMetricsMonitor(network_microvm, metrics)
    fcmetrics.start()

    samples = []
    host_ip = network_microvm.iface["eth0"]["iface"].host_ip

    for _ in range(ROUNDS):
        rc, ping_output, stderr = network_microvm.ssh.run(
            f"ping -c {REQUEST_PER_ROUND} -i {DELAY} {host_ip}"
        )
        assert rc == 0, stderr

        samples.extend(consume_ping_output(ping_output))

    for sample in samples:
        metrics.put_metric("ping_latency", sample, "Milliseconds")
    fcmetrics.stop()


class TcpIPerf3Test(IPerf3Test):
    """IPerf3 runner for the TCP throughput performance test"""

    BASE_PORT = 5000

    # How many clients/servers should be spawned per vcpu
    LOAD_FACTOR = 1

    # Time (in seconds) for which iperf "warms up"
    WARMUP_SEC = 5

    # Time (in seconds) for which iperf runs after warmup is done
    RUNTIME_SEC = 20

    def __init__(self, microvm, mode, host_ip, payload_length):
        self._host_ip = host_ip

        super().__init__(
            microvm,
            self.BASE_PORT,
            self.RUNTIME_SEC,
            self.WARMUP_SEC,
            mode,
            self.LOAD_FACTOR * microvm.vcpus_count,
            host_ip,
            payload_length=payload_length,
        )


@pytest.mark.nonci
@pytest.mark.timeout(120)
@pytest.mark.parametrize("network_microvm", [1, 2], indirect=True)
@pytest.mark.parametrize("payload_length", ["128K", "1024K"], ids=["p128K", "p1024K"])
@pytest.mark.parametrize("mode", ["g2h", "h2g", "bd"])
def test_network_tcp_throughput(
    network_microvm,
    payload_length,
    mode,
    metrics,
):
    """
    Iperf between guest and host in both directions for TCP workload.
    """

    # We run bi-directional tests only on uVM with more than 2 vCPus
    # because we need to pin one iperf3/direction per vCPU, and since we
    # have two directions, we need at least two vCPUs.
    if mode == "bd" and network_microvm.vcpus_count < 2:
        pytest.skip("bidrectional test only done with at least 2 vcpus")

    metrics.set_dimensions(
        {
            "performance_test": "test_network_tcp_throughput",
            "payload_length": payload_length,
            "mode": mode,
            **network_microvm.dimensions,
        }
    )
    fcmetrics = FCMetricsMonitor(network_microvm, metrics)
    fcmetrics.start()

    test = TcpIPerf3Test(
        network_microvm,
        mode,
        network_microvm.iface["eth0"]["iface"].host_ip,
        payload_length,
    )
    data = test.run_test(network_microvm.vcpus_count + 2)

    emit_iperf3_metrics(metrics, data, TcpIPerf3Test.WARMUP_SEC)
    fcmetrics.stop()
