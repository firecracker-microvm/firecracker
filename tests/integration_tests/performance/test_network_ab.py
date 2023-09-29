# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network latency of a Firecracker guest."""

import re

import pytest

from framework.utils import CpuMap
from framework.utils_iperf import IPerf3Test, emit_iperf3_metrics

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

    for sample in samples:
        metrics.put_metric("ping_latency", sample, "Milliseconds")


class TCPIPerf3Test(IPerf3Test):
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
@pytest.mark.timeout(3600)
@pytest.mark.parametrize("vcpus", [1, 2])
@pytest.mark.parametrize("payload_length", ["128K", "1024K"], ids=["p128K", "p1024K"])
@pytest.mark.parametrize("mode", ["g2h", "h2g", "bd"])
def test_network_tcp_throughput(
    microvm_factory,
    guest_kernel,
    rootfs,
    vcpus,
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
    if mode == "bd" and vcpus < 2:
        pytest.skip("bidrectional test only done with at least 2 vcpus")

    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=GUEST_MEM_MIB)
    iface = vm.add_net_iface()
    vm.start()

    # Check if the needed CPU cores are available. We have the API thread, VMM
    # thread and then one thread for each configured vCPU. Lastly, we need one for
    # the iperf server on the host.
    assert CpuMap.len() > 2 + vm.vcpus_count

    # Pin uVM threads to physical cores.
    assert vm.pin_vmm(0), "Failed to pin firecracker thread."
    assert vm.pin_api(1), "Failed to pin fc_api thread."
    for i in range(vm.vcpus_count):
        assert vm.pin_vcpu(i, i + 2), f"Failed to pin fc_vcpu {i} thread."

    test = TCPIPerf3Test(vm, mode, iface.host_ip, payload_length)
    data = test.run_test(vm.vcpus_count + 2)

    metrics.set_dimensions(
        {
            "performance_test": "test_network_tcp_throughput",
            "payload_length": payload_length,
            "mode": mode,
            **vm.dimensions,
        }
    )

    emit_iperf3_metrics(metrics, data, TCPIPerf3Test.WARMUP_SEC)
