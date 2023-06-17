# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network latency of a Firecracker guest."""

import json
import os
import re

import pytest

from framework.artifacts import DEFAULT_HOST_IP
from framework.stats import consumer, producer
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import CpuMap, DictQuery, get_kernel_version
from integration_tests.performance.configs import defs

TEST_ID = "network_latency"
kernel_version = get_kernel_version(level=1)
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID, kernel_version)
CONFIG_NAME_ABS = os.path.join(defs.CFG_LOCATION, CONFIG_NAME_REL)
CONFIG_DICT = json.load(open(CONFIG_NAME_ABS, encoding="utf-8"))

PING = "ping -c {} -i {} {}"
LATENCY = "latency"


# pylint: disable=R0903
class NetLatencyBaselineProvider(BaselineProvider):
    """Implementation of a baseline provider for the network latency...

    ...performance test.
    """

    def __init__(self, env_id):
        """Network latency baseline provider initialization."""
        baseline = self.read_baseline(CONFIG_DICT)
        super().__init__(DictQuery(baseline))
        self._tag = "baselines/{}/" + env_id + "/{}/ping"

    def get(self, ms_name: str, st_name: str) -> dict:
        """Return the baseline value corresponding to the key."""
        key = self._tag.format(ms_name, st_name)
        baseline = self._baselines.get(key)
        if baseline:
            target = baseline.get("target")
            delta_percentage = baseline.get("delta_percentage")
            return {
                "target": target,
                "delta": delta_percentage * target / 100,
            }
        return None


def consume_ping_output(cons, raw_data, requests):
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
    st_keys = ["Min", "Avg", "Max", "Stddev"]

    output = raw_data.strip().split("\n")
    assert len(output) > 2

    # E.g: round-trip min/avg/max/stddev = 17.478/17.705/17.808/0.210 ms
    stat_values = output[-1]
    pattern_stats = "min/avg/max/[a-z]+dev = (.+)/(.+)/(.+)/(.+) ms"
    stat_values = re.findall(pattern_stats, stat_values)[0]
    assert len(stat_values) == 4

    for index, stat_value in enumerate(stat_values[:4]):
        cons.consume_stat(
            st_name=st_keys[index], ms_name=LATENCY, value=float(stat_value)
        )

    # Compute percentiles.
    seqs = output[1 : requests + 1]
    times = []
    pattern_time = ".+ bytes from .+: icmp_seq=.+ ttl=.+ time=(.+) ms"
    for index, seq in enumerate(seqs):
        time = re.findall(pattern_time, seq)
        assert len(time) == 1
        times.append(time[0])

    times.sort()
    cons.consume_stat(
        st_name="Percentile50", ms_name=LATENCY, value=times[int(requests * 0.5)]
    )
    cons.consume_stat(
        st_name="Percentile90", ms_name=LATENCY, value=times[int(requests * 0.9)]
    )
    cons.consume_stat(
        st_name="Percentile99", ms_name=LATENCY, value=times[int(requests * 0.99)]
    )


@pytest.mark.nonci
@pytest.mark.timeout(3600)
def test_network_latency(
    microvm_factory, network_config, guest_kernel, rootfs, st_core
):
    """
    Test network latency for multiple vm configurations.

    Send a ping from the guest to the host.
    """
    requests = 1000
    interval = 0.2  # Seconds

    # Create a microvm from artifacts
    guest_mem_mib = 1024
    guest_vcpus = 1
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn()
    vm.basic_config(vcpu_count=guest_vcpus, mem_size_mib=guest_mem_mib)
    vm.ssh_network_config(network_config, "1")
    vm.start()

    # Check if the needed CPU cores are available. We have the API thread, VMM
    # thread and then one thread for each configured vCPU.
    assert CpuMap.len() >= 2 + vm.vcpus_count

    # Pin uVM threads to physical cores.
    current_cpu_id = 0
    assert vm.pin_vmm(current_cpu_id), "Failed to pin firecracker thread."
    current_cpu_id += 1
    assert vm.pin_api(current_cpu_id), "Failed to pin fc_api thread."
    for i in range(vm.vcpus_count):
        current_cpu_id += 1
        assert vm.pin_vcpu(i, current_cpu_id + i), f"Failed to pin fc_vcpu {i} thread."

    # is this actually needed, beyond baselines?
    guest_config = f"{guest_vcpus}vcpu_{guest_mem_mib}mb.json"
    st_core.name = TEST_ID
    st_core.custom["guest_config"] = guest_config.removesuffix(".json")

    env_id = f"{guest_kernel.name()}/{rootfs.name()}/{guest_config}"
    cons = consumer.LambdaConsumer(
        metadata_provider=DictMetadataProvider(
            measurements=CONFIG_DICT["measurements"],
            baseline_provider=NetLatencyBaselineProvider(env_id),
        ),
        func=consume_ping_output,
        func_kwargs={"requests": requests},
    )
    cmd = PING.format(requests, interval, DEFAULT_HOST_IP)
    prod = producer.SSHCommand(cmd, vm.ssh)

    st_core.add_pipe(producer=prod, consumer=cons, tag=f"{env_id}/ping")
    # Gather results and verify pass criteria.
    st_core.run_exercise()
