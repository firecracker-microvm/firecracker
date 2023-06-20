# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network latency of a Firecracker guest."""

import logging
import re
import os
import json
import pytest
import host_tools.network as net_tools
from conftest import ARTIFACTS_COLLECTION
from framework.artifacts import ArtifactSet
from framework.matrix import TestMatrix, TestContext
from framework.builder import MicrovmBuilder
from framework.stats import core, consumer, producer
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import get_kernel_version, CpuMap, DictQuery
from framework.artifacts import DEFAULT_HOST_IP
from framework.utils_cpuid import get_cpu_model_name, get_instance_type
from integration_tests.performance.utils import handle_failure
from integration_tests.performance.configs import defs


TEST_ID = "network_latency"
kernel_version = get_kernel_version(level=1)
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID, kernel_version)
CONFIG_NAME_ABS = os.path.join(defs.CFG_LOCATION, CONFIG_NAME_REL)
CONFIG_DICT = json.load(open(CONFIG_NAME_ABS, encoding="utf-8"))

PING = "ping -c {} -i {} {}"
PKT_LOSS = "pkt_loss"
LATENCY = "latency"

# pylint: disable=R0903
class NetLatencyBaselineProvider(BaselineProvider):
    """Implementation of a baseline provider for the network latency...

    ...performance test.
    """

    def __init__(self, env_id):
        """Network latency baseline provider initialization."""
        cpu_model_name = get_cpu_model_name()
        baselines = list(
            filter(
                lambda cpu_baseline: cpu_baseline["model"] == cpu_model_name,
                CONFIG_DICT["hosts"]["instances"][get_instance_type()]["cpus"],
            )
        )

        super().__init__(DictQuery({}))
        if len(baselines) > 0:
            super().__init__(DictQuery(baselines[0]))

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

    # E.g: 4 packets transmitted, 4 received, 0% packet loss
    packet_stats = output[-2]
    pattern_packet = ".+ packet.+transmitted, .+ received," " (.+)% packet loss"
    pkt_loss = re.findall(pattern_packet, packet_stats)[0]
    assert len(pkt_loss) == 1
    cons.consume_stat(st_name="Avg", ms_name=PKT_LOSS, value=float(pkt_loss[0]))

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
def test_network_latency(bin_cloner_path, results_file_dumper):
    """
    Test network latency for multiple vm configurations.

    @type: performance
    """
    logger = logging.getLogger("network_latency")
    microvm_artifacts = ArtifactSet(
        ARTIFACTS_COLLECTION.microvms(keyword="1vcpu_1024mb")
    )
    kernel_artifacts = ArtifactSet(ARTIFACTS_COLLECTION.kernels())
    disk_artifacts = ArtifactSet(ARTIFACTS_COLLECTION.disks(keyword="ubuntu"))

    logger.info("Testing on processor %s", get_cpu_model_name())

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        "builder": MicrovmBuilder(bin_cloner_path),
        "logger": logger,
        "requests": 1000,
        "interval": 0.2,  # Seconds.
        "name": "network_latency",
        "results_file_dumper": results_file_dumper,
    }

    # Create the test matrix.
    test_matrix = TestMatrix(
        context=test_context,
        artifact_sets=[microvm_artifacts, kernel_artifacts, disk_artifacts],
    )

    test_matrix.run_test(_g2h_send_ping)


def _g2h_send_ping(context):
    """Send ping from guest to host."""
    logger = context.custom["logger"]
    vm_builder = context.custom["builder"]
    interval_between_req = context.custom["interval"]
    name = context.custom["name"]
    file_dumper = context.custom["results_file_dumper"]

    logger.info(
        'Testing {} with microvm: "{}", kernel {}, disk {} '.format(
            name, context.microvm.name(), context.kernel.name(), context.disk.name()
        )
    )

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from aftifacts.
    vm_instance = vm_builder.build(
        kernel=context.kernel, disks=[rw_disk], ssh_key=ssh_key, config=context.microvm
    )
    basevm = vm_instance.vm
    basevm.start()

    # Check if the needed CPU cores are available. We have the API thread, VMM
    # thread and then one thread for each configured vCPU.
    assert CpuMap.len() >= 2 + basevm.vcpus_count

    # Pin uVM threads to physical cores.
    current_cpu_id = 0
    assert basevm.pin_vmm(current_cpu_id), "Failed to pin firecracker thread."
    current_cpu_id += 1
    assert basevm.pin_api(current_cpu_id), "Failed to pin fc_api thread."
    for i in range(basevm.vcpus_count):
        current_cpu_id += 1
        assert basevm.pin_vcpu(
            i, current_cpu_id + i
        ), f"Failed to pin fc_vcpu {i} thread."

    custom = {
        "microvm": context.microvm.name(),
        "kernel": context.kernel.name(),
        "disk": context.disk.name(),
        "cpu_model_name": get_cpu_model_name(),
    }

    st_core = core.Core(name="network_latency", iterations=1, custom=custom)
    env_id = (
        f"{context.kernel.name()}/{context.disk.name()}/" f"{context.microvm.name()}"
    )

    cons = consumer.LambdaConsumer(
        metadata_provider=DictMetadataProvider(
            measurements=CONFIG_DICT["measurements"],
            baseline_provider=NetLatencyBaselineProvider(env_id),
        ),
        func=consume_ping_output,
        func_kwargs={"requests": context.custom["requests"]},
    )
    cmd = PING.format(context.custom["requests"], interval_between_req, DEFAULT_HOST_IP)
    prod = producer.SSHCommand(cmd, net_tools.SSHConnection(basevm.ssh_config))

    st_core.add_pipe(producer=prod, consumer=cons, tag=f"{env_id}/ping")

    # Gather results and verify pass criteria.
    try:
        result = st_core.run_exercise()
    except core.CoreException as err:
        handle_failure(file_dumper, err)

    file_dumper.dump(result)
