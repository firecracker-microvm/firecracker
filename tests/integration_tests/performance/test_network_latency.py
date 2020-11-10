# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network latency of a Firecracker guest."""

import logging
import platform
import re
import pytest
import host_tools.network as net_tools
from conftest import ARTIFACTS_COLLECTION
from framework.artifacts import ArtifactSet
from framework.matrix import TestMatrix, TestContext
from framework.builder import MicrovmBuilder
from framework.statistics import core, consumer, producer, types, criteria,\
    function
from framework.utils import eager_map, CpuMap
from framework.builder import DEFAULT_HOST_IP


PING = "ping -c {} -i {} {}"
BASELINES = {
    "x86_64": {
        "target": 0.150,  # milliseconds
        "delta": 0.05  # milliseconds
    }
}

PKT_LOSS = "pkt_loss"
LATENCY = "latency"


def pass_criteria():
    """Define pass criteria for the statistics."""
    delta = BASELINES[platform.machine()]["delta"]
    target = BASELINES[platform.machine()]["target"]

    return {
        types.DefaultStat.AVG.name: criteria.EqualWith(target, delta)
    }


def measurements():
    """Define the produced measurements."""
    return [types.MeasurementDef(LATENCY, "millisecond"),
            types.MeasurementDef(PKT_LOSS, "percentage")]


def stats():
    """Define statistics based on the measurements."""
    # Add default statistics for "latency" measurement.
    stats_defs = types.StatisticDef.defaults(LATENCY, pass_criteria())
    stats_defs.append(consumer.StatisticDef(PKT_LOSS,
                                            PKT_LOSS,
                                            function.Identity))
    return stats_defs


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
    eager_map(cons.set_measurement_def, measurements())
    eager_map(cons.set_stat_def, stats())

    st_keys = [types.DefaultStat.MIN.name,
               types.DefaultStat.AVG.name,
               types.DefaultStat.MAX.name,
               types.DefaultStat.STDDEV.name]

    output = raw_data.strip().split('\n')
    assert len(output) > 2

    # E.g: round-trip min/avg/max/stddev = 17.478/17.705/17.808/0.210 ms
    stat_values = output[-1]
    pattern_stats = "round-trip min/avg/max/stddev = (.+)/(.+)/(.+)/(.+) ms"
    stat_values = re.findall(pattern_stats, stat_values)[0]
    assert len(stat_values) == 4

    for index, stat_value in enumerate(stat_values[:4]):
        cons.consume_stat(st_name=st_keys[index],
                          ms_name=LATENCY,
                          value=float(stat_value))

    # E.g: 4 packets transmitted, 4 received, 0% packet loss
    packet_stats = output[-2]
    pattern_packet = ".+ packet.+transmitted, .+ received," \
                     " (.+)% packet loss"
    pkt_loss = re.findall(pattern_packet, packet_stats)[0]
    assert len(pkt_loss) == 1
    cons.consume_stat(st_name=PKT_LOSS,
                      ms_name=PKT_LOSS,
                      value=pkt_loss[0])

    # Compute percentiles.
    seqs = output[1:requests + 1]
    times = list()
    pattern_time = ".+ bytes from .+: icmp_seq=.+ ttl=.+ time=(.+) ms"
    for index, seq in enumerate(seqs):
        time = re.findall(pattern_time, seq)
        assert len(time) == 1
        times.append(time[0])

    times.sort()
    cons.consume_stat(st_name=types.DefaultStat.P50.name,
                      ms_name=LATENCY,
                      value=times[int(requests * 0.5)])
    cons.consume_stat(st_name=types.DefaultStat.P90.name,
                      ms_name=LATENCY,
                      value=times[int(requests * 0.9)])
    cons.consume_stat(st_name=types.DefaultStat.P99.name,
                      ms_name=LATENCY,
                      value=times[int(requests * 0.99)])


@pytest.mark.nonci
@pytest.mark.skipif(platform.machine() != "x86_64",
                    reason="This test was observed only on x86_64. Further "
                           "support need to be added for aarch64 and amd64.")
@pytest.mark.timeout(3600)
def test_network_latency(bin_cloner_path):
    """Test network latency driver for multiple artifacts."""
    logger = logging.getLogger("network_latency")
    microvm_artifacts = ArtifactSet(
        ARTIFACTS_COLLECTION.microvms(keyword="1vcpu_1024mb")
    )
    kernel_artifacts = ArtifactSet(ARTIFACTS_COLLECTION.kernels())
    disk_artifacts = ArtifactSet(ARTIFACTS_COLLECTION.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'logger': logger,
        'requests': 1000,
        'interval': 0.2,  # Seconds.
        'name': 'network_latency'
    }

    # Create the test matrix.
    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])

    test_matrix.run_test(_g2h_send_ping)


def _g2h_send_ping(context):
    """Send ping from guest to host."""
    logger = context.custom['logger']
    vm_builder = context.custom['builder']
    interval_between_req = context.custom['interval']
    name = context.custom['name']

    logger.info("Testing {} with microvm: \"{}\", kernel {}, disk {} "
                .format(name,
                        context.microvm.name(),
                        context.kernel.name(),
                        context.disk.name()))

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from aftifacts.
    basevm = vm_builder.build(kernel=context.kernel,
                              disks=[rw_disk],
                              ssh_key=ssh_key,
                              config=context.microvm)

    basevm.start()

    # Check if the needed CPU cores are available. We have the API thread, VMM
    # thread and then one thread for each configured vCPU.
    assert CpuMap.len() >= 2 + basevm.vcpus_count

    # Pin uVM threads to physical cores.
    current_cpu_id = 0
    assert basevm.pin_vmm(current_cpu_id), \
        "Failed to pin firecracker thread."
    current_cpu_id += 1
    assert basevm.pin_api(current_cpu_id), \
        "Failed to pin fc_api thread."
    for i in range(basevm.vcpus_count):
        current_cpu_id += 1
        assert basevm.pin_vcpu(i, current_cpu_id + i), \
            f"Failed to pin fc_vcpu {i} thread."

    custom = {"microvm": context.microvm.name(),
              "kernel": context.kernel.name(),
              "disk": context.disk.name()}
    st_core = core.Core(name="network_latency", iterations=1, custom=custom)
    cons = consumer.LambdaConsumer(
        consume_stats=True,
        func=consume_ping_output,
        func_kwargs={"requests": context.custom['requests']}
    )
    cmd = PING.format(context.custom['requests'],
                      interval_between_req,
                      DEFAULT_HOST_IP)
    prod = producer.SSHCommand(cmd,
                               net_tools.SSHConnection(basevm.ssh_config))
    st_core.add_pipe(producer=prod, consumer=cons, tag="ping")

    # Gather results and verify pass criteria.
    st_core.run_exercise()
