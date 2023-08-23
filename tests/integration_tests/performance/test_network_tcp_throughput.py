# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network throughput of Firecracker uVMs."""

import json

import pytest

from framework.stats import consumer, producer
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import CpuMap, get_kernel_version
from framework.utils_iperf import IPerf3Test, consume_iperf3_output
from integration_tests.performance.configs import defs

TEST_ID = "network_tcp_throughput"
kernel_version = get_kernel_version(level=1)
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID, kernel_version)
CONFIG_NAME_ABS = defs.CFG_LOCATION / CONFIG_NAME_REL

BASE_PORT = 5000

# How many clients/servers should be spawned per vcpu
LOAD_FACTOR = 1

# Time (in seconds) for which iperf "warms up"
WARMUP_SEC = 5

# Time (in seconds) for which iperf runs after warmup is done
RUNTIME_SEC = 20


# pylint: disable=R0903
class NetTCPThroughputBaselineProvider(BaselineProvider):
    """Implementation of a baseline provider for the network throughput TCP...

    ...performance test.
    """

    def __init__(self, env_id, iperf_id, raw_baselines):
        """Network TCP throughput baseline provider initialization."""
        super().__init__(raw_baselines)

        self._tag = "baselines/{}/" + env_id + "/{}/" + iperf_id

    def get(self, metric_name: str, statistic_name: str) -> dict:
        """Return the baseline value corresponding to the key."""
        key = self._tag.format(metric_name, statistic_name)
        baseline = self._baselines.get(key)
        if baseline:
            target = baseline.get("target")
            delta_percentage = baseline.get("delta_percentage")
            return {
                "target": target,
                "delta": delta_percentage * target / 100,
            }
        return None


class TCPIPerf3Test(IPerf3Test):
    """IPerf3 runner for the TCP throughput performance test"""

    def __init__(self, microvm, mode, host_ip, payload_length):
        self._host_ip = host_ip

        super().__init__(
            microvm,
            BASE_PORT,
            RUNTIME_SEC,
            WARMUP_SEC,
            mode,
            LOAD_FACTOR * microvm.vcpus_count,
            host_ip,
            payload_length=payload_length,
        )


def pipe(basevm, mode, payload_length, current_avail_cpu, host_ip, env_id):
    """Create producer/consumer pipes."""
    test = TCPIPerf3Test(basevm, mode, host_ip, payload_length)

    iperf3_id = f"tcp-p{payload_length}-wsDEFAULT-{mode}"

    raw_baselines = json.loads(CONFIG_NAME_ABS.read_text("utf-8"))

    cons = consumer.LambdaConsumer(
        metadata_provider=DictMetadataProvider(
            measurements=raw_baselines["measurements"],
            baseline_provider=NetTCPThroughputBaselineProvider(
                env_id, iperf3_id, raw_baselines
            ),
        ),
        func=consume_iperf3_output,
    )

    prod = producer.LambdaProducer(
        test.run_test, func_kwargs={"first_free_cpu": current_avail_cpu}
    )
    return cons, prod, f"{env_id}/{iperf3_id}"


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
    st_core,
):
    """
    Iperf between guest and host in both directions for TCP workload.
    """

    # We run bi-directional tests only on uVM with more than 2 vCPus
    # because we need to pin one iperf3/direction per vCPU, and since we
    # have two directions, we need at least two vCPUs.
    if mode == "bd" and vcpus < 2:
        pytest.skip("bidrectional test only done with at least 2 vcpus")

    guest_mem_mib = 1024
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=guest_mem_mib)
    iface = vm.add_net_iface()
    vm.start()

    microvm_cfg = f"{vcpus}vcpu_{guest_mem_mib}mb.json"
    st_core.name = TEST_ID
    # we will use this also as metrics dimensions
    st_core.custom["guest_config"] = microvm_cfg.removesuffix(".json")

    # Check if the needed CPU cores are available. We have the API thread, VMM
    # thread and then one thread for each configured vCPU.
    assert CpuMap.len() >= 2 + vm.vcpus_count

    # Pin uVM threads to physical cores.
    current_avail_cpu = 0
    assert vm.pin_vmm(current_avail_cpu), "Failed to pin firecracker thread."
    current_avail_cpu += 1
    assert vm.pin_api(current_avail_cpu), "Failed to pin fc_api thread."
    for i in range(vm.vcpus_count):
        current_avail_cpu += 1
        assert vm.pin_vcpu(i, current_avail_cpu), f"Failed to pin fc_vcpu {i} thread."

    cons, prod, tag = pipe(
        vm,
        mode,
        payload_length,
        current_avail_cpu + 1,
        iface.host_ip,
        f"{st_core.env_id_prefix}/{microvm_cfg}",
    )
    st_core.add_pipe(prod, cons, tag)

    # Start running the commands on guest, gather results and verify pass
    # criteria.
    st_core.run_exercise()
