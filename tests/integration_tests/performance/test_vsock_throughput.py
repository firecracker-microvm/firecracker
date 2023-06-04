# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the VSOCK throughput of Firecracker uVMs."""

import json
import os

import pytest

from framework.stats import consumer, producer
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import CpuMap, get_kernel_version
from framework.utils_iperf import IPerf3Test, consume_iperf3_output
from framework.utils_vsock import VSOCK_UDS_PATH, make_host_port_path
from integration_tests.performance.configs import defs

TEST_ID = "vsock_throughput"
kernel_version = get_kernel_version(level=1)
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID, kernel_version)
CONFIG_NAME_ABS = defs.CFG_LOCATION / CONFIG_NAME_REL

BASE_PORT = 5201

# How many clients/servers should be spawned per vcpu
LOAD_FACTOR = 1

# Time (in seconds) for which iperf "warms up"
WARMUP_SEC = 3

# Time (in seconds) for which iperf runs after warmup is done
RUNTIME_SEC = 20


# pylint: disable=R0903
class VsockThroughputBaselineProvider(BaselineProvider):
    """Implementation of a baseline provider for the vsock throughput...

    ...performance test.
    """

    def __init__(self, env_id, iperf_id, raw_baselines):
        """Vsock throughput baseline provider initialization."""
        super().__init__(raw_baselines)

        self._tag = "baselines/{}/" + env_id + "/{}/" + iperf_id

    def get(self, metric_name: str, statistic_name: str) -> dict:
        """Return the baseline corresponding to the key."""
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


class VsockIPerf3Test(IPerf3Test):
    """IPerf3 runner for the vsock throughput performance test"""

    def __init__(self, microvm, mode, payload_length):
        super().__init__(
            microvm,
            BASE_PORT,
            RUNTIME_SEC,
            WARMUP_SEC,
            mode,
            LOAD_FACTOR * microvm.vcpus_count,
            2,
            iperf="/usr/local/bin/iperf3-vsock",
            payload_length=payload_length,
        )

    def host_command(self, port_offset):
        return (
            super()
            .host_command(port_offset)
            .with_arg("--vsock")
            .with_arg("-B", os.path.join(self._microvm.path, VSOCK_UDS_PATH))
        )

    def spawn_iperf3_client(self, client_idx):
        # Bind the UDS in the jailer's root.
        self._microvm.create_jailed_resource(
            os.path.join(
                self._microvm.path,
                make_host_port_path(VSOCK_UDS_PATH, self._base_port + client_idx),
            )
        )
        # The rootfs does not have iperf3-vsock
        iperf3_guest = "/tmp/iperf3-vsock"

        self._microvm.ssh.scp_put(self._iperf, iperf3_guest)
        self._guest_iperf = iperf3_guest
        return super().spawn_iperf3_client(client_idx)

    def guest_command(self, port_offset):
        return super().guest_command(port_offset).with_arg("--vsock")


def pipe(basevm, current_avail_cpu, env_id, mode, payload_length):
    """Producer/Consumer pipes generator."""

    test = VsockIPerf3Test(basevm, mode, payload_length)

    iperf3_id = f"vsock-p{payload_length}-{mode}"

    raw_baselines = json.loads(CONFIG_NAME_ABS.read_text("utf-8"))

    cons = consumer.LambdaConsumer(
        metadata_provider=DictMetadataProvider(
            raw_baselines["measurements"],
            VsockThroughputBaselineProvider(env_id, iperf3_id, raw_baselines),
        ),
        func=consume_iperf3_output,
    )

    prod = producer.LambdaProducer(
        test.run_test, func_kwargs={"first_free_cpu": current_avail_cpu}
    )
    return cons, prod, f"{env_id}/{iperf3_id}"


@pytest.mark.nonci
@pytest.mark.timeout(1200)
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("payload_length", ["64K", "1024K"], ids=["p64K", "p1024K"])
@pytest.mark.parametrize("mode", ["g2h", "h2g", "bd"])
def test_vsock_throughput(
    microvm_factory,
    guest_kernel,
    rootfs,
    vcpus,
    payload_length,
    mode,
    st_core,
):
    """
    Test vsock throughput for multiple vm configurations.
    """

    # We run bi-directional tests only on uVM with more than 2 vCPus
    # because we need to pin one iperf3/direction per vCPU, and since we
    # have two directions, we need at least two vCPUs.
    if mode == "bd" and vcpus < 2:
        pytest.skip("bidrectional test only done with at least 2 vcpus")

    mem_size_mib = 1024
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=mem_size_mib)
    vm.add_net_iface()
    # Create a vsock device
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/" + VSOCK_UDS_PATH)
    vm.start()

    guest_config = f"{vcpus}vcpu_{mem_size_mib}mb.json"
    st_core.name = TEST_ID
    st_core.custom["guest_config"] = guest_config.removesuffix(".json")

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
        current_avail_cpu + 1,
        f"{st_core.env_id_prefix}/{guest_config}",
        mode,
        payload_length,
    )
    st_core.add_pipe(prod, cons, tag)

    # Start running the commands on guest, gather results and verify pass
    # criteria.
    st_core.run_exercise()
