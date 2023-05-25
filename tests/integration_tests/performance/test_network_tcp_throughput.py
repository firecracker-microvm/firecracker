# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network throughput of Firecracker uVMs."""

import concurrent.futures
import json
import os
import time

import pytest

from framework.artifacts import DEFAULT_HOST_IP
from framework.stats import consumer, producer
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import (
    CmdBuilder,
    CpuMap,
    DictQuery,
    get_cpu_percent,
    get_kernel_version,
    run_cmd,
)
from integration_tests.performance.configs import defs

TEST_ID = "network_tcp_throughput"
kernel_version = get_kernel_version(level=1)
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID, kernel_version)
CONFIG_NAME_ABS = os.path.join(defs.CFG_LOCATION, CONFIG_NAME_REL)
CONFIG_DICT = json.load(open(CONFIG_NAME_ABS, encoding="utf-8"))

# Number of seconds to wait for the iperf3 server to start
SERVER_STARTUP_TIME_SEC = 2
DEBUG = False
IPERF3 = "iperf3"
THROUGHPUT = "throughput"
THROUGHPUT_TOTAL = "total"
DURATION = "duration"
BASE_PORT = 5000
CPU_UTILIZATION_VMM = "cpu_utilization_vmm"
CPU_UTILIZATION_VCPUS_TOTAL = "cpu_utilization_vcpus_total"
IPERF3_CPU_UTILIZATION_PERCENT_OUT_TAG = "cpu_utilization_percent"
IPERF3_END_RESULTS_TAG = "end"
DEBUG_CPU_UTILIZATION_VMM_SAMPLES_TAG = "cpu_utilization_vmm_samples"
DELTA_PERCENTAGE_TAG = "delta_percentage"
TARGET_TAG = "target"

# How many clients/servers should be spawned per vcpu
LOAD_FACTOR = 1

# Time (in seconds) for which iperf "warms up"
WARMUP_SEC = 5

# Time (in seconds) for which iperf runs after warmup is done
RUNTIME_SEC = 20

# Dictionary mapping modes (guest-to-host, host-to-guest, bidirectional) to arguments passed to the iperf3 clients spawned
MODE_MAP = {"bd": ["", "-R"], "g2h": [""], "h2g": ["-R"]}


# pylint: disable=R0903
class NetTCPThroughputBaselineProvider(BaselineProvider):
    """Implementation of a baseline provider for the network throughput TCP...

    ...performance test.
    """

    def __init__(self, env_id, iperf_id):
        """Network TCP throughput baseline provider initialization."""
        baseline = self.read_baseline(CONFIG_DICT)
        super().__init__(DictQuery(baseline))
        self._tag = "baselines/{}/" + env_id + "/{}/" + iperf_id

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


def produce_iperf_output(
    basevm, guest_cmd_builder, current_avail_cpu, runtime, omit, load_factor, modes
):
    """Produce iperf raw output from server-client connection."""
    # Check if we have enough CPUs to pin the servers on the host.
    # The available CPUs are the total minus vcpus, vmm and API threads.
    assert load_factor * basevm.vcpus_count < CpuMap.len() - basevm.vcpus_count - 2

    # Start the servers.
    for server_idx in range(load_factor * basevm.vcpus_count):
        assigned_cpu = CpuMap(current_avail_cpu)
        iperf_server = (
            CmdBuilder(f"taskset --cpu-list {assigned_cpu}")
            .with_arg(basevm.jailer.netns_cmd_prefix())
            .with_arg(IPERF3)
            .with_arg("-sD")
            .with_arg("-p", f"{BASE_PORT + server_idx}")
            .with_arg("-1")
            .build()
        )
        run_cmd(iperf_server)
        current_avail_cpu += 1

    # Wait for iperf3 server to start.
    time.sleep(SERVER_STARTUP_TIME_SEC)

    # Start `vcpus` iperf3 clients. We can not use iperf3 parallel streams
    # due to non deterministic results and lack of scaling.
    def spawn_iperf_client(conn, client_idx, mode):
        # Add the port where the iperf3 client is going to send/receive.
        cmd = (
            guest_cmd_builder.with_arg("-p", f"{BASE_PORT + client_idx}")
            .with_arg(mode)
            .build()
        )
        pinned_cmd = f"taskset --cpu-list {client_idx % basevm.vcpus_count}" f" {cmd}"
        _, stdout, _ = conn.execute_command(pinned_cmd)
        return stdout.read()

    # Remove inaccurate readings from the workloads end.
    cpu_load_runtime = runtime - 2
    assert cpu_load_runtime > 0
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        cpu_load_future = executor.submit(
            get_cpu_percent, basevm.jailer_clone_pid, cpu_load_runtime, omit
        )

        modes_len = len(modes)
        for client_idx in range(load_factor * basevm.vcpus_count):
            futures.append(
                executor.submit(
                    spawn_iperf_client,
                    basevm.ssh,
                    client_idx,
                    # Distribute the modes evenly.
                    modes[client_idx % modes_len],
                )
            )

        cpu_load = cpu_load_future.result()
        for future in futures[:-1]:
            res = json.loads(future.result())
            res[IPERF3_END_RESULTS_TAG][IPERF3_CPU_UTILIZATION_PERCENT_OUT_TAG] = None
            yield res

        # Attach the real CPU utilization vmm/vcpus to
        # the last iperf3 server-client pair measurements.
        res = json.loads(futures[-1].result())

        # We expect a single emulation thread tagged with `firecracker` name.
        tag = "firecracker"
        assert tag in cpu_load and len(cpu_load[tag]) > 0
        for thread_id in cpu_load[tag]:
            data = cpu_load[tag][thread_id]
            data_len = len(data)
            assert data_len == cpu_load_runtime
            vmm_util = sum(data) / data_len
            cpu_util_perc = res[IPERF3_END_RESULTS_TAG][
                IPERF3_CPU_UTILIZATION_PERCENT_OUT_TAG
            ] = {}
            cpu_util_perc[CPU_UTILIZATION_VMM] = vmm_util
            if DEBUG:
                res[IPERF3_END_RESULTS_TAG][
                    DEBUG_CPU_UTILIZATION_VMM_SAMPLES_TAG
                ] = data

        vcpus_util = 0
        for vcpu in range(basevm.vcpus_count):
            # We expect a single fc_vcpu thread tagged with
            # f`fc_vcpu {vcpu}`.
            tag = f"fc_vcpu {vcpu}"
            assert tag in cpu_load and len(cpu_load[tag]) == 1
            for thread_id in cpu_load[tag]:
                data = cpu_load[tag][thread_id]
                data_len = len(data)
                assert data_len == cpu_load_runtime
                if DEBUG:
                    res[IPERF3_END_RESULTS_TAG][
                        f"cpu_utilization_fc_vcpu_{vcpu}_samples"
                    ] = data

                vcpus_util += sum(data) / data_len

        cpu_util_perc[CPU_UTILIZATION_VCPUS_TOTAL] = vcpus_util

        yield res


def consume_iperf_tcp_output(cons, result, vcpus_count):
    """Consume iperf3 output result for TCP workload."""
    total_received = result[IPERF3_END_RESULTS_TAG]["sum_received"]
    duration = float(total_received["seconds"])
    cons.consume_data(DURATION, duration)

    # Computed at the receiving end.
    total_recv_bytes = int(total_received["bytes"])
    tput = round((total_recv_bytes * 8) / (1024 * 1024 * duration), 2)
    cons.consume_data(THROUGHPUT, tput)

    cpu_util = result[IPERF3_END_RESULTS_TAG][IPERF3_CPU_UTILIZATION_PERCENT_OUT_TAG]
    if cpu_util:
        cpu_util_host = cpu_util[CPU_UTILIZATION_VMM]
        cpu_util_guest = cpu_util[CPU_UTILIZATION_VCPUS_TOTAL]

        cons.consume_stat("Avg", CPU_UTILIZATION_VMM, cpu_util_host)
        cons.consume_stat("Avg", CPU_UTILIZATION_VCPUS_TOTAL, cpu_util_guest)

    if DEBUG:
        if DEBUG_CPU_UTILIZATION_VMM_SAMPLES_TAG in result["end"]:
            cpu_util_vmm_samples = result[IPERF3_END_RESULTS_TAG][
                DEBUG_CPU_UTILIZATION_VMM_SAMPLES_TAG
            ]
            cons.consume_custom(
                DEBUG_CPU_UTILIZATION_VMM_SAMPLES_TAG, cpu_util_vmm_samples
            )

        for vcpu in range(vcpus_count):
            fcvcpu_samples_tag = f"cpu_utilization_fc_vcpu_{vcpu}_samples"
            if fcvcpu_samples_tag in result[IPERF3_END_RESULTS_TAG]:
                cpu_util_fc_vcpu_samples = result[IPERF3_END_RESULTS_TAG][
                    fcvcpu_samples_tag
                ]
                cons.consume_custom(fcvcpu_samples_tag, cpu_util_fc_vcpu_samples)


def pipe(basevm, mode, payload_length, current_avail_cpu, host_ip, env_id):
    """Create producer/consumer pipes."""
    iperf_guest_cmd_builder = (
        CmdBuilder(IPERF3)
        .with_arg("--verbose")
        .with_arg("--client", host_ip)
        .with_arg("--time", RUNTIME_SEC)
        .with_arg("--json")
        .with_arg("--omit", WARMUP_SEC)
    )

    if payload_length != "DEFAULT":
        iperf_guest_cmd_builder = iperf_guest_cmd_builder.with_arg(
            "--len", f"{payload_length}"
        )

    iperf3_id = f"tcp-p{payload_length}-wsDEFAULT-{mode}"

    cons = consumer.LambdaConsumer(
        metadata_provider=DictMetadataProvider(
            measurements=CONFIG_DICT["measurements"],
            baseline_provider=NetTCPThroughputBaselineProvider(env_id, iperf3_id),
        ),
        func=consume_iperf_tcp_output,
        func_kwargs={"vcpus_count": basevm.vcpus_count},
    )

    prod_kwargs = {
        "guest_cmd_builder": iperf_guest_cmd_builder,
        "basevm": basevm,
        "current_avail_cpu": current_avail_cpu,
        "runtime": RUNTIME_SEC,
        "omit": WARMUP_SEC,
        "load_factor": LOAD_FACTOR,
        "modes": MODE_MAP[mode],
    }
    prod = producer.LambdaProducer(produce_iperf_output, prod_kwargs)
    return cons, prod, f"{env_id}/{iperf3_id}"


@pytest.mark.nonci
@pytest.mark.timeout(3600)
@pytest.mark.parametrize("vcpus", [1, 2])
@pytest.mark.parametrize(
    "payload_length", ["DEFAULT", "1024K"], ids=["pDEFAULT", "p1024K"]
)
@pytest.mark.parametrize("mode", ["g2h", "h2g", "bd"])
def test_network_tcp_throughput(
    microvm_factory,
    network_config,
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
    vm.spawn()
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=guest_mem_mib)
    vm.ssh_network_config(network_config, "1")
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
        DEFAULT_HOST_IP,
        f"{guest_kernel.name()}/{rootfs.name()}/{microvm_cfg}",
    )
    st_core.add_pipe(prod, cons, tag)

    # Start running the commands on guest, gather results and verify pass
    # criteria.
    st_core.run_exercise()
