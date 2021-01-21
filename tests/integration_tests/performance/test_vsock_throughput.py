# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the VSOCK throughput of Firecracker uVMs."""


import os
import json
import logging
import time
import concurrent.futures
import pytest
from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.matrix import TestMatrix, TestContext
from framework.builder import MicrovmBuilder
from framework.statistics import core, consumer, producer, criteria, types
from framework.utils import CpuMap, CmdBuilder, run_cmd, eager_map, \
    get_cpu_percent
from framework.utils_cpuid import get_cpu_model_name
import host_tools.network as net_tools
import integration_tests.performance.configs.vsock_throughput_test_config as\
    test_cfg


SERVER_STARTUP_TIME = test_cfg.CONFIG["server_startup_time"]
VSOCK_UDS_PATH = "v.sock"


def measurements():
    """Define the produced measurements for VSOCK workloads."""
    return [types.MeasurementDef(test_cfg.THROUGHPUT,
                                 test_cfg.THROUGHPUT_UNIT),
            types.MeasurementDef(test_cfg.DURATION, test_cfg.DURATION_UNIT),
            types.MeasurementDef.cpu_utilization_vmm(),
            types.MeasurementDef.cpu_utilization_vcpus_total()]


def no_criteria_stats():
    """Return statistics without pass criteria.

    Useful for baselines gathering.
    """
    return [types.StatisticDef.sum(st_name=test_cfg.THROUGHPUT_TOTAL,
                                   ms_name=test_cfg.THROUGHPUT),
            types.StatisticDef.avg(test_cfg.DURATION),
            types.StatisticDef.get_first_observation(
                st_name="value",
                ms_name=test_cfg.CPU_UTILIZATION_VMM),
            types.StatisticDef.get_first_observation(
                st_name="value",
                ms_name=test_cfg.CPU_UTILIZATION_VCPUS_TOTAL)]


def criteria_stats(cpu_baselines: str, iperf3_id: str, env_id: str):
    """Return statistics tailored to the platform cpu model."""
    baseline_bw = cpu_baselines["baseline_bw"][env_id][iperf3_id]
    delta_throughput = \
        baseline_bw[test_cfg.DELTA_PERCENTAGE_TAG] * baseline_bw[
            test_cfg.TARGET_TAG] / 100
    baseline_cpu_util = cpu_baselines["baseline_cpu_utilization"][env_id]
    baseline_cpu_host = \
        baseline_cpu_util["vmm"][iperf3_id]
    baseline_host_target = baseline_cpu_host[test_cfg.TARGET_TAG]
    baseline_host_delta = \
        baseline_cpu_host[test_cfg.DELTA_PERCENTAGE_TAG] * \
        baseline_host_target / 100
    baseline_cpu_guest = \
        baseline_cpu_util["vcpus_total"][iperf3_id]
    baseline_guest_target = baseline_cpu_guest[test_cfg.TARGET_TAG]
    baseline_guest_delta = \
        baseline_guest_target * baseline_guest_target / 100

    return [types.StatisticDef.sum(
                st_name=test_cfg.THROUGHPUT_TOTAL,
                ms_name=test_cfg.THROUGHPUT,
                criteria=criteria.EqualWith(baseline_bw[test_cfg.TARGET_TAG],
                                            delta_throughput)),
            types.StatisticDef.avg(test_cfg.DURATION),
            types.StatisticDef.get_first_observation(
                st_name="value",
                ms_name=test_cfg.CPU_UTILIZATION_VMM,
                criteria=criteria.EqualWith(baseline_host_target,
                                            baseline_host_delta)),
            types.StatisticDef.get_first_observation(
                st_name="value",
                ms_name=test_cfg.CPU_UTILIZATION_VCPUS_TOTAL,
                criteria=criteria.EqualWith(baseline_guest_target,
                                            baseline_guest_delta)
            )]


def produce_iperf_output(basevm,
                         guest_cmd_builder,
                         current_avail_cpu,
                         runtime,
                         omit,
                         load_factor,
                         modes):
    """Produce iperf raw output from server-client connection."""
    # Check if we have enough CPUs to pin the servers on the host.
    # The available CPUs are the total minus vcpus, vmm and API threads.
    assert load_factor * basevm.vcpus_count < CpuMap.len() - \
        basevm.vcpus_count - 2

    host_uds_path = os.path.join(
        basevm.path,
        VSOCK_UDS_PATH
    )

    # Start the servers.
    for server_idx in range(load_factor*basevm.vcpus_count):
        assigned_cpu = CpuMap(current_avail_cpu)
        iperf_server = \
            CmdBuilder(f"taskset --cpu-list {assigned_cpu}") \
            .with_arg(test_cfg.IPERF3) \
            .with_arg("-sD") \
            .with_arg("--vsock") \
            .with_arg("-B", host_uds_path) \
            .with_arg("-p", f"{test_cfg.BASE_PORT + server_idx}") \
            .with_arg("-1") \
            .build()

        run_cmd(iperf_server)
        current_avail_cpu += 1

    # Wait for iperf3 servers to start.
    time.sleep(SERVER_STARTUP_TIME)

    # Start `vcpus` iperf3 clients. We can not use iperf3 parallel streams
    # due to non deterministic results and lack of scaling.
    def spawn_iperf_client(conn, client_idx, mode):
        # Add the port where the iperf3 client is going to send/receive.
        cmd = guest_cmd_builder.with_arg(
            "-p", test_cfg.BASE_PORT + client_idx).with_arg(mode).build()

        # Bind the UDS in the jailer's root.
        basevm.create_jailed_resource(os.path.join(
            basevm.path,
            _make_host_port_path(VSOCK_UDS_PATH,
                                 test_cfg.BASE_PORT + client_idx)))

        pinned_cmd = f"taskset --cpu-list {client_idx % basevm.vcpus_count}" \
            f" {cmd}"
        rc, stdout, _ = conn.execute_command(pinned_cmd)

        assert rc == 0

        return stdout.read()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = list()
        cpu_load_future = executor.submit(get_cpu_percent,
                                          basevm.jailer_clone_pid,
                                          runtime - SERVER_STARTUP_TIME,
                                          omit)

        modes_len = len(modes)
        ssh_connection = net_tools.SSHConnection(basevm.ssh_config)
        for client_idx in range(load_factor*basevm.vcpus_count):
            futures.append(executor.submit(spawn_iperf_client,
                                           ssh_connection,
                                           client_idx,
                                           # Distribute the modes evenly.
                                           modes[client_idx % modes_len]))

        cpu_load = cpu_load_future.result()
        for future in futures[:-1]:
            res = json.loads(future.result())
            res[test_cfg.IPERF3_END_RESULTS_TAG][
                test_cfg.IPERF3_CPU_UTILIZATION_PERCENT_OUT_TAG] = None
            yield res

        # Attach the real CPU utilization vmm/vcpus to
        # the last iperf3 server-client pair measurements.
        res = json.loads(futures[-1].result())

        # We expect a single emulation thread tagged with `firecracker` name.
        tag = "firecracker"
        assert tag in cpu_load and len(cpu_load[tag]) == 1
        thread_id = list(cpu_load[tag])[0]
        data = cpu_load[tag][thread_id]
        vmm_util = sum(data)/len(data)
        cpu_util_perc = res[test_cfg.IPERF3_END_RESULTS_TAG][
            test_cfg.IPERF3_CPU_UTILIZATION_PERCENT_OUT_TAG] = dict()
        cpu_util_perc[test_cfg.CPU_UTILIZATION_VMM] = vmm_util

        vcpus_util = 0
        for vcpu in range(basevm.vcpus_count):
            # We expect a single fc_vcpu thread tagged with
            # f`fc_vcpu {vcpu}`.
            tag = f"fc_vcpu {vcpu}"
            assert tag in cpu_load and len(cpu_load[tag]) == 1
            thread_id = list(cpu_load[tag])[0]
            data = cpu_load[tag][thread_id]
            vcpus_util += (sum(data)/len(data))

        cpu_util_perc[test_cfg.CPU_UTILIZATION_VCPUS_TOTAL] = vcpus_util

        yield res


def consume_iperf_output(cons, result):
    """Consume iperf3 output result for TCP workload."""
    total_received = result[test_cfg.IPERF3_END_RESULTS_TAG]['sum_received']
    duration = float(total_received['seconds'])
    cons.consume_measurement(test_cfg.DURATION, duration)

    # Computed at the receiving end.
    total_recv_bytes = int(total_received['bytes'])
    tput = round((total_recv_bytes*8) / (1024*1024*duration), 2)
    cons.consume_measurement(test_cfg.THROUGHPUT, tput)

    cpu_util = result[test_cfg.IPERF3_END_RESULTS_TAG][
        test_cfg.IPERF3_CPU_UTILIZATION_PERCENT_OUT_TAG]
    if cpu_util:
        cpu_util_host = cpu_util[test_cfg.CPU_UTILIZATION_VMM]
        cpu_util_guest = cpu_util[test_cfg.CPU_UTILIZATION_VCPUS_TOTAL]

        cons.consume_measurement(test_cfg.CPU_UTILIZATION_VMM, cpu_util_host)
        cons.consume_measurement(test_cfg.CPU_UTILIZATION_VCPUS_TOTAL,
                                 cpu_util_guest)


def pipes(basevm, current_avail_cpu, env_id):
    """Producer/Consumer pipes generator."""
    host_cpu_model_name = get_cpu_model_name()
    cpus_baselines = test_cfg.CONFIG["hosts"]["instances"]["m5d.metal"]["cpus"]
    stats = no_criteria_stats()
    baselines = list(filter(
        lambda baseline: baseline["model"] == host_cpu_model_name,
        cpus_baselines))

    for mode in test_cfg.CONFIG["modes"]:
        # We run bi-directional tests only on uVM with more than 2 vCPus
        # because we need to pin one iperf3/direction per vCPU, and since we
        # have two directions, we need at least two vCPUs.
        if mode == "bd" and basevm.vcpus_count < 2:
            continue

        for protocol in test_cfg.CONFIG["protocols"]:
            host_cpu_model_name = get_cpu_model_name()

            for payload_length in protocol["payload_length"]:
                iperf_guest_cmd_builder = CmdBuilder(test_cfg.IPERF3) \
                    .with_arg("--vsock") \
                    .with_arg("-c", 2)       \
                    .with_arg("--json") \
                    .with_arg("--omit", protocol["omit"]) \
                    .with_arg("--time", test_cfg.CONFIG["time"])

                if payload_length:
                    iperf_guest_cmd_builder = iperf_guest_cmd_builder \
                        .with_arg("--len", f"{payload_length}")
                    iperf3_id_payload_len = payload_length
                else:
                    iperf3_id_payload_len = "DEFAULT"

                iperf3_id = f"vsock-p{iperf3_id_payload_len}" \
                    f"-{basevm.vcpus_count}vcpu-{mode}"

                cons = consumer.LambdaConsumer(
                    consume_stats=False,
                    func=consume_iperf_output
                )

                if len(baselines) > 0:
                    stats = criteria_stats(baselines[0], iperf3_id, env_id)

                eager_map(cons.set_measurement_def, measurements())
                eager_map(cons.set_stat_def, stats)

                prod_kwargs = {
                    "guest_cmd_builder": iperf_guest_cmd_builder,
                    "basevm": basevm,
                    "current_avail_cpu": current_avail_cpu,
                    "runtime": test_cfg.CONFIG["time"],
                    "omit": protocol["omit"],
                    "load_factor": test_cfg.CONFIG["load_factor"],
                    "modes": test_cfg.CONFIG["modes"][mode],
                }
                prod = producer.LambdaProducer(produce_iperf_output,
                                               prod_kwargs)
                yield cons, prod, f"{env_id}/{iperf3_id}"


@pytest.mark.nonci
@pytest.mark.timeout(600)
def test_vsock_throughput(bin_cloner_path):
    """Test vsock throughput driver for multiple artifacts."""
    logger = logging.getLogger("vsock_throughput")
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="1vcpu_1024mb"))
    microvm_artifacts.insert(artifacts.microvms(keyword="2vcpu_1024mb"))
    kernel_artifacts = ArtifactSet(
        artifacts.kernels(keyword="vmlinux-4.14.bin"))
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'logger': logger,
        'name': 'vsock_throughput'
    }

    print(get_cpu_model_name())

    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])
    test_matrix.run_test(iperf_workload)


def iperf_workload(context):
    """Run a statistic exercise."""
    vm_builder = context.custom['builder']
    logger = context.custom["logger"]

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from artifacts.
    basevm = vm_builder.build(kernel=context.kernel,
                              disks=[rw_disk],
                              ssh_key=ssh_key,
                              config=context.microvm)

    # Create a vsock device
    basevm.vsock.put(
        vsock_id="vsock0",
        guest_cid=3,
        uds_path="/" + VSOCK_UDS_PATH
    )

    basevm.start()

    st_core = core.Core(name="vsock_throughput",
                        iterations=1)

    # Check if the needed CPU cores are available. We have the API thread, VMM
    # thread and then one thread for each configured vCPU.
    assert CpuMap.len() >= 2 + basevm.vcpus_count

    # Pin uVM threads to physical cores.
    current_avail_cpu = 0
    assert basevm.pin_vmm(current_avail_cpu), \
        "Failed to pin firecracker thread."
    current_avail_cpu += 1
    assert basevm.pin_api(current_avail_cpu), \
        "Failed to pin fc_api thread."
    for i in range(basevm.vcpus_count):
        current_avail_cpu += 1
        assert basevm.pin_vcpu(i, current_avail_cpu), \
            f"Failed to pin fc_vcpu {i} thread."

    logger.info("Testing with microvm: \"{}\", kernel {}, disk {}"
                .format(context.microvm.name(),
                        context.kernel.name(),
                        context.disk.name()))

    for cons, prod, tag in \
            pipes(basevm,
                  current_avail_cpu + 1,
                  f"{context.kernel.name()}/{context.disk.name()}"):
        st_core.add_pipe(prod, cons, tag)

    # Start running the commands on guest, gather results and verify pass
    # criteria.
    st_core.run_exercise()

    basevm.kill()


def _make_host_port_path(uds_path, port):
    """Build the path for a Unix socket, mapped to host vsock port `port`."""
    return "{}_{}".format(uds_path, port)
