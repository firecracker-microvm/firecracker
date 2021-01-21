# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network throughput of Firecracker uVMs."""


import json
import logging
import time
import concurrent.futures
import pytest
from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet, \
    DEFAULT_HOST_IP
from framework.matrix import TestMatrix, TestContext
from framework.builder import MicrovmBuilder
from framework.statistics import core, consumer, producer, criteria, types
from framework.utils import CpuMap, CmdBuilder, run_cmd, eager_map, \
    get_cpu_percent
from framework.utils_cpuid import get_cpu_model_name
import host_tools.network as net_tools
import integration_tests.performance.configs\
    .network_tcp_throughput_test_config as test_cfg


def measurements():
    """Define the produced measurements for TCP workloads."""
    return [types.MeasurementDef.cpu_utilization_vcpus_total(),
            types.MeasurementDef.cpu_utilization_vmm(),
            types.MeasurementDef(test_cfg.THROUGHPUT, "Mbps"),
            types.MeasurementDef(test_cfg.DURATION, "seconds"),
            types.MeasurementDef(test_cfg.RETRANSMITS, "#")]


def criteria_stats(cpu_baseline: dict, iperf3_id: str, env_id: str):
    """Return statistics definitions based with pass criteria."""
    baseline_bw = cpu_baseline["baseline_bw"][env_id][iperf3_id]
    delta_throughput = \
        baseline_bw[test_cfg.DELTA_PERCENTAGE_TAG] * \
        baseline_bw[test_cfg.TARGET_TAG] / 100
    baseline_cpu_util = cpu_baseline["baseline_cpu_utilization"][env_id]
    baseline_cpu_host = baseline_cpu_util["vmm"][
        iperf3_id]
    baseline_vmm_target = baseline_cpu_host[test_cfg.TARGET_TAG]
    baseline_vmm_delta = \
        baseline_cpu_host[test_cfg.DELTA_PERCENTAGE_TAG] * \
        baseline_vmm_target / 100
    baseline_cpu_vcpus_total = \
        baseline_cpu_util["vcpus_total"][iperf3_id]
    baseline_vcpus_total_target = baseline_cpu_vcpus_total[test_cfg.TARGET_TAG]
    baseline_vcpus_total_delta = \
        baseline_cpu_vcpus_total[test_cfg.DELTA_PERCENTAGE_TAG] * \
        baseline_vcpus_total_target / 100

    return [
        types.StatisticDef.sum(
            st_name=test_cfg.THROUGHPUT_TOTAL,
            ms_name=test_cfg.THROUGHPUT,
            criteria=criteria.EqualWith(baseline_bw[test_cfg.TARGET_TAG],
                                        delta_throughput)),
        types.StatisticDef.sum(ms_name=test_cfg.RETRANSMITS,
                               st_name=test_cfg.RETRANSMITS_TOTAL),
        types.StatisticDef.avg(test_cfg.DURATION),
        types.StatisticDef.get_first_observation(
            ms_name=test_cfg.CPU_UTILIZATION_VMM,
            st_name="value",
            criteria=criteria.EqualWith(baseline_vmm_target,
                                        baseline_vmm_delta)),
        types.StatisticDef.get_first_observation(
            ms_name=test_cfg.CPU_UTILIZATION_VCPUS_TOTAL,
            st_name="value",
            criteria=criteria.EqualWith(baseline_vcpus_total_target,
                                        baseline_vcpus_total_delta))]


def no_criteria_stats():
    """Return stats without pass criteria.

    These statistics are useful for baseline gathering.
    """
    return [
        types.StatisticDef.sum(st_name=test_cfg.THROUGHPUT_TOTAL,
                               ms_name=test_cfg.THROUGHPUT),
        types.StatisticDef.sum(st_name=test_cfg.RETRANSMITS_TOTAL,
                               ms_name=test_cfg.RETRANSMITS),
        types.StatisticDef.avg(ms_name=test_cfg.DURATION),
        types.StatisticDef.get_first_observation(
            st_name="value",
            ms_name=test_cfg.CPU_UTILIZATION_VMM),
        types.StatisticDef.get_first_observation(
            st_name="value",
            ms_name=test_cfg.CPU_UTILIZATION_VCPUS_TOTAL)
    ]


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

    # Start the servers.
    for server_idx in range(load_factor*basevm.vcpus_count):
        assigned_cpu = CpuMap(current_avail_cpu)
        iperf_server = \
            CmdBuilder(f"taskset --cpu-list {assigned_cpu}") \
            .with_arg(basevm.jailer.netns_cmd_prefix()) \
            .with_arg(test_cfg.IPERF3) \
            .with_arg("-sD") \
            .with_arg("-p", f"{test_cfg.BASE_PORT + server_idx}") \
            .with_arg("-1") \
            .build()
        run_cmd(iperf_server)
        current_avail_cpu += 1

    # Wait for iperf3 server to start.
    time.sleep(2)

    # Start `vcpus` iperf3 clients. We can not use iperf3 parallel streams
    # due to non deterministic results and lack of scaling.
    def spawn_iperf_client(conn, client_idx, mode):
        # Add the port where the iperf3 client is going to send/receive.
        cmd = guest_cmd_builder                                 \
            .with_arg("-p", f"{test_cfg.BASE_PORT + client_idx}")       \
            .with_arg(mode)                                     \
            .build()
        pinned_cmd = f"taskset --cpu-list {client_idx % basevm.vcpus_count}" \
                     f" {cmd}"
        _, stdout, _ = conn.execute_command(pinned_cmd)
        return stdout.read()

    # Remove inaccurate readings from the workloads end.
    cpu_load_runtime = runtime - 2
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = list()
        cpu_load_future = executor.submit(get_cpu_percent,
                                          basevm.jailer_clone_pid,
                                          cpu_load_runtime,
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
        for thread_id in cpu_load[tag]:
            data = cpu_load[tag][thread_id]
            data_len = len(data)
            assert data_len == cpu_load_runtime
            vmm_util = sum(data)/data_len
            cpu_util_perc = res[test_cfg.IPERF3_END_RESULTS_TAG][
                test_cfg.IPERF3_CPU_UTILIZATION_PERCENT_OUT_TAG] = dict()
            cpu_util_perc[test_cfg.CPU_UTILIZATION_VMM] = vmm_util
            if test_cfg.DEBUG:
                res[test_cfg.IPERF3_END_RESULTS_TAG][
                    test_cfg.DEBUG_CPU_UTILIZATION_VMM_SAMPLES_TAG] \
                    = data

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
                if test_cfg.DEBUG:
                    res[test_cfg.IPERF3_END_RESULTS_TAG][
                        f"cpu_utilization_fc_vcpu_{vcpu}_samples"] = data

                vcpus_util += sum(data)/data_len

        cpu_util_perc[test_cfg.CPU_UTILIZATION_VCPUS_TOTAL] = vcpus_util

        yield res


def consume_iperf_tcp_output(cons,
                             result,
                             vcpus_count):
    """Consume iperf3 output result for TCP workload."""
    total_received = result[test_cfg.IPERF3_END_RESULTS_TAG]['sum_received']
    duration = float(total_received['seconds'])
    cons.consume_measurement(test_cfg.DURATION, duration)

    total_sent = result[test_cfg.IPERF3_END_RESULTS_TAG]['sum_sent']
    retransmits = int(total_sent['retransmits'])
    cons.consume_measurement(test_cfg.RETRANSMITS, retransmits)

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

    if test_cfg.DEBUG:
        if test_cfg.DEBUG_CPU_UTILIZATION_VMM_SAMPLES_TAG in result['end']:
            cpu_util_vmm_samples = result[test_cfg.IPERF3_END_RESULTS_TAG][
                test_cfg.DEBUG_CPU_UTILIZATION_VMM_SAMPLES_TAG]
            cons.consume_custom(test_cfg.DEBUG_CPU_UTILIZATION_VMM_SAMPLES_TAG,
                                cpu_util_vmm_samples)

        for vcpu in range(vcpus_count):
            fcvcpu_samples_tag = f"cpu_utilization_fc_vcpu_{vcpu}_samples"
            if fcvcpu_samples_tag in result[test_cfg.IPERF3_END_RESULTS_TAG]:
                cpu_util_fc_vcpu_samples = \
                    result[test_cfg.IPERF3_END_RESULTS_TAG][fcvcpu_samples_tag]
                cons.consume_custom(fcvcpu_samples_tag,
                                    cpu_util_fc_vcpu_samples)


def create_pipes_generator(basevm,
                           mode,
                           current_avail_cpu,
                           protocol,
                           host_ip,
                           env_id):
    """Create producer/consumer pipes."""
    host_cpu_model_name = get_cpu_model_name()
    cpus_baselines = test_cfg.CONFIG["hosts"]["instances"]["m5d.metal"]["cpus"]
    stats = no_criteria_stats()
    baselines = list(filter(
        lambda baseline: baseline["model"] == host_cpu_model_name,
        cpus_baselines))

    for payload_length in protocol["payload_length"]:
        for ws in protocol["window_size"]:
            iperf_guest_cmd_builder = CmdBuilder(test_cfg.IPERF3) \
                .with_arg("--verbose") \
                .with_arg("--client", host_ip) \
                .with_arg("--time", test_cfg.CONFIG["time"]) \
                .with_arg("--json") \
                .with_arg("--omit", protocol["omit"])

            if ws:
                iperf_guest_cmd_builder = iperf_guest_cmd_builder \
                    .with_arg("--window", f"{ws}")
                iperf3_id_ws = ws
            else:
                iperf3_id_ws = "DEFAULT"

            if payload_length:
                iperf_guest_cmd_builder = iperf_guest_cmd_builder \
                    .with_arg("--len", f"{payload_length}")
                iperf3_id_payload_len = payload_length
            else:
                iperf3_id_payload_len = "DEFAULT"

            iperf3_id = f"tcp-p{iperf3_id_payload_len}" \
                        f"-ws{iperf3_id_ws}-{basevm.vcpus_count}vcpu-{mode}"

            cons = consumer.LambdaConsumer(
                consume_stats=False,
                func=consume_iperf_tcp_output,
                func_kwargs={
                    "vcpus_count": basevm.vcpus_count
                }
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
                "modes": test_cfg.CONFIG["modes"][mode]
            }
            prod = producer.LambdaProducer(produce_iperf_output,
                                           prod_kwargs)
            yield cons, prod, f"{env_id}/{iperf3_id}"


def pipes(basevm, host_ip, current_avail_cpu, env_id):
    """Pipes generator."""
    for mode in test_cfg.CONFIG["modes"]:
        # We run bi-directional tests only on uVM with more than 2 vCPus
        # because we need to pin one iperf3/direction per vCPU, and since we
        # have two directions, we need at least two vCPUs.
        if mode == "bd" and basevm.vcpus_count < 2:
            continue

        for protocol in test_cfg.CONFIG["protocols"]:
            # Distribute modes evenly between producers and consumers.
            pipes_generator = create_pipes_generator(basevm,
                                                     mode,
                                                     current_avail_cpu,
                                                     protocol,
                                                     host_ip,
                                                     env_id)

            for cons, prod, pipe_tag in pipes_generator:
                yield cons, prod, pipe_tag


@pytest.mark.nonci
@pytest.mark.timeout(3600)
def test_network_throughput(bin_cloner_path):
    """Test network throughput driver for multiple artifacts."""
    logger = logging.getLogger("network_tcp_throughput")
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_1024mb"))
    microvm_artifacts.insert(artifacts.microvms(keyword="1vcpu_1024mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels())
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'logger': logger,
        'name': 'network_tcp_throughput'
    }

    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])
    test_matrix.run_test(iperf_workload)


def iperf_workload(context):
    """Iperf between guest and host in both directions for TCP workload."""
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

    basevm.start()
    custom = {"microvm": context.microvm.name(),
              "kernel": context.kernel.name(),
              "disk": context.disk.name()}
    st_core = core.Core(name="network_tcp_throughput",
                        iterations=1,
                        check=True,
                        custom=custom)

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
                  DEFAULT_HOST_IP,
                  current_avail_cpu + 1,
                  f"{context.kernel.name()}/{context.disk.name()}"):
        st_core.add_pipe(prod, cons, tag)

    # Start running the commands on guest, gather results and verify pass
    # criteria.
    st_core.run_exercise()
