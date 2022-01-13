# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""
import concurrent
import json
import logging
import os
from enum import Enum
import shutil
import pytest

from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.builder import MicrovmBuilder
from framework.matrix import TestContext, TestMatrix
from framework.stats import core
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import get_cpu_percent, CmdBuilder, DictQuery, run_cmd
from framework.utils_cpuid import get_cpu_model_name
import host_tools.drive as drive_tools
import host_tools.network as net_tools  # pylint: disable=import-error
import framework.stats as st
from integration_tests.performance.configs import defs
from integration_tests.performance.utils import handle_failure, \
    dump_test_result

DEBUG = False
TEST_ID = "block_device_performance"
FIO = "fio"

# Measurements tags.
CPU_UTILIZATION_VMM = "cpu_utilization_vmm"
CPU_UTILIZATION_VMM_SAMPLES_TAG = "cpu_utilization_vmm_samples"
CPU_UTILIZATION_VCPUS_TOTAL = "cpu_utilization_vcpus_total"
CONFIG = json.load(open(defs.CFG_LOCATION /
                        "block_performance_test_config.json",
                        encoding='utf-8'))


# pylint: disable=R0903
class BlockBaselinesProvider(BaselineProvider):
    """Implementation of a baseline provider for the block performance test."""

    def __init__(self, env_id, fio_id):
        """Block baseline provider initialization."""
        cpu_model_name = get_cpu_model_name()
        baselines = list(filter(
            lambda cpu_baseline: cpu_baseline["model"] == cpu_model_name,
            CONFIG["hosts"]["instances"]["m5d.metal"]["cpus"]))

        super().__init__(DictQuery({}))
        if len(baselines) > 0:
            super().__init__(DictQuery(baselines[0]))

        self._tag = "baselines/{}/" + env_id + "/{}/" + fio_id

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


def run_fio(env_id, basevm, ssh_conn, mode, bs):
    """Run a fio test in the specified mode with block size bs."""
    logs_path = f"{basevm.jailer.chroot_base_with_id()}/{env_id}/{mode}{bs}"

    # Compute the fio command. Pin it to the first guest CPU.
    cmd = CmdBuilder(FIO) \
        .with_arg(f"--name={mode}-{bs}") \
        .with_arg(f"--rw={mode}") \
        .with_arg(f"--bs={bs}") \
        .with_arg("--filename=/dev/vdb") \
        .with_arg("--time_base=1") \
        .with_arg(f"--size={CONFIG['block_device_size']}M") \
        .with_arg("--direct=1") \
        .with_arg("--ioengine=libaio") \
        .with_arg("--iodepth=32") \
        .with_arg(f"--ramp_time={CONFIG['omit']}") \
        .with_arg(f"--numjobs={CONFIG['load_factor'] * basevm.vcpus_count}") \
        .with_arg("--randrepeat=0") \
        .with_arg(f"--runtime={CONFIG['time']}") \
        .with_arg(f"--write_iops_log={mode}{bs}") \
        .with_arg(f"--write_bw_log={mode}{bs}") \
        .with_arg("--log_avg_msec=1000") \
        .with_arg("--output-format=json+") \
        .build()

    rc, _, stderr = ssh_conn.execute_command(
        "echo 'none' > /sys/block/vdb/queue/scheduler")
    assert rc == 0, stderr.read()
    assert stderr.read() == ""

    # First, flush all guest cached data to host, then drop guest FS caches.
    rc, _, stderr = ssh_conn.execute_command("sync")
    assert rc == 0, stderr.read()
    assert stderr.read() == ""
    rc, _, stderr = ssh_conn.execute_command(
        "echo 3 > /proc/sys/vm/drop_caches")
    assert rc == 0, stderr.read()
    assert stderr.read() == ""

    # Then, flush all host cached data to hardware, also drop host FS caches.
    run_cmd("sync")
    run_cmd("echo 3 > /proc/sys/vm/drop_caches")

    # Start the CPU load monitor.
    with concurrent.futures.ThreadPoolExecutor() as executor:
        cpu_load_future = executor.submit(get_cpu_percent,
                                          basevm.jailer_clone_pid,
                                          CONFIG["time"],
                                          omit=CONFIG["omit"])

        # Print the fio command in the log and run it
        rc, _, stderr = ssh_conn.execute_command(cmd)
        assert rc == 0, stderr.read()
        assert stderr.read() == ""

        if os.path.isdir(logs_path):
            shutil.rmtree(logs_path)

        os.makedirs(logs_path)

        ssh_conn.scp_get_file("*.log", logs_path)
        rc, _, stderr = ssh_conn.execute_command("rm *.log")
        assert rc == 0, stderr.read()

        result = {}
        cpu_load = cpu_load_future.result()
        tag = "firecracker"
        assert tag in cpu_load and len(cpu_load[tag]) == 1

        data = list(cpu_load[tag].values())[0]
        data_len = len(data)
        assert data_len == CONFIG["time"]

        result[CPU_UTILIZATION_VMM] = sum(data) / data_len
        if DEBUG:
            result[CPU_UTILIZATION_VMM_SAMPLES_TAG] = data

        vcpus_util = 0
        for vcpu in range(basevm.vcpus_count):
            # We expect a single fc_vcpu thread tagged with
            # f`fc_vcpu {vcpu}`.
            tag = f"fc_vcpu {vcpu}"
            assert tag in cpu_load and len(cpu_load[tag]) == 1
            data = list(cpu_load[tag].values())[0]
            data_len = len(data)

            assert data_len == CONFIG["time"]
            if DEBUG:
                samples_tag = f"cpu_utilization_fc_vcpu_{vcpu}_samples"
                result[samples_tag] = data
            vcpus_util += sum(data) / data_len

        result[CPU_UTILIZATION_VCPUS_TOTAL] = vcpus_util
        return result


class DataDirection(Enum):
    """Operation type."""

    READ = 0
    WRITE = 1
    TRIM = 2

    def __str__(self):
        """Representation as string."""
        # pylint: disable=W0143
        if self.value == 0:
            return "read"
        # pylint: disable=W0143
        if self.value == 1:
            return "write"
        # pylint: disable=W0143
        if self.value == 2:
            return "trim"
        return ""


def read_values(cons, numjobs, env_id, mode, bs, measurement, logs_path):
    """Read the values for each measurement.

    The values are logged once every second. The time resolution is in msec.
    The log file format documentation can be found here:
    https://fio.readthedocs.io/en/latest/fio_doc.html#log-file-formats
    """
    values = {}

    for job_id in range(numjobs):
        file_path = f"{logs_path}/{env_id}/{mode}{bs}/{mode}" \
            f"{bs}_{measurement}.{job_id + 1}.log"
        file = open(file_path, encoding='utf-8')
        lines = file.readlines()

        direction_count = 1
        if mode.endswith("readwrite") or mode.endswith("rw"):
            direction_count = 2

        for idx in range(0, len(lines), direction_count):
            value_idx = idx//direction_count
            for direction in range(direction_count):
                data = lines[idx + direction].split(sep=",")
                data_dir = DataDirection(int(data[2].strip()))

                measurement_id = f"{measurement}_{str(data_dir)}"
                if measurement_id not in values:
                    values[measurement_id] = {}

                if value_idx not in values[measurement_id]:
                    values[measurement_id][value_idx] = []
                values[measurement_id][value_idx].append(int(data[1].strip()))

    for (measurement_id, value_indexes) in values.items():
        for idx in value_indexes:
            # Discard data points which were not measured by all jobs.
            if len(value_indexes[idx]) != numjobs:
                continue

            value = sum(value_indexes[idx])
            if DEBUG:
                cons.consume_custom(measurement_id, value)
            cons.consume_data(measurement_id, value)


def consume_fio_output(cons, result, numjobs, mode, bs, env_id, logs_path):
    """Consumer function."""
    cpu_utilization_vmm = result[CPU_UTILIZATION_VMM]
    cpu_utilization_vcpus = result[CPU_UTILIZATION_VCPUS_TOTAL]

    cons.consume_stat("Avg", CPU_UTILIZATION_VMM, cpu_utilization_vmm)
    cons.consume_stat("Avg",
                      CPU_UTILIZATION_VCPUS_TOTAL,
                      cpu_utilization_vcpus)

    read_values(cons, numjobs, env_id, mode, bs, "iops", logs_path)
    read_values(cons, numjobs, env_id, mode, bs, "bw", logs_path)


@pytest.mark.nonci
@pytest.mark.timeout(CONFIG["time"] * 1000)  # 1.40 hours
def test_block_performance(bin_cloner_path, results_file_dumper):
    """
    Test block performance for multiple vm configurations.

    @type: performance
    """
    logger = logging.getLogger(TEST_ID)
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
        'name': TEST_ID,
        'results_file_dumper': results_file_dumper
    }

    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])
    test_matrix.run_test(fio_workload)


def fio_workload(context):
    """Execute block device emulation benchmarking scenarios."""
    vm_builder = context.custom['builder']
    logger = context.custom["logger"]
    file_dumper = context.custom["results_file_dumper"]

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from artifacts.
    vm_instance = vm_builder.build(kernel=context.kernel,
                                   disks=[rw_disk],
                                   ssh_key=ssh_key,
                                   config=context.microvm)
    basevm = vm_instance.vm

    # Add a secondary block device for benchmark tests.
    fs = drive_tools.FilesystemFile(
        os.path.join(basevm.fsfiles, 'scratch'),
        CONFIG["block_device_size"]
    )
    basevm.add_drive('scratch', fs.path)
    basevm.start()

    # Get names of threads in Firecracker.
    current_cpu_id = 0
    basevm.pin_vmm(current_cpu_id)
    current_cpu_id += 1
    basevm.pin_api(current_cpu_id)
    for vcpu_id in range(basevm.vcpus_count):
        current_cpu_id += 1
        basevm.pin_vcpu(vcpu_id, current_cpu_id)

    st_core = core.Core(name=TEST_ID,
                        iterations=1,
                        custom={"microvm": context.microvm.name(),
                                "kernel": context.kernel.name(),
                                "disk": context.disk.name(),
                                "cpu_model_name": get_cpu_model_name()})

    logger.info("Testing with microvm: \"{}\", kernel {}, disk {}"
                .format(context.microvm.name(),
                        context.kernel.name(),
                        context.disk.name()))

    ssh_connection = net_tools.SSHConnection(basevm.ssh_config)
    env_id = f"{context.kernel.name()}/{context.disk.name()}/" \
             f"{context.microvm.name()}"

    for mode in CONFIG["fio_modes"]:
        for bs in CONFIG["fio_blk_sizes"]:
            fio_id = f"{mode}-bs{bs}"
            st_prod = st.producer.LambdaProducer(
                func=run_fio,
                func_kwargs={"env_id": env_id, "basevm": basevm,
                             "ssh_conn": ssh_connection, "mode": mode,
                             "bs": bs})
            st_cons = st.consumer.LambdaConsumer(
                metadata_provider=DictMetadataProvider(
                    CONFIG["measurements"],
                    BlockBaselinesProvider(env_id,
                                           fio_id)),
                func=consume_fio_output,
                func_kwargs={"numjobs": basevm.vcpus_count, "mode": mode,
                             "bs": bs, "env_id": env_id,
                             "logs_path": basevm.jailer.chroot_base_with_id()})
            st_core.add_pipe(st_prod, st_cons, tag=f"{env_id}/{fio_id}")

    # Gather results and verify pass criteria.
    try:
        result = st_core.run_exercise()
    except core.CoreException as err:
        handle_failure(file_dumper, err)

    dump_test_result(file_dumper, result)
