# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""
import concurrent
import json
import logging
import os
from enum import Enum
import shutil
from numbers import Number

import pytest


from conftest import _test_images_s3_bucket
from framework import utils
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.builder import MicrovmBuilder
from framework.matrix import TestContext, TestMatrix
from framework.statistics import core, criteria
from framework.statistics.baselines_util import BaselineProvider, DictQuery
from framework.statistics.types import DefaultMeasurement
from framework.utils import get_cpu_percent, CmdBuilder, eager_map
from framework.utils_cpuid import get_cpu_model_name
import host_tools.drive as drive_tools
import host_tools.network as net_tools  # pylint: disable=import-error
import framework.statistics as st


DEBUG = False
TEST_ID = "block_device_performance"
FIO = "fio"

# Measurements tags.
IOPS = "iops_{}"
BW = "bw_{}"
LAT = "lat_{}"
CLAT = "clat_{}"
SLAT = "slat_{}"
READ_OP = "read"
WRITE_OP = "write"
CPU_UTILIZATION_VMM = DefaultMeasurement.CPU_UTILIZATION_VMM.name.lower()
CPU_UTILIZATION_VMM_SAMPLES_TAG = f"{CPU_UTILIZATION_VMM}_samples"
CPU_UTILIZATION_VCPUS_TOTAL = \
    f"{DefaultMeasurement.CPU_UTILIZATION_VCPUS_TOTAL.name.lower()}"

# Measurements units.
KIBPERSEC_UNIT = "KiB/s"
IOPERSEC_UNIT = "io/s"

CONFIG_RAW_FILE = os.path.join(
    os.path.dirname(__file__),
    'configs/block_performance_test_config_raw.json')


with open(CONFIG_RAW_FILE) as config_raw:
    CONFIG = json.load(config_raw)


class BlockBaselineProvider(BaselineProvider):
    """Implementation of a baseline provider for the block performance test."""

    def __init__(self, cpu_model_name):
        """Block baseline provider initialization."""
        baselines = list(filter(
            lambda cpu_baseline: cpu_baseline["model"] == cpu_model_name,
            CONFIG["hosts"]["instances"]["m5d.metal"]["cpus"]))

        super().__init__(DictQuery(dict()))
        if len(baselines) > 0:
            super().__init__(DictQuery(baselines[0]))

    def target(self, key: str) -> Number:
        """Return the target value corresponding to the key."""
        return self._baselines.get(key)["target"]

    def delta(self, key: str) -> Number:
        """Return the delta value corresponding to the key."""
        return self.target(key) * self._baselines.get(key)[
            "delta_percentage"] / 100


def cpu_utilization_measurements():
    """CPU utilization measurements."""
    return [st.consumer.MeasurementDef.cpu_utilization_vmm(),
            st.consumer.MeasurementDef.cpu_utilization_vcpus_total()]


def ops_measurements(operation: str):
    """Return measurements based on the operation (read/write)."""
    return [st.consumer.MeasurementDef(IOPS.format(operation), IOPERSEC_UNIT),
            st.consumer.MeasurementDef(BW.format(operation), KIBPERSEC_UNIT)]


def measurements(mode):
    """Define metrics based on the mode."""
    ms = cpu_utilization_measurements()
    ms.extend(ops_measurements(READ_OP))
    if mode.endswith(WRITE_OP) or mode.endswith("rw"):
        ms.extend(ops_measurements(WRITE_OP))
    return ms


def no_criteria_cpu_utilization_stats():
    """Return the set of CPU utilization statistics without criteria."""
    return [
        st.consumer.StatisticDef.get_first_observation(CPU_UTILIZATION_VMM,
                                                       st_name="value"),
        st.consumer.StatisticDef.get_first_observation(
            CPU_UTILIZATION_VCPUS_TOTAL, st_name="value"
        )
    ]


def criteria_cpu_utilization_stats(env_id, fio_id):
    """Return the set of CPU utilization statistics with criteria."""
    cpu_util_vmm_key = f"baseline_cpu_utilization_vmm/{env_id}/{fio_id}"
    cpu_util_vcpus_total_key = "baseline_cpu_utilization_vcpus_total/" \
                               f"{env_id}/{fio_id}"
    blk_baseline_provider = BlockBaselineProvider(get_cpu_model_name())
    return [
        st.consumer.StatisticDef.get_first_observation(
            st_name="value",
            ms_name=CPU_UTILIZATION_VMM,
            criteria=criteria.EqualWith(
                blk_baseline_provider.target(cpu_util_vmm_key),
                blk_baseline_provider.delta(cpu_util_vmm_key))
        ),
        st.consumer.StatisticDef.get_first_observation(
            st_name="value",
            ms_name=CPU_UTILIZATION_VCPUS_TOTAL,
            criteria=criteria.EqualWith(
                blk_baseline_provider.target(cpu_util_vcpus_total_key),
                blk_baseline_provider.delta(cpu_util_vcpus_total_key))
        )
    ]


def no_criteria_ops_stats(operation: str):
    """Return statistics without criteria."""
    return [
        st.consumer.StatisticDef.avg(IOPS.format(operation)),
        st.consumer.StatisticDef.stddev(IOPS.format(operation)),
        st.consumer.StatisticDef.avg(BW.format(operation)),
        st.consumer.StatisticDef.stddev(BW.format(operation))]


def criteria_ops_stats(env_id: str, fio_id: str, operation: str):
    """Return statistics with pass criteria given by the baselines."""
    bw_key = f"baseline_{BW.format(operation)}/{env_id}/{fio_id}"
    iops_key = f"baseline_{IOPS.format(operation)}/{env_id}/{fio_id}"
    blk_baseline_provider = BlockBaselineProvider(get_cpu_model_name())
    return [
        st.consumer.StatisticDef.avg(
            IOPS.format(operation),
            criteria=criteria.EqualWith(
                blk_baseline_provider.target(iops_key),
                blk_baseline_provider.delta(iops_key))),
        st.consumer.StatisticDef.stddev(IOPS.format(operation)),
        st.consumer.StatisticDef.avg(
            BW.format(operation),
            criteria=criteria.EqualWith(
                blk_baseline_provider.target(bw_key),
                blk_baseline_provider.delta(bw_key))),
        st.consumer.StatisticDef.stddev(BW.format(operation))]


def statistics(mode, env_id, fio_id):
    """Define statistics based on the mode."""
    host_cpu_model = get_cpu_model_name()
    cpu_baselines = CONFIG["hosts"]["instances"]["m5d.metal"]["cpus"]
    host_cpu_baselines = None
    for baselines in cpu_baselines:
        if baselines["model"] == host_cpu_model:
            host_cpu_baselines = baselines
            break

    # Because of current fio modes (randread, randrw, readwrite, read) we can
    # always assume that we measure read operations.
    stats = no_criteria_cpu_utilization_stats()
    stats.extend(no_criteria_ops_stats("read"))

    if host_cpu_baselines:
        stats = criteria_cpu_utilization_stats(env_id, fio_id)
        stats.extend(criteria_ops_stats(env_id, fio_id, "read"))

    if mode.endswith("write") or mode.endswith("rw"):
        if host_cpu_baselines:
            stats.extend(criteria_ops_stats(env_id, fio_id, "write"))
        else:
            stats.extend(no_criteria_ops_stats("write"))

    return stats


def run_fio(env_id, basevm, ssh_conn, mode, bs):
    """Run a fio test in the specified mode with block size bs."""
    # Compute the fio command. Pin it to the first guest CPU.
    cmd = CmdBuilder(FIO) \
        .with_arg(f"--name={mode}-{bs}")\
        .with_arg(f"--rw={mode}")\
        .with_arg(f"--bs={bs}")\
        .with_arg("--filename=/dev/vdb") \
        .with_arg("--time_base=1") \
        .with_arg(f"--size={CONFIG['block_device_size']}M")\
        .with_arg("--direct=1") \
        .with_arg("--ioengine=libaio") \
        .with_arg("--iodepth=32") \
        .with_arg(f"--ramp_time={CONFIG['omit']}") \
        .with_arg(f"--numjobs={CONFIG['load_factor'] * basevm.vcpus_count}") \
        .with_arg("--randrepeat=0") \
        .with_arg(f"--runtime={CONFIG['time']}")\
        .with_arg(f"--write_iops_log={mode}{bs}") \
        .with_arg(f"--write_bw_log={mode}{bs}") \
        .with_arg("--log_avg_msec=1000") \
        .with_arg("--output-format=json+") \
        .build()

    rc, _, stderr = ssh_conn.execute_command(
        "echo 'none' > /sys/block/vdb/queue/scheduler")
    assert rc == 0, stderr.read()
    assert stderr.read() == ""

    utils.run_cmd("echo 3 > /proc/sys/vm/drop_caches")

    rc, _, stderr = ssh_conn.execute_command(
        "echo 3 > /proc/sys/vm/drop_caches")
    assert rc == 0, stderr.read()
    assert stderr.read() == ""

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

        if os.path.isdir(f"results/{env_id}/{mode}{bs}"):
            shutil.rmtree(f"results/{env_id}/{mode}{bs}")

        os.makedirs(f"results/{env_id}/{mode}{bs}")

        ssh_conn.scp_get_file("*.log", f"results/{env_id}/{mode}{bs}/")
        rc, _, stderr = ssh_conn.execute_command("rm *.log")
        assert rc == 0, stderr.read()

        result = dict()
        cpu_load = cpu_load_future.result()
        tag = "firecracker"
        assert tag in cpu_load and len(cpu_load[tag]) == 1

        data = list(cpu_load[tag].values())[0]
        data_len = len(data)
        assert data_len == CONFIG["time"]

        result[CPU_UTILIZATION_VMM] = sum(data)/data_len
        if DEBUG:
            result[CPU_UTILIZATION_VMM_SAMPLES_TAG] = data

        vcpus_util = 0
        for vcpu in range(basevm.vcpus_count):
            # We expect a single fc_vcpu thread tagged with
            # f`fc_vcpu {vcpu}`.
            tag = f"fc_vcpu {vcpu}"
            cpu_utilization_prefix = \
                DefaultMeasurement.CPU_UTILIZATION_VMM.name.lower()
            assert tag in cpu_load and len(cpu_load[tag]) == 1
            data = list(cpu_load[tag].values())[0]
            data_len = len(data)

            assert data_len == CONFIG["time"]
            if DEBUG:
                result[f"{cpu_utilization_prefix}_samples_fc_vcpu_{vcpu}"] = \
                    data
            vcpus_util += sum(data)/data_len

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


def read_values(cons, numjobs, env_id, mode, bs, measurement):
    """Read the values for each measurement.

    The values are logged once every second. The time resolution is in msec.
    The log file format documentation can be found here:
    https://fio.readthedocs.io/en/latest/fio_doc.html#log-file-formats
    """
    values = dict()

    for job_id in range(numjobs):
        file_path = f"results/{env_id}/{mode}{bs}/{mode}{bs}_{measurement}" \
                  f".{job_id + 1}.log"
        file = open(file_path)
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
                    values[measurement_id] = dict()

                if value_idx not in values[measurement_id]:
                    values[measurement_id][value_idx] = list()
                values[measurement_id][value_idx].append(int(data[1].strip()))

        for measurement_id in values:
            for idx in values[measurement_id]:
                # Discard data points which were not measured by all jobs.
                if len(values[measurement_id][idx]) != numjobs:
                    continue

                value = sum(values[measurement_id][idx])
                if DEBUG:
                    cons.consume_custom(measurement_id, value)
                cons.consume_measurement(measurement_id, value)


def consume_fio_output(cons, result, numjobs, mode, bs, env_id):
    """Consumer function."""
    cpu_utilization_vmm = result[CPU_UTILIZATION_VMM]
    cpu_utilization_vcpus = result[CPU_UTILIZATION_VCPUS_TOTAL]

    cons.consume_measurement(CPU_UTILIZATION_VMM, cpu_utilization_vmm)
    cons.consume_measurement(CPU_UTILIZATION_VCPUS_TOTAL,
                             cpu_utilization_vcpus)

    read_values(cons, numjobs, env_id, mode, bs, "iops")
    read_values(cons, numjobs, env_id, mode, bs, "bw")


@pytest.mark.nonci
@pytest.mark.timeout(CONFIG["time"] * 1000)
def test_block_performance(bin_cloner_path):
    """Test network throughput driver for multiple artifacts."""
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
        'name': TEST_ID
    }

    print(f"CPU model: {get_cpu_model_name()}.")

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

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from artifacts.
    basevm = vm_builder.build(kernel=context.kernel,
                              disks=[rw_disk],
                              ssh_key=ssh_key,
                              config=context.microvm)

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
                                "disk": context.disk.name()})

    logger.info("Testing with microvm: \"{}\", kernel {}, disk {}"
                .format(context.microvm.name(),
                        context.kernel.name(),
                        context.disk.name()))

    ssh_connection = net_tools.SSHConnection(basevm.ssh_config)
    env_id = f"{context.kernel.name()}/{context.disk.name()}"
    for mode in CONFIG["fio_modes"]:
        ms_defs = measurements(mode)
        for bs in CONFIG["fio_blk_sizes"]:
            fio_id = f"{mode}-bs{bs}-{basevm.vcpus_count}vcpu"
            st_defs = statistics(mode, env_id, fio_id)
            st_prod = st.producer.LambdaProducer(
                func=run_fio,
                func_kwargs={
                    "env_id": env_id,
                    "basevm": basevm,
                    "ssh_conn": ssh_connection,
                    "mode": mode,
                    "bs": bs
                }
            )

            numjobs = CONFIG['load_factor'] * basevm.vcpus_count
            st_cons = st.consumer.LambdaConsumer(
                consume_stats=False,
                func=consume_fio_output,
                func_kwargs={"numjobs": numjobs,
                             "mode": mode,
                             "bs": bs,
                             "env_id": env_id})
            eager_map(st_cons.set_measurement_def, ms_defs)
            eager_map(st_cons.set_stat_def, st_defs)
            st_core.add_pipe(st_prod, st_cons, tag=f"{env_id}/{fio_id}")

    st_core.run_exercise()
    basevm.kill()
