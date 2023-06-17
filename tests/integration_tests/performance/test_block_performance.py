# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""

import concurrent
import json
import os
import shutil
from enum import Enum

import pytest

import framework.stats as st
import host_tools.drive as drive_tools
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import (
    CmdBuilder,
    DictQuery,
    get_cpu_percent,
    get_kernel_version,
    run_cmd,
)
from integration_tests.performance.configs import defs

TEST_ID = "block_performance"
kernel_version = get_kernel_version(level=1)
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID, kernel_version)
CONFIG_NAME_ABS = os.path.join(defs.CFG_LOCATION, CONFIG_NAME_REL)
CONFIG = json.load(open(CONFIG_NAME_ABS, encoding="utf-8"))

DEBUG = False
FIO = "fio"

# Measurements tags.
CPU_UTILIZATION_VMM = "cpu_utilization_vmm"
CPU_UTILIZATION_VMM_SAMPLES_TAG = "cpu_utilization_vmm_samples"
CPU_UTILIZATION_VCPUS_TOTAL = "cpu_utilization_vcpus_total"


# pylint: disable=R0903
class BlockBaselinesProvider(BaselineProvider):
    """Implementation of a baseline provider for the block performance test."""

    def __init__(self, env_id, fio_id):
        """Block baseline provider initialization."""
        baseline = self.read_baseline(CONFIG)
        super().__init__(DictQuery(baseline))
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


def run_fio(env_id, basevm, mode, bs):
    """Run a fio test in the specified mode with block size bs."""
    logs_path = f"{basevm.jailer.chroot_base_with_id()}/{env_id}/{mode}{bs}"

    # Compute the fio command. Pin it to the first guest CPU.
    cmd = (
        CmdBuilder(FIO)
        .with_arg(f"--name={mode}-{bs}")
        .with_arg(f"--rw={mode}")
        .with_arg(f"--bs={bs}")
        .with_arg("--filename=/dev/vdb")
        .with_arg("--time_base=1")
        .with_arg(f"--size={CONFIG['block_device_size']}M")
        .with_arg("--direct=1")
        .with_arg("--ioengine=libaio")
        .with_arg("--iodepth=32")
        .with_arg(f"--ramp_time={CONFIG['omit']}")
        .with_arg(f"--numjobs={CONFIG['load_factor'] * basevm.vcpus_count}")
        .with_arg("--randrepeat=0")
        .with_arg(f"--runtime={CONFIG['time']}")
        .with_arg(f"--write_bw_log={mode}{bs}")
        .with_arg("--log_avg_msec=1000")
        .with_arg("--output-format=json+")
        .build()
    )

    rc, _, stderr = basevm.ssh.execute_command(
        "echo 'none' > /sys/block/vdb/queue/scheduler"
    )
    assert rc == 0, stderr.read()
    assert stderr.read() == ""

    # First, flush all guest cached data to host, then drop guest FS caches.
    rc, _, stderr = basevm.ssh.execute_command("sync")
    assert rc == 0, stderr.read()
    assert stderr.read() == ""
    rc, _, stderr = basevm.ssh.execute_command("echo 3 > /proc/sys/vm/drop_caches")
    assert rc == 0, stderr.read()
    assert stderr.read() == ""

    # Then, flush all host cached data to hardware, also drop host FS caches.
    run_cmd("sync")
    run_cmd("echo 3 > /proc/sys/vm/drop_caches")

    # Start the CPU load monitor.
    with concurrent.futures.ThreadPoolExecutor() as executor:
        cpu_load_future = executor.submit(
            get_cpu_percent,
            basevm.jailer_clone_pid,
            CONFIG["time"],
            omit=CONFIG["omit"],
        )

        # Print the fio command in the log and run it
        rc, _, stderr = basevm.ssh.execute_command(cmd)
        assert rc == 0, stderr.read()
        assert stderr.read() == ""

        if os.path.isdir(logs_path):
            shutil.rmtree(logs_path)

        os.makedirs(logs_path)

        basevm.ssh.scp_get_file("*.log", logs_path)
        rc, _, stderr = basevm.ssh.execute_command("rm *.log")
        assert rc == 0, stderr.read()

        result = {}
        cpu_load = cpu_load_future.result()
        tag = "firecracker"
        assert tag in cpu_load and len(cpu_load[tag]) > 0

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
        file_path = (
            f"{logs_path}/{env_id}/{mode}{bs}/{mode}"
            f"{bs}_{measurement}.{job_id + 1}.log"
        )
        file = open(file_path, encoding="utf-8")
        lines = file.readlines()

        direction_count = 1
        if mode.endswith("rw"):
            direction_count = 2

        for idx in range(0, len(lines), direction_count):
            value_idx = idx // direction_count
            for direction in range(direction_count):
                data = lines[idx + direction].split(sep=",")
                data_dir = DataDirection(int(data[2].strip()))

                measurement_id = f"{measurement}_{str(data_dir)}"
                if measurement_id not in values:
                    values[measurement_id] = {}

                if value_idx not in values[measurement_id]:
                    values[measurement_id][value_idx] = []
                values[measurement_id][value_idx].append(int(data[1].strip()))

    for measurement_id, value_indexes in values.items():
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
    cons.consume_stat("Avg", CPU_UTILIZATION_VCPUS_TOTAL, cpu_utilization_vcpus)

    read_values(cons, numjobs, env_id, mode, bs, "bw", logs_path)


@pytest.mark.nonci
@pytest.mark.timeout(CONFIG["time"] * 1000)  # 1.40 hours
@pytest.mark.parametrize("vcpus", [1, 2])
def test_block_performance(
    microvm_factory,
    network_config,
    guest_kernel,
    rootfs,
    vcpus,
    io_engine,
    st_core,
):
    """
    Execute block device emulation benchmarking scenarios.
    """
    guest_mem_mib = 1024
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn()
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=guest_mem_mib)
    vm.ssh_network_config(network_config, "1")
    # Add a secondary block device for benchmark tests.
    fs = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "scratch"), CONFIG["block_device_size"]
    )
    vm.add_drive("scratch", fs.path, io_engine=io_engine)
    vm.start()

    # Get names of threads in Firecracker.
    current_cpu_id = 0
    vm.pin_vmm(current_cpu_id)
    current_cpu_id += 1
    vm.pin_api(current_cpu_id)
    for vcpu_id in range(vm.vcpus_count):
        current_cpu_id += 1
        vm.pin_vcpu(vcpu_id, current_cpu_id)

    # define test dimensions
    st_core.name = TEST_ID
    microvm_cfg = f"{vcpus}vcpu_{guest_mem_mib}mb.json"
    st_core.custom.update(
        {
            "guest_config": microvm_cfg.removesuffix(".json"),
            "io_engine": io_engine,
        }
    )

    env_id = f"{guest_kernel.name()}/{rootfs.name()}/{io_engine.lower()}_{microvm_cfg}"

    for mode in CONFIG["fio_modes"]:
        for bs in CONFIG["fio_blk_sizes"]:
            fio_id = f"{mode}-bs{bs}"
            st_prod = st.producer.LambdaProducer(
                func=run_fio,
                func_kwargs={
                    "env_id": env_id,
                    "basevm": vm,
                    "mode": mode,
                    "bs": bs,
                },
            )
            st_cons = st.consumer.LambdaConsumer(
                metadata_provider=DictMetadataProvider(
                    CONFIG["measurements"], BlockBaselinesProvider(env_id, fio_id)
                ),
                func=consume_fio_output,
                func_kwargs={
                    "numjobs": vm.vcpus_count,
                    "mode": mode,
                    "bs": bs,
                    "env_id": env_id,
                    "logs_path": vm.jailer.chroot_base_with_id(),
                },
            )
            st_core.add_pipe(st_prod, st_cons, tag=f"{env_id}/{fio_id}")

    # Gather results and verify pass criteria.
    st_core.run_exercise()
