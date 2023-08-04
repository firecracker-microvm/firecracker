# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""

import concurrent
import json
import os
import shutil
from enum import Enum
from pathlib import Path

import pytest

import framework.stats as st
import host_tools.drive as drive_tools
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import (
    CmdBuilder,
    get_cpu_percent,
    get_kernel_version,
    run_cmd,
    summarize_cpu_percent,
)
from integration_tests.performance.configs import defs

TEST_ID = "block_performance"
kernel_version = get_kernel_version(level=1)
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID, kernel_version)
CONFIG_NAME_ABS = defs.CFG_LOCATION / CONFIG_NAME_REL

FIO = "fio"

# Measurements tags.
CPU_UTILIZATION_VMM = "cpu_utilization_vmm"
CPU_UTILIZATION_VMM_SAMPLES_TAG = "cpu_utilization_vmm_samples"
CPU_UTILIZATION_VCPUS_TOTAL = "cpu_utilization_vcpus_total"

# size of the block device used in the test, in MB
BLOCK_DEVICE_SIZE_MB = 2048

# How many fio workloads should be spawned per vcpu
LOAD_FACTOR = 1

# Time (in seconds) for which fio "warms up"
WARMUP_SEC = 10

# Time (in seconds) for which fio runs after warmup is done
RUNTIME_SEC = 300


# pylint: disable=R0903
class BlockBaselinesProvider(BaselineProvider):
    """Implementation of a baseline provider for the block performance test."""

    def __init__(self, env_id, fio_id, raw_baselines):
        """Block baseline provider initialization."""
        super().__init__(raw_baselines)

        self._tag = "baselines/{}/" + env_id + "/{}/" + fio_id

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
        .with_arg(f"--size={BLOCK_DEVICE_SIZE_MB}M")
        .with_arg("--direct=1")
        .with_arg("--ioengine=libaio")
        .with_arg("--iodepth=32")
        .with_arg(f"--ramp_time={WARMUP_SEC}")
        .with_arg(f"--numjobs={basevm.vcpus_count}")
        # Set affinity of the entire fio process to a set of vCPUs equal in size to number of workers
        .with_arg(
            f"--cpus_allowed={','.join(str(i) for i in range(basevm.vcpus_count))}"
        )
        # Instruct fio to pin one worker per vcpu
        .with_arg("--cpus_allowed_policy=split")
        .with_arg("--randrepeat=0")
        .with_arg(f"--runtime={RUNTIME_SEC}")
        .with_arg(f"--write_bw_log={mode}{bs}")
        .with_arg("--log_avg_msec=1000")
        .with_arg("--output-format=json+")
        .build()
    )

    rc, _, stderr = basevm.ssh.run("echo 'none' > /sys/block/vdb/queue/scheduler")
    assert rc == 0, stderr
    assert stderr == ""

    # First, flush all guest cached data to host, then drop guest FS caches.
    rc, _, stderr = basevm.ssh.run("sync")
    assert rc == 0, stderr
    assert stderr == ""
    rc, _, stderr = basevm.ssh.run("echo 3 > /proc/sys/vm/drop_caches")
    assert rc == 0, stderr
    assert stderr == ""

    # Then, flush all host cached data to hardware, also drop host FS caches.
    run_cmd("sync")
    run_cmd("echo 3 > /proc/sys/vm/drop_caches")

    # Start the CPU load monitor.
    with concurrent.futures.ThreadPoolExecutor() as executor:
        cpu_load_future = executor.submit(
            get_cpu_percent,
            basevm.jailer_clone_pid,
            RUNTIME_SEC,
            omit=WARMUP_SEC,
        )

        # Print the fio command in the log and run it
        rc, _, stderr = basevm.ssh.run(f"cd /tmp; {cmd}")
        assert rc == 0, stderr
        assert stderr == ""

        if os.path.isdir(logs_path):
            shutil.rmtree(logs_path)

        os.makedirs(logs_path)

        basevm.ssh.scp_get("/tmp/*.log", logs_path)
        rc, _, stderr = basevm.ssh.run("rm /tmp/*.log")
        assert rc == 0, stderr

        return cpu_load_future.result()


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
            Path(logs_path)
            / env_id
            / f"{mode}{bs}"
            / f"{mode}{bs}_{measurement}.{job_id + 1}.log"
        )
        lines = file_path.read_text(encoding="utf-8").splitlines()

        direction_count = 1

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

    for measurement_id, data in values.items():
        for time in data:
            # Discard data points which were not measured by all jobs.
            if len(data[time]) != numjobs:
                continue

            yield from [
                (f"{measurement_id}_{vcpu}", throughput, "Megabits/Second")
                for vcpu, throughput in enumerate(data[time])
            ]

            value = sum(data[time])
            cons.consume_data(measurement_id, value)


def consume_fio_output(cons, cpu_load, numjobs, mode, bs, env_id, logs_path):
    """Consumer function."""
    vmm_util, vcpu_util = summarize_cpu_percent(cpu_load)

    cons.consume_stat("Avg", CPU_UTILIZATION_VMM, vmm_util)
    cons.consume_stat("Avg", CPU_UTILIZATION_VCPUS_TOTAL, vcpu_util)

    for thread_name, data in cpu_load.items():
        yield from [
            (f"cpu_utilization_{thread_name}", x, "Percent")
            for x in list(data.values())[0]
        ]

    yield from read_values(cons, numjobs, env_id, mode, bs, "bw", logs_path)


@pytest.mark.nonci
@pytest.mark.timeout(RUNTIME_SEC * 1000)  # 1.40 hours
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("fio_mode", ["randread", "randwrite"])
@pytest.mark.parametrize("fio_block_size", [4096], ids=["bs4096"])
def test_block_performance(
    microvm_factory,
    guest_kernel,
    rootfs,
    vcpus,
    fio_mode,
    fio_block_size,
    io_engine,
    st_core,
):
    """
    Execute block device emulation benchmarking scenarios.
    """
    guest_mem_mib = 1024
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=guest_mem_mib)
    vm.add_net_iface()
    # Add a secondary block device for benchmark tests.
    fs = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "scratch"), BLOCK_DEVICE_SIZE_MB
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

    env_id = f"{st_core.env_id_prefix}/{io_engine.lower()}_{microvm_cfg}"

    fio_id = f"{fio_mode}-bs{fio_block_size}"
    st_prod = st.producer.LambdaProducer(
        func=run_fio,
        func_kwargs={
            "env_id": env_id,
            "basevm": vm,
            "mode": fio_mode,
            "bs": fio_block_size,
        },
    )

    raw_baselines = json.loads(CONFIG_NAME_ABS.read_text("utf-8"))

    st_cons = st.consumer.LambdaConsumer(
        metadata_provider=DictMetadataProvider(
            raw_baselines["measurements"],
            BlockBaselinesProvider(env_id, fio_id, raw_baselines),
        ),
        func=consume_fio_output,
        func_kwargs={
            "numjobs": vm.vcpus_count,
            "mode": fio_mode,
            "bs": fio_block_size,
            "env_id": env_id,
            "logs_path": vm.jailer.chroot_base_with_id(),
        },
    )
    st_core.add_pipe(st_prod, st_cons, tag=f"{env_id}/{fio_id}")

    # Gather results and verify pass criteria.
    st_core.run_exercise()
