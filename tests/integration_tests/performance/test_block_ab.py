# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""

import concurrent
import os
import shutil
from pathlib import Path

import pytest

import host_tools.drive as drive_tools
from framework.utils import CmdBuilder, get_cpu_percent, run_cmd

# size of the block device used in the test, in MB
BLOCK_DEVICE_SIZE_MB = 2048

# Time (in seconds) for which fio "warms up"
WARMUP_SEC = 10

# Time (in seconds) for which fio runs after warmup is done
RUNTIME_SEC = 30

# VM guest memory size
GUEST_MEM_MIB = 1024


def prepare_microvm_for_test(microvm):
    """Prepares the microvm for running a fio-based performance test by tweaking
    various performance related parameters."""
    rc, _, stderr = microvm.ssh.run("echo 'none' > /sys/block/vdb/queue/scheduler")
    assert rc == 0, stderr
    assert stderr == ""

    # First, flush all guest cached data to host, then drop guest FS caches.
    rc, _, stderr = microvm.ssh.run("sync")
    assert rc == 0, stderr
    assert stderr == ""
    rc, _, stderr = microvm.ssh.run("echo 3 > /proc/sys/vm/drop_caches")
    assert rc == 0, stderr
    assert stderr == ""

    # Then, flush all host cached data to hardware, also drop host FS caches.
    run_cmd("sync")
    run_cmd("echo 3 > /proc/sys/vm/drop_caches")


def run_fio(microvm, mode, block_size):
    """Run a fio test in the specified mode with block size bs."""
    cmd = (
        CmdBuilder("fio")
        .with_arg(f"--name={mode}-{block_size}")
        .with_arg(f"--rw={mode}")
        .with_arg(f"--bs={block_size}")
        .with_arg("--filename=/dev/vdb")
        .with_arg("--time_base=1")
        .with_arg(f"--size={BLOCK_DEVICE_SIZE_MB}M")
        .with_arg("--direct=1")
        .with_arg("--ioengine=libaio")
        .with_arg("--iodepth=32")
        .with_arg(f"--ramp_time={WARMUP_SEC}")
        .with_arg(f"--numjobs={microvm.vcpus_count}")
        # Set affinity of the entire fio process to a set of vCPUs equal in size to number of workers
        .with_arg(
            f"--cpus_allowed={','.join(str(i) for i in range(microvm.vcpus_count))}"
        )
        # Instruct fio to pin one worker per vcpu
        .with_arg("--cpus_allowed_policy=split")
        .with_arg("--randrepeat=0")
        .with_arg(f"--runtime={RUNTIME_SEC}")
        .with_arg(f"--write_bw_log={mode}")
        .with_arg("--log_avg_msec=1000")
        .with_arg("--output-format=json+")
        .build()
    )

    logs_path = Path(microvm.jailer.chroot_base_with_id()) / "fio_output"

    if logs_path.is_dir():
        shutil.rmtree(logs_path)

    logs_path.mkdir()

    prepare_microvm_for_test(microvm)

    # Start the CPU load monitor.
    with concurrent.futures.ThreadPoolExecutor() as executor:
        cpu_load_future = executor.submit(
            get_cpu_percent,
            microvm.jailer_clone_pid,
            RUNTIME_SEC,
            omit=WARMUP_SEC,
        )

        # Print the fio command in the log and run it
        rc, _, stderr = microvm.ssh.run(f"cd /tmp; {cmd}")
        assert rc == 0, stderr
        assert stderr == ""

        microvm.ssh.scp_get("/tmp/*.log", logs_path)
        rc, _, stderr = microvm.ssh.run("rm /tmp/*.log")
        assert rc == 0, stderr

        return logs_path, cpu_load_future.result()


def process_fio_logs(vm, fio_mode, logs_dir, metrics):
    """Parses the fio logs in `{logs_dir}/{fio_mode}_bw.*.log and emits their contents as CloudWatch metrics"""
    for job_id in range(vm.vcpus_count):
        data = Path(f"{logs_dir}/{fio_mode}_bw.{job_id + 1}.log").read_text("UTF-8")

        for line in data.splitlines():
            _, value, direction, _ = line.split(",", maxsplit=3)
            value = int(value.strip())

            # See https://fio.readthedocs.io/en/latest/fio_doc.html#log-file-formats
            match direction.strip():
                case "0":
                    metrics.put_metric("bw_read", value, "Kilobytes/Second")
                case "1":
                    metrics.put_metric("bw_write", value, "Kilobytes/Second")
                case _:
                    assert False


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
    metrics,
):
    """
    Execute block device emulation benchmarking scenarios.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=GUEST_MEM_MIB)
    vm.add_net_iface()
    # Add a secondary block device for benchmark tests.
    fs = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "scratch"), BLOCK_DEVICE_SIZE_MB
    )
    vm.add_drive("scratch", fs.path, io_engine=io_engine)
    vm.start()

    # Pin uVM threads to physical cores.
    assert vm.pin_vmm(0), "Failed to pin firecracker thread."
    assert vm.pin_api(1), "Failed to pin fc_api thread."
    for i in range(vm.vcpus_count):
        assert vm.pin_vcpu(i, i + 2), f"Failed to pin fc_vcpu {i} thread."

    logs_dir, cpu_load = run_fio(vm, fio_mode, fio_block_size)

    process_fio_logs(vm, fio_mode, logs_dir, metrics)

    for cpu_util_data_point in list(cpu_load["firecracker"].values())[0]:
        metrics.put_metric("cpu_utilization_vmm", cpu_util_data_point, "Percent")

    metrics.set_dimensions(
        {
            "performance_test": "test_block_performance",
            "io_engine": io_engine,
            "fio_mode": fio_mode,
            "fio_block_size": str(fio_block_size),
            **vm.dimensions,
        }
    )
