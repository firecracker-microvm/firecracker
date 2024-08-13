# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""

import concurrent
import os
import shutil
from pathlib import Path

import pytest

import host_tools.drive as drive_tools
from framework.utils import CmdBuilder, check_output, track_cpu_utilization

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
    _, _, stderr = microvm.ssh.check_output(
        "echo 'none' > /sys/block/vdb/queue/scheduler"
    )
    assert stderr == ""

    # First, flush all guest cached data to host, then drop guest FS caches.
    _, _, stderr = microvm.ssh.check_output("sync")
    assert stderr == ""
    _, _, stderr = microvm.ssh.check_output("echo 3 > /proc/sys/vm/drop_caches")
    assert stderr == ""

    # Then, flush all host cached data to hardware, also drop host FS caches.
    check_output("sync")
    check_output("echo 3 > /proc/sys/vm/drop_caches")


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
            track_cpu_utilization,
            microvm.firecracker_pid,
            RUNTIME_SEC,
            omit=WARMUP_SEC,
        )

        # Print the fio command in the log and run it
        rc, _, stderr = microvm.ssh.run(f"cd /tmp; {cmd}")
        assert rc == 0, stderr
        assert stderr == ""

        microvm.ssh.scp_get("/tmp/*.log", logs_path)
        microvm.ssh.check_output("rm /tmp/*.log")

        return logs_path, cpu_load_future.result()


def process_fio_logs(vm, fio_mode, logs_dir, metrics):
    """Parses the fio logs in `{logs_dir}/{fio_mode}_bw.*.log and emits their contents as CloudWatch metrics"""

    data = [
        Path(f"{logs_dir}/{fio_mode}_bw.{job_id + 1}.log")
        .read_text("UTF-8")
        .splitlines()
        for job_id in range(vm.vcpus_count)
    ]

    for tup in zip(*data):
        bw_read = 0
        bw_write = 0

        for line in tup:
            _, value, direction, _ = line.split(",", maxsplit=3)
            value = int(value.strip())

            # See https://fio.readthedocs.io/en/latest/fio_doc.html#log-file-formats
            match direction.strip():
                case "0":
                    bw_read += value
                case "1":
                    bw_write += value
                case _:
                    assert False

        if bw_read:
            metrics.put_metric("bw_read", bw_read, "Kilobytes/Second")
        if bw_write:
            metrics.put_metric("bw_write", bw_write, "Kilobytes/Second")


@pytest.mark.timeout(120)
@pytest.mark.nonci
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
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=GUEST_MEM_MIB)
    vm.add_net_iface()
    # Add a secondary block device for benchmark tests.
    fs = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "scratch"), BLOCK_DEVICE_SIZE_MB
    )
    vm.add_drive("scratch", fs.path, io_engine=io_engine)
    vm.start()

    metrics.set_dimensions(
        {
            "performance_test": "test_block_performance",
            "io_engine": io_engine,
            "fio_mode": fio_mode,
            "fio_block_size": str(fio_block_size),
            **vm.dimensions,
        }
    )

    vm.pin_threads(0)

    logs_dir, cpu_util = run_fio(vm, fio_mode, fio_block_size)

    process_fio_logs(vm, fio_mode, logs_dir, metrics)

    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")


@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("fio_mode", ["randread"])
@pytest.mark.parametrize("fio_block_size", [4096], ids=["bs4096"])
def test_block_vhost_user_performance(
    microvm_factory,
    guest_kernel,
    rootfs,
    vcpus,
    fio_mode,
    fio_block_size,
    metrics,
):
    """
    Execute block device emulation benchmarking scenarios.
    """

    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=GUEST_MEM_MIB)
    vm.add_net_iface()

    # Add a secondary block device for benchmark tests.
    fs = drive_tools.FilesystemFile(size=BLOCK_DEVICE_SIZE_MB)
    vm.add_vhost_user_drive("scratch", fs.path)
    vm.start()

    metrics.set_dimensions(
        {
            "performance_test": "test_block_performance",
            "io_engine": "vhost-user",
            "fio_mode": fio_mode,
            "fio_block_size": str(fio_block_size),
            **vm.dimensions,
        }
    )

    next_cpu = vm.pin_threads(0)
    vm.disks_vhost_user["scratch"].pin(next_cpu)

    logs_dir, cpu_util = run_fio(vm, fio_mode, fio_block_size)

    process_fio_logs(vm, fio_mode, logs_dir, metrics)

    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")
