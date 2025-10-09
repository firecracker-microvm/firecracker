# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""

import concurrent
import os

import pytest

import framework.utils_fio as fio
import host_tools.drive as drive_tools
from framework.utils import check_output, track_cpu_utilization

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


def run_fio(
    microvm, mode: fio.Mode, block_size: int, test_output_dir, fio_engine: fio.Engine
):
    """Run a fio test in the specified mode with block size bs."""
    cmd = fio.build_cmd(
        "/dev/vdb",
        BLOCK_DEVICE_SIZE_MB,
        block_size,
        mode,
        microvm.vcpus_count,
        fio_engine,
        RUNTIME_SEC,
        WARMUP_SEC,
    )

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

        microvm.ssh.scp_get("/tmp/fio.json", test_output_dir)
        microvm.ssh.scp_get("/tmp/*.log", test_output_dir)

        return cpu_load_future.result()


def emit_fio_metrics(logs_dir, metrics):
    """Parses the fio logs in `logs_dir` and emits their contents as CloudWatch metrics"""
    bw_reads, bw_writes = fio.process_log_files(logs_dir, fio.LogType.BW)
    for tup in zip(*bw_reads):
        metrics.put_metric("bw_read", sum(tup), "Kilobytes/Second")
    for tup in zip(*bw_writes):
        metrics.put_metric("bw_write", sum(tup), "Kilobytes/Second")

    clat_reads, clat_writes = fio.process_log_files(logs_dir, fio.LogType.CLAT)
    # latency values in fio logs are in nanoseconds, but cloudwatch only supports
    # microseconds as the more granular unit, so need to divide by 1000.
    for tup in zip(*clat_reads):
        for value in tup:
            metrics.put_metric("clat_read", value / 1000, "Microseconds")
    for tup in zip(*clat_writes):
        for value in tup:
            metrics.put_metric("clat_write", value / 1000, "Microseconds")


@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("fio_mode", [fio.Mode.RANDREAD, fio.Mode.RANDWRITE])
@pytest.mark.parametrize("fio_block_size", [4096], ids=["bs4096"])
@pytest.mark.parametrize("fio_engine", [fio.Engine.LIBAIO, fio.Engine.PSYNC])
def test_block_performance(
    uvm_plain_acpi,
    vcpus,
    fio_mode,
    fio_block_size,
    fio_engine,
    io_engine,
    metrics,
    results_dir,
):
    """
    Execute block device emulation benchmarking scenarios.
    """
    vm = uvm_plain_acpi
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
            "fio_engine": fio_engine,
            **vm.dimensions,
        }
    )

    vm.pin_threads(0)

    cpu_util = run_fio(vm, fio_mode, fio_block_size, results_dir, fio_engine)

    emit_fio_metrics(results_dir, metrics)

    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")


@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("fio_mode", [fio.Mode.RANDREAD])
@pytest.mark.parametrize("fio_block_size", [4096], ids=["bs4096"])
def test_block_vhost_user_performance(
    uvm_plain_acpi,
    vcpus,
    fio_mode,
    fio_block_size,
    metrics,
    results_dir,
):
    """
    Execute block device emulation benchmarking scenarios.
    """

    vm = uvm_plain_acpi
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
            "fio_engine": "libaio",
            **vm.dimensions,
        }
    )

    next_cpu = vm.pin_threads(0)
    vm.disks_vhost_user["scratch"].pin(next_cpu)

    cpu_util = run_fio(vm, fio_mode, fio_block_size, results_dir, fio.Engine.LIBAIO)

    emit_fio_metrics(results_dir, metrics)

    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")
