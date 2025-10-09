# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for pmem device"""

import concurrent
import os
from pathlib import Path

import pytest

import framework.utils_fio as fio
import host_tools.drive as drive_tools
from framework.utils import track_cpu_utilization

PMEM_DEVICE_SIZE_MB = 2048
PMEM_DEVICE_SIZE_SINGLE_READ_MB = 512
WARMUP_SEC = 10
RUNTIME_SEC = 30
GUEST_MEM_MIB = 1024


def run_fio(
    microvm, test_output_dir, mode: fio.Mode, block_size: int, fio_engine: fio.Engine
):
    """Run a normal fio test"""
    cmd = fio.build_cmd(
        "/dev/pmem0",
        PMEM_DEVICE_SIZE_MB,
        block_size,
        mode,
        microvm.vcpus_count,
        fio_engine,
        RUNTIME_SEC,
        WARMUP_SEC,
    )

    with concurrent.futures.ThreadPoolExecutor() as executor:
        cpu_load_future = executor.submit(
            track_cpu_utilization,
            microvm.firecracker_pid,
            RUNTIME_SEC,
            omit=WARMUP_SEC,
        )

        rc, _, stderr = microvm.ssh.run(f"cd /tmp; {cmd}")
        assert rc == 0, stderr
        assert stderr == ""

        microvm.ssh.scp_get("/tmp/fio.json", test_output_dir)
        microvm.ssh.scp_get("/tmp/*.log", test_output_dir)

        return cpu_load_future.result()


def emit_fio_metrics(logs_dir, metrics):
    """Parses the fio logs and emits bandwidth as metrics"""
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
def test_pmem_performance(
    uvm_plain_acpi,
    vcpus,
    fio_mode,
    fio_block_size,
    fio_engine,
    metrics,
    results_dir,
):
    """
    Measure performance of pmem device
    """
    vm = uvm_plain_acpi
    vm.memory_monitor = None
    vm.spawn()
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=GUEST_MEM_MIB)
    vm.add_net_iface()
    # Add a secondary block device for benchmark tests.
    fs = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "scratch"), PMEM_DEVICE_SIZE_MB
    )
    vm.add_pmem("scratch", fs.path, False, False)
    vm.start()
    vm.pin_threads(0)

    metrics.set_dimensions(
        {
            "performance_test": "test_pmem_performance",
            "fio_mode": fio_mode,
            "fio_block_size": str(fio_block_size),
            "fio_engine": fio_engine,
            **vm.dimensions,
        }
    )

    # Do a full read run before benchmarking to deal with shadow page faults.
    # The impact of shadow page faults is tested in another test.
    run_fio_single_read(vm, 0, results_dir, fio_block_size)

    cpu_util = run_fio(vm, results_dir, fio_mode, fio_block_size, fio_engine)
    emit_fio_metrics(results_dir, metrics)
    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")


def run_fio_single_read(microvm, run_index, test_output_dir, block_size: int):
    """
    Run a single full read test with fio.
    The test is single threaded and uses only `libaio` since we just need
    to test a sequential
    """
    cmd = fio.build_cmd(
        "/dev/pmem0",
        None,
        block_size,
        fio.Mode.READ,
        1,
        fio.Engine.LIBAIO,
        None,
        None,
        False,
    )

    rc, _, stderr = microvm.ssh.run(f"cd /tmp; {cmd}")
    assert rc == 0, stderr
    assert stderr == ""

    log_path = Path(test_output_dir) / f"fio_{run_index}.json"
    microvm.ssh.scp_get("/tmp/fio.json", log_path)


def emit_fio_single_read_metrics(logs_dir, metrics):
    """Process json output of the fio command and emmit `read` metrics"""
    bw_reads, _ = fio.process_json_files(logs_dir)
    for reads in bw_reads:
        metrics.put_metric("bw_read", sum(reads) / 1000, "Kilobytes/Second")


@pytest.mark.nonci
@pytest.mark.parametrize("fio_block_size", [4096], ids=["bs4096"])
def test_pmem_first_read(
    microvm_factory,
    guest_kernel_acpi,
    rootfs,
    fio_block_size,
    metrics,
    results_dir,
):
    """
    Measure performance of a first full read from the pmem device.
    Values should be lower than in normal perf test since the first
    read of each page should also trigger a KVM internal page fault
    which should slow things down.
    """

    for i in range(10):
        vm = microvm_factory.build(
            guest_kernel_acpi, rootfs, pci=True, monitor_memory=False
        )
        vm.spawn()
        vm.basic_config(mem_size_mib=GUEST_MEM_MIB)
        vm.add_net_iface()

        fs = drive_tools.FilesystemFile(
            os.path.join(vm.fsfiles, "scratch"),
            PMEM_DEVICE_SIZE_SINGLE_READ_MB,
        )
        vm.add_pmem("scratch", fs.path, False, False)

        vm.start()
        vm.pin_threads(0)

        metrics.set_dimensions(
            {
                "performance_test": "test_pmem_first_read",
                "fio_block_size": str(fio_block_size),
                **vm.dimensions,
            }
        )
        run_fio_single_read(vm, i, results_dir, fio_block_size)

    emit_fio_single_read_metrics(results_dir, metrics)
