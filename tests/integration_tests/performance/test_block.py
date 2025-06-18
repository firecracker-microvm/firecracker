# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""

import concurrent
import glob
import os
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


def run_fio(microvm, mode, block_size, test_output_dir, fio_engine="libaio"):
    """Run a fio test in the specified mode with block size bs."""
    cmd = (
        CmdBuilder("fio")
        .with_arg(f"--name={mode}-{block_size}")
        .with_arg(f"--numjobs={microvm.vcpus_count}")
        .with_arg(f"--runtime={RUNTIME_SEC}")
        .with_arg("--time_based=1")
        .with_arg(f"--ramp_time={WARMUP_SEC}")
        .with_arg("--filename=/dev/vdb")
        .with_arg("--direct=1")
        .with_arg(f"--rw={mode}")
        .with_arg("--randrepeat=0")
        .with_arg(f"--bs={block_size}")
        .with_arg(f"--size={BLOCK_DEVICE_SIZE_MB}M")
        .with_arg(f"--ioengine={fio_engine}")
        .with_arg("--iodepth=32")
        # Set affinity of the entire fio process to a set of vCPUs equal in size to number of workers
        .with_arg(
            f"--cpus_allowed={','.join(str(i) for i in range(microvm.vcpus_count))}"
        )
        # Instruct fio to pin one worker per vcpu
        .with_arg("--cpus_allowed_policy=split")
        .with_arg("--log_avg_msec=1000")
        .with_arg(f"--write_bw_log={mode}")
        .with_arg("--output-format=json+")
        .with_arg("--output=/tmp/fio.json")
    )

    # Latency measurements only make sence for psync engine
    if fio_engine == "psync":
        cmd = cmd.with_arg(f"--write_lat_log={mode}")

    cmd = cmd.build()

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


def process_fio_log_files(root_dir, logs_glob):
    """
    Parses all fio log files in the root_dir matching the given glob and
    yields tuples of same-timestamp read and write metrics
    """
    # We specify `root_dir` for `glob.glob` because otherwise it will
    # struggle with directory with names like:
    # test_block_performance[vmlinux-5.10.233-Sync-bs4096-randread-1vcpu]
    data = [
        Path(root_dir / pathname).read_text("UTF-8").splitlines()
        for pathname in glob.glob(logs_glob, root_dir=root_dir)
    ]

    # If not data found, there is nothing to iterate over
    if not data:
        return [], []

    for tup in zip(*data):
        read_values = []
        write_values = []

        for line in tup:
            # See https://fio.readthedocs.io/en/latest/fio_doc.html#log-file-formats
            _, value, direction, _ = line.split(",", maxsplit=3)
            value = int(value.strip())

            match direction.strip():
                case "0":
                    read_values.append(value)
                case "1":
                    write_values.append(value)
                case _:
                    assert False

        yield read_values, write_values


def emit_fio_metrics(logs_dir, metrics):
    """Parses the fio logs in `{logs_dir}/*_[clat|bw].*.log and emits their contents as CloudWatch metrics"""
    for bw_read, bw_write in process_fio_log_files(logs_dir, "*_bw.*.log"):
        if bw_read:
            metrics.put_metric("bw_read", sum(bw_read), "Kilobytes/Second")
        if bw_write:
            metrics.put_metric("bw_write", sum(bw_write), "Kilobytes/Second")

    for lat_read, lat_write in process_fio_log_files(logs_dir, "*_clat.*.log"):
        # latency values in fio logs are in nanoseconds, but cloudwatch only supports
        # microseconds as the more granular unit, so need to divide by 1000.
        for value in lat_read:
            metrics.put_metric("clat_read", value / 1000, "Microseconds")
        for value in lat_write:
            metrics.put_metric("clat_write", value / 1000, "Microseconds")


@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("fio_mode", ["randread", "randwrite"])
@pytest.mark.parametrize("fio_block_size", [4096], ids=["bs4096"])
@pytest.mark.parametrize("fio_engine", ["libaio", "psync"])
def test_block_performance(
    microvm_factory,
    guest_kernel_acpi,
    rootfs,
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
    vm = microvm_factory.build(guest_kernel_acpi, rootfs, monitor_memory=False)
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
@pytest.mark.parametrize("fio_mode", ["randread"])
@pytest.mark.parametrize("fio_block_size", [4096], ids=["bs4096"])
def test_block_vhost_user_performance(
    microvm_factory,
    guest_kernel_acpi,
    rootfs,
    vcpus,
    fio_mode,
    fio_block_size,
    metrics,
    results_dir,
):
    """
    Execute block device emulation benchmarking scenarios.
    """

    vm = microvm_factory.build(guest_kernel_acpi, rootfs, monitor_memory=False)
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

    cpu_util = run_fio(vm, fio_mode, fio_block_size, results_dir)

    emit_fio_metrics(results_dir, metrics)

    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")
