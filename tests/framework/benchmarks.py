# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Benchmark workloads shared by the performance tests."""

import concurrent.futures
import os
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import psutil

import framework.utils_fio as fio
import host_tools.drive as drive_tools
from framework.microvm import Microvm
from framework.utils import check_output, track_cpu_utilization
from framework.utils_hugepages import HugePagesConfig
from framework.utils_iperf import IPerf3Test
from framework.utils_vsock import VSOCK_UDS_PATH, make_host_port_path
from framework.utils_wait import wait_for_unix_socket_on_host

# Size (in MB) of the block device that run_fio tests
BLOCK_DEVICE_SIZE_MB = 2048

# Time (in seconds) for which fio "warms up" before measurements are taken.
# The bandwidth ramp is direction-dependent: reads reach steady state almost
# immediately, while writes take a few seconds to settle. These values were
# derived from per-second fio bandwidth logs: the worst-case (libaio randwrite)
# transient clears by ~6-7s (10s rounding up), while reads are within noise
# from the first second, so they need no ramp.
WARMUP_SEC_READ = 0
WARMUP_SEC_WRITE = 10


def warmup_sec_for(mode: fio.Mode) -> int:
    """Return the fio warmup (ramp) time appropriate for the given mode."""
    write_modes = {fio.Mode.WRITE, fio.Mode.RANDWRITE, fio.Mode.TRIM, fio.Mode.RANDTRIM}
    return WARMUP_SEC_WRITE if mode in write_modes else WARMUP_SEC_READ


# Time (in seconds) for which run_fio runs fio after warmup is done
RUNTIME_SEC = 15


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
    microvm,
    mode: fio.Mode,
    block_size: int,
    test_output_dir,
    fio_engine: fio.Engine,
    readonly: bool = False,
):
    """Run a fio test in the specified mode with block size bs."""
    warmup_sec = warmup_sec_for(mode)
    cmd = fio.build_cmd(
        "/dev/vdb",
        BLOCK_DEVICE_SIZE_MB,
        block_size,
        mode,
        microvm.vcpus_count,
        fio_engine,
        RUNTIME_SEC,
        warmup_sec,
        readonly=readonly,
    )

    prepare_microvm_for_test(microvm)

    # Start the CPU load monitor.
    with concurrent.futures.ThreadPoolExecutor() as executor:
        cpu_load_future = executor.submit(
            track_cpu_utilization,
            microvm.firecracker_pid,
            RUNTIME_SEC,
            omit=warmup_sec,
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


class VsockIPerf3Test(IPerf3Test):
    """IPerf3 runner for the vsock throughput performance test"""

    BASE_PORT = 5201

    # How many clients/servers should be spawned per vcpu
    LOAD_FACTOR = 1

    # Time (in seconds) for which iperf "warms up"
    WARMUP_SEC = 3

    # Time (in seconds) for which iperf runs after warmup is done
    RUNTIME_SEC = 10

    # VM guest memory size
    GUEST_MEM_MIB = 1024

    def __init__(self, microvm, mode, payload_length):
        super().__init__(
            microvm,
            self.BASE_PORT,
            self.RUNTIME_SEC,
            self.WARMUP_SEC,
            mode,
            self.LOAD_FACTOR * microvm.vcpus_count,
            2,
            iperf="/usr/local/bin/iperf3-vsock",
            payload_length=payload_length,
        )
        # The rootfs does not have iperf3-vsock
        iperf3_guest = "/tmp/iperf3-vsock"

        self._microvm.ssh.scp_put(self._iperf, iperf3_guest)
        self._guest_iperf = iperf3_guest

    def host_command(self, port_offset):
        return (
            super()
            .host_command(port_offset)
            .with_arg("--vsock")
            .with_arg("-B", os.path.join(self._microvm.path, VSOCK_UDS_PATH))
        )

    def wait_for_server(self, port_offset):
        # The server listens on a Unix socket; link it into the jail so the
        # guest can reach it.
        uds_path = os.path.join(
            self._microvm.path,
            make_host_port_path(VSOCK_UDS_PATH, self._base_port + port_offset),
        )
        wait_for_unix_socket_on_host(self._microvm.netns.cmd_prefix(), uds_path)
        self._microvm.create_jailed_resource(uds_path)

    def guest_command(self, port_offset):
        return super().guest_command(port_offset).with_arg("--vsock")


ITERATIONS = 30


@lru_cache
def get_scratch_drives():
    """Create an array of scratch disks."""
    scratchdisks = ["vdb", "vdc", "vdd", "vde"]
    return [
        (drive, drive_tools.FilesystemFile(tempfile.mktemp(), size=64))
        for drive in scratchdisks
    ]


@dataclass
class SnapshotRestoreTest:
    """Dataclass encapsulating properties of snapshot restore tests"""

    vcpus: int = 1
    mem: int = 128
    nets: int = 3
    blocks: int = 3
    all_devices: bool = False
    huge_pages: HugePagesConfig = HugePagesConfig.NONE
    track_dirty_pages: bool = False

    @property
    def id(self):
        """Computes a unique id for this test instance"""
        return "all_dev" if self.all_devices else f"{self.vcpus}vcpu_{self.mem}mb"

    def dimensions(self, vm, performance_test, uffd_handler):
        """Metric dimensions describing this test setup and the given microVM"""
        return {
            "net_devices": str(self.nets),
            "block_devices": str(self.blocks),
            "vsock_devices": str(int(self.all_devices)),
            "balloon_devices": str(int(self.all_devices)),
            "huge_pages_config": str(self.huge_pages),
            "performance_test": performance_test,
            "uffd_handler": str(uffd_handler),
            **vm.dimensions,
        }

    def boot_vm(self, microvm_factory, guest_kernel, rootfs, pci_enabled) -> Microvm:
        """Creates the initial snapshot that will be loaded repeatedly to sample latencies"""
        vm = microvm_factory.build(
            guest_kernel,
            rootfs,
            monitor_memory=False,
            pci=pci_enabled,
        )
        vm.spawn(log_level="Info", emit_metrics=True)
        vm.time_api_requests = False
        vm.basic_config(
            vcpu_count=self.vcpus,
            mem_size_mib=self.mem,
            rootfs_io_engine="Sync",
            huge_pages=self.huge_pages,
            track_dirty_pages=self.track_dirty_pages,
        )

        for _ in range(self.nets):
            vm.add_net_iface()

        if self.blocks > 1:
            scratch_drives = get_scratch_drives()
            for name, diskfile in scratch_drives[: (self.blocks - 1)]:
                vm.add_drive(name, diskfile.path, io_engine="Sync")

        if self.all_devices:
            vm.api.balloon.put(
                amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
            )
            vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/v.sock")

        vm.start()

        return vm


# If guest memory is >3072MB, it is split in a 2nd region
X86_MEMORY_GAP_START = 3072 * 2**20


def emit_memory_overhead_metrics(firecracker_pid, mem_size_mib, metrics):
    """Emits the total, binary, overhead, USS and text memory of a Firecracker process as metrics"""
    guest_mem_bytes = mem_size_mib * 2**20
    guest_mem_splits = {
        guest_mem_bytes,
        X86_MEMORY_GAP_START,
    }
    if guest_mem_bytes > X86_MEMORY_GAP_START:
        guest_mem_splits.add(guest_mem_bytes - X86_MEMORY_GAP_START)

    mem_stats = defaultdict(int)
    ps = psutil.Process(firecracker_pid)

    for pmmap in ps.memory_maps(grouped=False):
        # We publish 'size' and 'rss' (resident). size would be the worst case,
        # whereas rss is the current paged-in memory.

        mem_stats["total_size"] += pmmap.size
        mem_stats["total_rss"] += pmmap.rss
        pmmap_path = Path(pmmap.path)
        if pmmap_path.exists() and pmmap_path.name.startswith("firecracker"):
            mem_stats["binary_size"] += pmmap.size
            mem_stats["binary_rss"] += pmmap.rss

        if pmmap.size not in guest_mem_splits:
            mem_stats["overhead_size"] += pmmap.size
            mem_stats["overhead_rss"] += pmmap.rss

    for key, value in mem_stats.items():
        metrics.put_metric(key, value, unit="Bytes")

    mem_info = ps.memory_full_info()
    for metric in ["uss", "text"]:
        val = getattr(mem_info, metric)
        metrics.put_metric(metric, val, unit="Bytes")


MEMHP_BOOTARGS = "console=ttyS0 reboot=k panic=1 memhp_default_state=online_movable"


def timed_memory_hotplug(uvm, size, metrics, metric_prefix, fc_metric_name):
    """Wait for all memory hotplug events to be processed"""

    uvm.flush_metrics()

    # poll every 5ms to check completion as the fastest hotplug is around 30ms
    api_time, total_time = uvm.hotplug_memory(size, poll=0.005)

    fc_metrics = uvm.flush_metrics()

    metrics.put_metric(
        f"{metric_prefix}_api_time",
        api_time,
        unit="Seconds",
    )
    metrics.put_metric(
        f"{metric_prefix}_total_time",
        total_time,
        unit="Seconds",
    )
    metrics.put_metric(
        f"{metric_prefix}_fc_time",
        fc_metrics["memory_hotplug"][fc_metric_name]["sum_us"],
        unit="Microseconds",
    )
