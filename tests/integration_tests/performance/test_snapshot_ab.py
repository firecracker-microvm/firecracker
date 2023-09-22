# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for snapshot restore."""
import shutil
import statistics
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import List

import pytest

import host_tools.drive as drive_tools
from framework.microvm import Snapshot
from framework.properties import global_props

USEC_IN_MSEC = 1000
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

    @property
    def id(self):
        """Computes a unique id for this test instance"""
        return "all_dev" if self.all_devices else f"{self.vcpus}vcpu_{self.mem}mb"

    @property
    def dimensions(self):
        """Gets the cloudwatch dimensions for this test"""
        return {
            "vcpus": str(self.vcpus),
            "guest_memory": f"{self.mem}MB",
            "net_devices": str(self.nets),
            "block_devices": str(self.blocks),
            "vsock_devices": str(int(self.all_devices)),
            "balloon_devices": str(int(self.all_devices)),
        }

    def create_snapshot(
        self,
        microvm_factory,
        guest_kernel,
        rootfs,
    ) -> Snapshot:
        """Creates the initial snapshot that will be loaded repeatedly to sample latencies"""
        vm = microvm_factory.build(
            guest_kernel,
            rootfs,
            monitor_memory=False,
        )
        vm.spawn(log_level="Info")
        vm.time_api_requests = False
        vm.basic_config(
            vcpu_count=self.vcpus,
            mem_size_mib=self.mem,
            rootfs_io_engine="Sync",
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
        snapshot = vm.snapshot_full()
        vm.kill()

        return snapshot

    def sample_latency(self, microvm_factory, guest_kernel, rootfs) -> List[float]:
        """Collects latency samples for the microvm configuration specified by this instance"""
        snapshot = self.create_snapshot(microvm_factory, guest_kernel, rootfs)

        values = []

        for _ in range(ITERATIONS):
            microvm = microvm_factory.build(
                monitor_memory=False,
            )
            microvm.spawn()
            microvm.restore_from_snapshot(snapshot, resume=True)

            # Check if guest still runs commands.
            exit_code, _, _ = microvm.ssh.run("true")
            assert exit_code == 0

            value = 0
            # Parse all metric data points in search of load_snapshot time.
            microvm.flush_metrics()
            metrics = microvm.get_all_metrics()
            for data_point in metrics:
                cur_value = data_point["latencies_us"]["load_snapshot"]
                if cur_value > 0:
                    value = cur_value / USEC_IN_MSEC
                    break
            assert value > 0
            values.append(value)
            microvm.kill()
            shutil.rmtree(Path(microvm.chroot()))

        snapshot.delete()
        return values


@pytest.mark.nonci
@pytest.mark.parametrize(
    "test_setup",
    [
        SnapshotRestoreTest(mem=128, vcpus=1),
        SnapshotRestoreTest(mem=1024, vcpus=1),
        SnapshotRestoreTest(mem=2048, vcpus=2),
        SnapshotRestoreTest(mem=4096, vcpus=3),
        SnapshotRestoreTest(mem=6144, vcpus=4),
        SnapshotRestoreTest(mem=8192, vcpus=5),
        SnapshotRestoreTest(mem=10240, vcpus=6),
        SnapshotRestoreTest(mem=12288, vcpus=7),
        SnapshotRestoreTest(all_devices=True),
    ],
    ids=lambda x: x.id,
)
def test_restore_latency(
    microvm_factory, rootfs, guest_kernel_linux_4_14, test_setup, metrics
):
    """
    Restores snapshots with vcpu/memory configuration, roughly scaling according to mem = (vcpus - 1) * 2048MB,
    which resembles firecracker production setups. Also contains a test case for restoring a snapshot will all devices
    attached to it.

    We only test a single guest kernel, as the guest kernel does not "participate" in snapshot restore.
    """

    samples = test_setup.sample_latency(
        microvm_factory,
        guest_kernel_linux_4_14,
        rootfs,
    )

    metrics.set_dimensions(
        {
            "instance": global_props.instance,
            "cpu_model": global_props.cpu_model,
            "host_kernel": "linux-" + global_props.host_linux_version,
            "guest_kernel": guest_kernel_linux_4_14.stem[2:],
            "rootfs": rootfs.name,
            "performance_test": "test_restore_latency",
            **test_setup.dimensions,
        }
    )

    metrics.put_metric("latency_Avg", statistics.mean(samples), "Milliseconds")

    for sample in samples:
        metrics.put_metric("latency", sample, "Milliseconds")
