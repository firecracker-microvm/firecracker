# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for snapshot restore."""
import re
import signal
import tempfile
import time
from dataclasses import dataclass
from functools import lru_cache

import pytest

import host_tools.drive as drive_tools
from framework.microvm import HugePagesConfig, Microvm

USEC_IN_MSEC = 1000
NS_IN_MSEC = 1_000_000
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

    @property
    def id(self):
        """Computes a unique id for this test instance"""
        return "all_dev" if self.all_devices else f"{self.vcpus}vcpu_{self.mem}mb"

    def boot_vm(self, microvm_factory, guest_kernel, rootfs) -> Microvm:
        """Creates the initial snapshot that will be loaded repeatedly to sample latencies"""
        vm = microvm_factory.build(
            guest_kernel,
            rootfs,
            monitor_memory=False,
        )
        vm.spawn(log_level="Info", emit_metrics=True)
        vm.time_api_requests = False
        vm.basic_config(
            vcpu_count=self.vcpus,
            mem_size_mib=self.mem,
            rootfs_io_engine="Sync",
            huge_pages=self.huge_pages,
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
    microvm_factory, rootfs, guest_kernel_linux_5_10, test_setup, metrics
):
    """
    Restores snapshots with vcpu/memory configuration, roughly scaling according to mem = (vcpus - 1) * 2048MB,
    which resembles firecracker production setups. Also contains a test case for restoring a snapshot will all devices
    attached to it.

    We only test a single guest kernel, as the guest kernel does not "participate" in snapshot restore.
    """
    vm = test_setup.boot_vm(microvm_factory, guest_kernel_linux_5_10, rootfs)

    metrics.set_dimensions(
        {
            "net_devices": str(test_setup.nets),
            "block_devices": str(test_setup.blocks),
            "vsock_devices": str(int(test_setup.all_devices)),
            "balloon_devices": str(int(test_setup.all_devices)),
            "huge_pages_config": str(test_setup.huge_pages),
            "performance_test": "test_restore_latency",
            "uffd_handler": "None",
            **vm.dimensions,
        }
    )

    snapshot = vm.snapshot_full()
    vm.kill()
    for microvm in microvm_factory.build_n_from_snapshot(snapshot, ITERATIONS):
        value = 0
        # Parse all metric data points in search of load_snapshot time.
        microvm.flush_metrics()
        for data_point in microvm.get_all_metrics():
            cur_value = data_point["latencies_us"]["load_snapshot"]
            if cur_value > 0:
                value = cur_value / USEC_IN_MSEC
                break
        assert value > 0
        metrics.put_metric("latency", value, "Milliseconds")


# When using the fault-all handler, all guest memory will be faulted in way before the helper tool
# wakes up, because it gets faulted in on the first page fault. In this scenario, we are not measuring UFFD
# latencies, but KVM latencies of setting up missing EPT entries.
@pytest.mark.nonci
@pytest.mark.parametrize("uffd_handler", [None, "on_demand", "fault_all"])
@pytest.mark.parametrize("huge_pages", HugePagesConfig)
def test_post_restore_latency(
    microvm_factory,
    rootfs,
    guest_kernel_linux_5_10,
    metrics,
    uffd_handler,
    huge_pages,
):
    """Collects latency metric of post-restore memory accesses done inside the guest"""
    if huge_pages != HugePagesConfig.NONE and uffd_handler is None:
        pytest.skip("huge page snapshots can only be restored using uffd")

    test_setup = SnapshotRestoreTest(mem=1024, vcpus=2, huge_pages=huge_pages)
    vm = test_setup.boot_vm(microvm_factory, guest_kernel_linux_5_10, rootfs)

    metrics.set_dimensions(
        {
            "net_devices": str(test_setup.nets),
            "block_devices": str(test_setup.blocks),
            "vsock_devices": str(int(test_setup.all_devices)),
            "balloon_devices": str(int(test_setup.all_devices)),
            "huge_pages_config": str(test_setup.huge_pages),
            "performance_test": "test_post_restore_latency",
            "uffd_handler": str(uffd_handler),
            **vm.dimensions,
        }
    )

    vm.ssh.check_output(
        "nohup /usr/local/bin/fast_page_fault_helper >/dev/null 2>&1 </dev/null &"
    )

    # Give helper time to initialize
    time.sleep(5)

    snapshot = vm.snapshot_full()
    vm.kill()

    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot, ITERATIONS, uffd_handler_name=uffd_handler
    ):
        _, pid, _ = microvm.ssh.check_output("pidof fast_page_fault_helper")

        microvm.ssh.check_output(f"kill -s {signal.SIGUSR1} {pid}")

        _, duration, _ = microvm.ssh.check_output(
            "while [ ! -f /tmp/fast_page_fault_helper.out ]; do sleep 1; done; cat /tmp/fast_page_fault_helper.out"
        )

        metrics.put_metric("fault_latency", int(duration) / NS_IN_MSEC, "Milliseconds")


@pytest.mark.nonci
@pytest.mark.parametrize("huge_pages", HugePagesConfig)
@pytest.mark.parametrize(
    ("vcpus", "mem"), [(1, 128), (1, 1024), (2, 2048), (3, 4096), (4, 6144)]
)
def test_population_latency(
    microvm_factory,
    rootfs,
    guest_kernel_linux_5_10,
    metrics,
    huge_pages,
    vcpus,
    mem,
):
    """Collects population latency metrics (e.g. how long it takes UFFD handler to fault in all memory)"""
    test_setup = SnapshotRestoreTest(mem=mem, vcpus=vcpus, huge_pages=huge_pages)
    vm = test_setup.boot_vm(microvm_factory, guest_kernel_linux_5_10, rootfs)

    metrics.set_dimensions(
        {
            "net_devices": str(test_setup.nets),
            "block_devices": str(test_setup.blocks),
            "vsock_devices": str(int(test_setup.all_devices)),
            "balloon_devices": str(int(test_setup.all_devices)),
            "huge_pages_config": str(test_setup.huge_pages),
            "performance_test": "test_population_latency",
            "uffd_handler": "fault_all",
            **vm.dimensions,
        }
    )

    snapshot = vm.snapshot_full()
    vm.kill()

    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot, ITERATIONS, uffd_handler_name="fault_all"
    ):
        # do _something_ to trigger a pagefault, which will then cause the UFFD handler to fault in _everything_
        microvm.ssh.check_output("true")

        for _ in range(5):
            time.sleep(1)

            match = re.match(
                r"Finished Faulting All: (\d+)us", microvm.uffd_handler.log_data
            )

            if match:
                latency_us = int(match.group(1))

                metrics.put_metric(
                    "populate_latency", latency_us / 1000, "Milliseconds"
                )
                break
        else:
            raise RuntimeError("UFFD handler did not print population latency after 5s")


def test_snapshot_create_latency(
    microvm_factory,
    guest_kernel_linux_5_10,
    rootfs,
    metrics,
):
    """Measure the latency of creating a Full snapshot"""

    vm = microvm_factory.build(guest_kernel_linux_5_10, rootfs, monitor_memory=False)
    vm.spawn()
    vm.basic_config(vcpu_count=2, mem_size_mib=512)
    vm.start()
    vm.pin_threads(0)

    metrics.set_dimensions(
        {**vm.dimensions, "performance_test": "test_snapshot_create_latency"}
    )

    for _ in range(ITERATIONS):
        vm.snapshot_full()
        fc_metrics = vm.flush_metrics()

        value = fc_metrics["latencies_us"]["full_create_snapshot"] / USEC_IN_MSEC
        metrics.put_metric("latency", value, "Milliseconds")
