# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for snapshot restore."""

import re
import signal

import pytest
from tenacity import Retrying, retry_if_exception_type, stop_after_delay, wait_fixed

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.benchmarks import ITERATIONS, SnapshotRestoreTest
from framework.microvm import SnapshotType
from framework.utils import (
    start_fast_page_fault_helper,
    wait_for_fast_page_fault_helper_output,
)
from framework.utils_hugepages import HugePagesConfig
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend

USEC_IN_MSEC = 1000
NS_IN_MSEC = 1_000_000
POPULATION_ITERATIONS = 15

pytestmark = [
    pin_guest_kernel(GUEST_KERNEL_DEFAULT),
    pin_vm_backend(VM_BACKEND_KVM),
]


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
    microvm_factory, guest_kernel, rootfs, pci_enabled, test_setup, metrics
):
    """
    Restores snapshots with vcpu/memory configuration, roughly scaling according to mem = (vcpus - 1) * 2048MB,
    which resembles firecracker production setups. Also contains a test case for restoring a snapshot will all devices
    attached to it.

    We only test a single guest kernel, as the guest kernel does not "participate" in snapshot restore.
    """
    vm = test_setup.boot_vm(microvm_factory, guest_kernel, rootfs, pci_enabled)

    metrics.set_dimensions(test_setup.dimensions(vm, "test_restore_latency", None))

    snapshot = vm.snapshot_full()
    vm.kill()
    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot, ITERATIONS, no_netns_reuse=True
    ):
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
@pytest.mark.parametrize(
    "huge_pages,uffd_handler",
    [
        (HugePagesConfig.NONE, None),
        (HugePagesConfig.NONE, "on_demand"),
        (HugePagesConfig.NONE, "fault_all"),
        (HugePagesConfig.TRANSPARENT, "on_demand"),
        (HugePagesConfig.HUGETLBFS_2MB, "on_demand"),
        (HugePagesConfig.HUGETLBFS_2MB, "fault_all"),
    ],
)
def test_post_restore_latency(
    microvm_factory,
    rootfs,
    guest_kernel,
    pci_enabled,
    metrics,
    uffd_handler,
    huge_pages,
):
    """Collects latency metric of post-restore memory accesses done inside the guest"""
    test_setup = SnapshotRestoreTest(mem=1024, vcpus=2, huge_pages=huge_pages)
    vm = test_setup.boot_vm(microvm_factory, guest_kernel, rootfs, pci_enabled)

    metrics.set_dimensions(
        test_setup.dimensions(vm, "test_post_restore_latency", uffd_handler)
    )

    # Starts the helper and blocks until it has touched its memory and is
    # waiting in sigwait, so the snapshot below captures it in that state.
    pid = start_fast_page_fault_helper(vm.ssh)

    snapshot = vm.snapshot_full()
    vm.kill()

    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot, ITERATIONS, uffd_handler_name=uffd_handler
    ):
        microvm.ssh.check_output(f"kill -s {signal.SIGUSR1} {pid}")

        duration = wait_for_fast_page_fault_helper_output(microvm.ssh, pid)

        metrics.put_metric("fault_latency", int(duration) / NS_IN_MSEC, "Milliseconds")


@pytest.mark.nonci
@pytest.mark.parametrize(
    ("vcpus", "mem", "huge_pages"),
    [
        (vcpus, mem, huge_pages)
        for vcpus, mem in [(1, 128), (1, 1024), (2, 2048), (3, 4096), (4, 6144)]
        for huge_pages in [HugePagesConfig.NONE, HugePagesConfig.HUGETLBFS_2MB]
    ]
    + [(1, 1024, HugePagesConfig.TRANSPARENT)],
)
def test_population_latency(
    microvm_factory,
    rootfs,
    guest_kernel,
    pci_enabled,
    metrics,
    huge_pages,
    vcpus,
    mem,
):
    """Collects population latency metrics (e.g. how long it takes UFFD handler to fault in all memory)"""
    test_setup = SnapshotRestoreTest(mem=mem, vcpus=vcpus, huge_pages=huge_pages)
    vm = test_setup.boot_vm(microvm_factory, guest_kernel, rootfs, pci_enabled)

    metrics.set_dimensions(
        test_setup.dimensions(vm, "test_population_latency", "fault_all")
    )

    snapshot = vm.snapshot_full()
    vm.kill()

    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot, POPULATION_ITERATIONS, uffd_handler_name="fault_all"
    ):
        # API response times are unreliable while the uffd handler is
        # faulting in all pages — skip the timing validation.
        microvm.time_api_requests = False
        # do _something_ to trigger a pagefault, which will then cause the UFFD handler to fault in _everything_
        microvm.ssh.check_output("true")

        for attempt in Retrying(
            retry=retry_if_exception_type(AssertionError),
            stop=stop_after_delay(5),
            wait=wait_fixed(0.05),
            reraise=True,
        ):
            with attempt:
                match = re.match(
                    r"Finished Faulting All: (\d+)us", microvm.uffd_handler.log_data
                )
                assert match, "UFFD handler did not print population latency after 5s"

        latency_us = int(match.group(1))
        metrics.put_metric("populate_latency", latency_us / 1000, "Milliseconds")


@pytest.mark.nonci
def test_snapshot_create_latency(
    uvm,
    metrics,
    snapshot_type,
):
    """Measure the latency of creating a Full snapshot"""

    vm = uvm
    vm.spawn()
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=512,
        track_dirty_pages=snapshot_type.needs_dirty_page_tracking,
    )
    vm.start()
    vm.pin_threads(0)

    metrics.set_dimensions(
        {
            **vm.dimensions,
            "performance_test": "test_snapshot_create_latency",
            "snapshot_type": str(snapshot_type),
        }
    )

    match snapshot_type:
        case SnapshotType.FULL:
            metric = "full_create_snapshot"
        case SnapshotType.DIFF | SnapshotType.DIFF_MINCORE:
            metric = "diff_create_snapshot"

    for _ in range(ITERATIONS):
        vm.make_snapshot(snapshot_type)
        fc_metrics = vm.flush_metrics()

        value = fc_metrics["latencies_us"][metric] / USEC_IN_MSEC
        metrics.put_metric("latency", value, "Milliseconds")
