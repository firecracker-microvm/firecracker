# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmarks with dirty page tracking on.

Each test runs the workload of the performance test whose name it extends
with `_dirty_tracking`, in one case for each path that dirty page tracking
changes. It reports the same metrics under the same `performance_test`, with
the `track_dirty_pages` dimension set. No tracking path depends on the
transport, so every test runs with PCI on. Enclaves cannot track dirty pages,
so the module runs on KVM only.
"""

import json
import os
import signal
from pathlib import Path

import pytest

import framework.utils_fio as fio
import host_tools.drive as drive_tools
from framework.artifacts import (
    ACPI_GUEST_KERNELS,
    GUEST_KERNEL_DEFAULT,
    pin_guest_kernel,
    pin_pci,
)
from framework.benchmarks import (
    BLOCK_DEVICE_SIZE_MB,
    ITERATIONS,
    MEMHP_BOOTARGS,
    SnapshotRestoreTest,
    VsockIPerf3Test,
    emit_fio_metrics,
    emit_memory_overhead_metrics,
    run_fio,
    timed_memory_hotplug,
)
from framework.utils import (
    start_fast_page_fault_helper,
    wait_for_fast_page_fault_helper_output,
)
from framework.utils_hugepages import HugePagesConfig
from framework.utils_iperf import IPerf3Test, emit_iperf3_metrics
from framework.utils_vsock import boot_vsock_vm
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend

USEC_IN_MSEC = 1000
NS_IN_MSEC = 1_000_000

pytestmark = [pytest.mark.nonci, pin_pci(True), pin_vm_backend(VM_BACKEND_KVM)]


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
@pytest.mark.parametrize("uffd_handler", ["on_demand", "fault_all"])
def test_post_restore_latency_dirty_tracking(
    microvm_factory, guest_kernel, rootfs, pci_enabled, uffd_handler, metrics
):
    """Post-restore memory access latency with hugetlbfs.

    Tracking makes KVM map guest memory at 4 KiB in stage 2 instead of 2 MiB.
    """
    test_setup = SnapshotRestoreTest(
        mem=1024,
        vcpus=2,
        huge_pages=HugePagesConfig.HUGETLBFS_2MB,
        track_dirty_pages=True,
    )
    vm = test_setup.boot_vm(microvm_factory, guest_kernel, rootfs, pci_enabled)

    metrics.set_dimensions(
        test_setup.dimensions(vm, "test_post_restore_latency", uffd_handler)
    )

    pid = start_fast_page_fault_helper(vm.ssh)

    snapshot = vm.snapshot_full()
    vm.kill()

    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot,
        ITERATIONS,
        uffd_handler_name=uffd_handler,
        track_dirty_pages=True,
    ):
        microvm.ssh.check_output(f"kill -s {signal.SIGUSR1} {pid}")

        duration = wait_for_fast_page_fault_helper_output(microvm.ssh, pid)

        metrics.put_metric("fault_latency", int(duration) / NS_IN_MSEC, "Milliseconds")


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
@pytest.mark.parametrize(
    "test_setup",
    [
        SnapshotRestoreTest(mem=128, vcpus=1, track_dirty_pages=True),
        SnapshotRestoreTest(mem=12288, vcpus=7, track_dirty_pages=True),
    ],
    ids=lambda x: x.id,
)
def test_restore_latency_dirty_tracking(
    microvm_factory, guest_kernel, rootfs, pci_enabled, test_setup, metrics
):
    """Snapshot restore latency at the smallest and largest setups.

    Restore sets up tracking for each guest memory region: one at 128 MiB, and
    two on x86 at 12 GiB.
    """
    vm = test_setup.boot_vm(microvm_factory, guest_kernel, rootfs, pci_enabled)

    metrics.set_dimensions(test_setup.dimensions(vm, "test_restore_latency", None))

    snapshot = vm.snapshot_full()
    vm.kill()
    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot, ITERATIONS, no_netns_reuse=True, track_dirty_pages=True
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


@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pytest.mark.timeout(120)
def test_network_tcp_throughput_dirty_tracking(uvm, metrics, results_dir):
    """TCP throughput from host to guest at 128K and 2 vCPUs.

    Firecracker marks the guest RX buffers it writes received data into.
    """
    vm = uvm
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=2, mem_size_mib=1024, track_dirty_pages=True)
    vm.add_net_iface()
    vm.start()
    first_free_cpu = vm.pin_threads(0)

    # Time (in seconds) for which iperf "warms up"
    warmup_sec = 5

    metrics.set_dimensions(
        {
            "performance_test": "test_network_tcp_throughput",
            "payload_length": "128K",
            "mode": "h2g",
            **vm.dimensions,
        }
    )

    test = IPerf3Test(
        microvm=vm,
        base_port=5000,
        runtime=10,
        omit=warmup_sec,
        mode="h2g",
        num_clients=vm.vcpus_count,
        connect_to=vm.iface["eth0"]["iface"].host_ip,
        payload_length="128K",
    )
    data = test.run_test(first_free_cpu)

    for i, h2g in enumerate(data["h2g"]):
        Path(results_dir / f"h2g_{i}.json").write_text(
            json.dumps(h2g), encoding="utf-8"
        )

    emit_iperf3_metrics(metrics, data, warmup_sec)


@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pytest.mark.timeout(120)
def test_vsock_throughput_dirty_tracking(uvm, metrics, results_dir):
    """Vsock throughput from host to guest at 64K and 2 vCPUs.

    Firecracker marks the guest RX buffers it writes received data into.
    """
    vm = boot_vsock_vm(
        uvm,
        vcpu_count=2,
        mem_size_mib=1024,
        log_level="Info",
        emit_metrics=True,
        pin_threads=True,
        track_dirty_pages=True,
    )

    metrics.set_dimensions(
        {
            "performance_test": "test_vsock_throughput",
            "payload_length": "64K",
            "mode": "h2g",
            **vm.dimensions,
        }
    )

    test = VsockIPerf3Test(vm, "h2g", "64K")
    data = test.run_test(vm.vcpus_count + 2)

    for i, h2g in enumerate(data["h2g"]):
        Path(results_dir / f"h2g_{i}.json").write_text(
            json.dumps(h2g), encoding="utf-8"
        )

    emit_iperf3_metrics(metrics, data, VsockIPerf3Test.WARMUP_SEC)


@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pytest.mark.parametrize("threaded", [False, True], ids=["inline", "threaded"])
def test_block_performance_dirty_tracking(
    uvm, io_engine, threaded, metrics, results_dir
):
    """Block randread with libaio at 2 vCPUs.

    Firecracker marks the guest buffers it writes read data into. Inline runs
    process the drive on the VMM thread. Threaded runs give it one queue per
    vCPU, each with its own worker thread, so several threads mark at once.
    """
    vcpu_count = 2
    num_queues = vcpu_count if threaded else None
    vm = uvm
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=vcpu_count, mem_size_mib=1024, track_dirty_pages=True)
    vm.add_net_iface()
    fs = drive_tools.FilesystemFile(
        os.path.join(vm.fsfiles, "scratch"), BLOCK_DEVICE_SIZE_MB
    )
    vm.add_drive("scratch", fs.path, io_engine=io_engine, num_queues=num_queues)
    vm.start()

    metrics.set_dimensions(
        {
            "performance_test": "test_block_performance",
            "io_engine": io_engine,
            "num_queues": str(num_queues) if threaded else "inline",
            "fio_mode": fio.Mode.RANDREAD,
            "fio_block_size": "4096",
            "fio_engine": fio.Engine.LIBAIO,
            **vm.dimensions,
        }
    )

    next_cpu = vm.pin_threads(0)
    if threaded:
        assert vm.pin_block_workers("scratch", next_cpu) == next_cpu + num_queues

    cpu_util = run_fio(vm, fio.Mode.RANDREAD, 4096, results_dir, fio.Engine.LIBAIO)

    emit_fio_metrics(results_dir, metrics)

    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")


@pin_guest_kernel(ACPI_GUEST_KERNELS)
def test_memory_overhead_dirty_tracking(
    microvm_factory, guest_kernel, rootfs, pci_enabled, metrics
):
    """Firecracker memory overhead at 4 vCPUs and 4 GiB.

    Firecracker keeps a dirty bitmap for each guest memory region, and x86
    splits 4 GiB into two regions.
    """
    mem_size_mib = 4096
    for _ in range(5):
        microvm = microvm_factory.build(
            guest_kernel, rootfs, pci=pci_enabled, monitor_memory=False
        )
        microvm.spawn(emit_metrics=True)
        microvm.basic_config(
            vcpu_count=4, mem_size_mib=mem_size_mib, track_dirty_pages=True
        )
        microvm.add_net_iface()
        microvm.start()
        metrics.set_dimensions(
            {"performance_test": "test_memory_overhead", **microvm.dimensions}
        )

        snapshot = microvm.snapshot_full()
        microvm.kill()
        microvm2 = microvm_factory.build_from_snapshot(snapshot, track_dirty_pages=True)

        emit_memory_overhead_metrics(microvm2.firecracker_pid, mem_size_mib, metrics)


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
@pytest.mark.parametrize(
    "huge_pages", [HugePagesConfig.TRANSPARENT, HugePagesConfig.HUGETLBFS_2MB]
)
def test_memory_hotplug_latency_dirty_tracking(
    microvm_factory, guest_kernel, rootfs, pci_enabled, huge_pages, metrics
):
    """Memory hotplug latency at 16 GiB with huge pages.

    Tracking makes KVM map the plugged memory at 4 KiB in stage 2.
    """
    hotplug_size = 16384
    for i in range(20):
        uvm = microvm_factory.build(guest_kernel, rootfs, pci=pci_enabled)
        uvm.spawn()
        uvm.memory_monitor = None
        uvm.basic_config(
            boot_args=MEMHP_BOOTARGS,
            huge_pages=huge_pages,
            mem_size_mib=512,
            track_dirty_pages=True,
        )
        uvm.api.memory_hotplug.put(
            total_size_mib=hotplug_size, slot_size_mib=128, block_size_mib=2
        )
        uvm.add_net_iface()
        uvm.start()

        if i == 0:
            metrics.set_dimensions(
                {
                    "performance_test": "test_memory_hotplug_latency",
                    "hotplug_size": str(hotplug_size),
                    "huge_pages": huge_pages,
                    **uvm.dimensions,
                }
            )

        timed_memory_hotplug(uvm, hotplug_size, metrics, "hotplug", "plug_agg")
        timed_memory_hotplug(uvm, 0, metrics, "hotunplug", "unplug_agg")
        timed_memory_hotplug(uvm, hotplug_size, metrics, "hotplug_2nd", "plug_agg")
        uvm.kill()
