# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""

import os

import pytest

import framework.utils_fio as fio
import host_tools.drive as drive_tools
from framework.artifacts import ACPI_GUEST_KERNELS, pin_guest_kernel
from framework.benchmarks import BLOCK_DEVICE_SIZE_MB, emit_fio_metrics, run_fio
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend

pytestmark = pin_guest_kernel(ACPI_GUEST_KERNELS)

# VM guest memory size
GUEST_MEM_MIB = 1024


@pytest.mark.nonci
@pytest.mark.parametrize(
    "vcpu_count",
    [1, 2],
    ids=["1vcpu", "2vcpu"],
    indirect=True,
)
@pytest.mark.parametrize("fio_mode", [fio.Mode.RANDREAD, fio.Mode.RANDWRITE])
@pytest.mark.parametrize("fio_block_size", [4096], ids=["bs4096"])
@pytest.mark.parametrize("fio_engine", [fio.Engine.LIBAIO, fio.Engine.PSYNC])
@pytest.mark.parametrize("threaded", [False, True], ids=["inline", "threaded"])
def test_block_performance(
    uvm,
    vcpu_count,
    io_engine,
    fio_mode,
    fio_block_size,
    fio_engine,
    threaded,
    metrics,
    results_dir,
):
    """
    Execute block device emulation benchmarking scenarios.

    Inline runs process the drive on the VMM thread. Threaded runs give it one queue per vCPU,
    each with its own worker thread.
    """
    if threaded and fio_engine == fio.Engine.PSYNC:
        pytest.skip("threaded runs use libaio only, to keep the matrix small")
    num_queues = vcpu_count if threaded else None
    vm = uvm
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=vcpu_count, mem_size_mib=GUEST_MEM_MIB)
    vm.add_net_iface()
    # Add a secondary block device for benchmark tests.
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
            "fio_mode": fio_mode,
            "fio_block_size": str(fio_block_size),
            "fio_engine": fio_engine,
            **vm.dimensions,
        }
    )

    next_cpu = vm.pin_threads(0)
    if threaded:
        assert vm.pin_block_workers("scratch", next_cpu) == next_cpu + num_queues

    cpu_util = run_fio(vm, fio_mode, fio_block_size, results_dir, fio_engine)

    emit_fio_metrics(results_dir, metrics)

    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")


@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("fio_block_size", [4096], ids=["bs4096"])
@pytest.mark.parametrize("fio_engine", [fio.Engine.LIBAIO, fio.Engine.PSYNC])
def test_block_vmdk_performance(
    uvm,
    vcpus,
    fio_block_size,
    fio_engine,
    metrics,
    results_dir,
):
    """Execute block device benchmarking scenarios against a VMDK image.

    Reads from a VMDK image go through the imago backend instead of a plain
    file, so this keeps an eye on the throughput and latency it delivers.
    """
    vm = uvm
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=GUEST_MEM_MIB)
    vm.add_net_iface()
    # Add a secondary, read-only VMDK block device for benchmark tests.
    vmdk = drive_tools.VmdkFile(
        os.path.join(vm.fsfiles, "scratch.vmdk"),
        BLOCK_DEVICE_SIZE_MB,
        pattern=bytes(range(256)),
    )
    vm.create_jailed_resource(vmdk.extent_path)
    vm.add_drive(
        "scratch", vmdk.descriptor_path, is_read_only=True, image_format="Vmdk"
    )
    vm.start()

    metrics.set_dimensions(
        {
            "performance_test": "test_block_vmdk_performance",
            "io_engine": "Sync",
            "fio_mode": fio.Mode.RANDREAD.value,
            "fio_block_size": str(fio_block_size),
            "fio_engine": fio_engine.value,
            "image_format": "Vmdk",
            **vm.dimensions,
        }
    )

    vm.pin_threads(0)

    cpu_util = run_fio(
        vm, fio.Mode.RANDREAD, fio_block_size, results_dir, fio_engine, readonly=True
    )

    emit_fio_metrics(results_dir, metrics)

    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")


@pytest.mark.nonci
@pin_vm_backend(VM_BACKEND_KVM)
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("fio_mode", [fio.Mode.RANDREAD])
@pytest.mark.parametrize("fio_block_size", [4096], ids=["bs4096"])
def test_block_vhost_user_performance(
    uvm,
    vcpus,
    fio_mode,
    fio_block_size,
    metrics,
    results_dir,
):
    """
    Execute block device emulation benchmarking scenarios.
    """

    vm = uvm
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
