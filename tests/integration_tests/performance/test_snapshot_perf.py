# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import platform

import pytest

from framework.artifacts import kernel_params
from framework.properties import global_props
from framework.stats import consumer, producer, types
from framework.utils import CpuMap

# How many latencies do we sample per test.
SAMPLE_COUNT = 3
USEC_IN_MSEC = 1000
PLATFORM = platform.machine()

# measurement without pass criteria = test is infallible but still submits metrics. Nice!
LATENCY_MEASUREMENT = types.MeasurementDef.create_measurement(
    "latency",
    "ms",
    [],
    {},
)

# The guest kernel does not "participate" in snapshot restore, so just pick
# some arbitrary one
only_one_guest_kernel = pytest.mark.parametrize(
    "guest_kernel", list(kernel_params("vmlinux-4.14*")), indirect=True
)


def snapshot_create_producer(vm, target_version):
    """Produce results for snapshot create tests."""
    vm.snapshot_full(target_version=target_version)
    metrics = vm.flush_metrics()

    value = metrics["latencies_us"]["full_create_snapshot"] / USEC_IN_MSEC

    print(f"Latency {value} ms")

    return value


def snapshot_resume_producer(microvm_factory, snapshot):
    """Produce results for snapshot resume tests."""

    microvm = microvm_factory.build()
    microvm.spawn()
    microvm.restore_from_snapshot(snapshot, resume=True)

    # Attempt to connect to resumed microvm.
    # Verify if guest can run commands.
    exit_code, _, _ = microvm.ssh.run("ls")
    assert exit_code == 0

    value = 0
    # Parse all metric data points in search of load_snapshot time.
    metrics = microvm.get_all_metrics()
    for data_point in metrics:
        cur_value = data_point["latencies_us"]["load_snapshot"] / USEC_IN_MSEC
        if cur_value > 0:
            value = cur_value
            break

    print("Latency {value} ms")
    return value


@only_one_guest_kernel
def test_older_snapshot_resume_latency(
    microvm_factory,
    guest_kernel,
    rootfs,
    firecracker_release,
    io_engine,
    st_core,
):
    """
    Test scenario: Older snapshot load performance measurement.

    With each previous firecracker version, create a snapshot and try to
    restore in current version.
    """

    # due to bug fixed in commit 8dab78b
    firecracker_version = firecracker_release.version_tuple
    if global_props.instance == "m6a.metal" and firecracker_version < (1, 3, 3):
        pytest.skip("incompatible with AMD and Firecracker <1.3.3")

    vcpus, guest_mem_mib = 2, 512
    microvm_cfg = f"{vcpus}vcpu_{guest_mem_mib}mb.json"
    vm = microvm_factory.build(
        guest_kernel,
        rootfs,
        monitor_memory=False,
        fc_binary_path=firecracker_release.path,
        jailer_binary_path=firecracker_release.jailer,
    )
    vm.spawn()
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=guest_mem_mib)
    vm.add_net_iface()
    vm.start()
    # Check if guest works.
    exit_code, _, _ = vm.ssh.run("ls")
    assert exit_code == 0
    snapshot = vm.snapshot_full()

    st_core.name = "older_snapshot_resume_latency"
    st_core.iterations = SAMPLE_COUNT
    st_core.custom["guest_config"] = microvm_cfg.strip(".json")
    st_core.custom["io_engine"] = io_engine
    st_core.custom["snapshot_type"] = "FULL"

    prod = producer.LambdaProducer(
        func=snapshot_resume_producer,
        func_kwargs={
            "microvm_factory": microvm_factory,
            "snapshot": snapshot,
        },
    )

    cons = consumer.LambdaConsumer(
        func=lambda cons, result: cons.consume_stat(
            st_name="max", ms_name="latency", value=result
        ),
        func_kwargs={},
    )
    cons.set_measurement_def(LATENCY_MEASUREMENT)

    st_core.add_pipe(producer=prod, consumer=cons, tag=microvm_cfg)
    # Gather results and verify pass criteria.
    st_core.run_exercise()


@only_one_guest_kernel
def test_snapshot_create_latency(
    microvm_factory,
    guest_kernel,
    rootfs,
    st_core,
):
    """Measure the latency of creating a Full snapshot"""

    guest_mem_mib = 512
    vcpus = 2
    microvm_cfg = f"{vcpus}vcpu_{guest_mem_mib}mb.json"
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn()
    vm.basic_config(
        vcpu_count=vcpus,
        mem_size_mib=guest_mem_mib,
    )
    vm.start()

    # Check if the needed CPU cores are available. We have the API
    # thread, VMM thread and then one thread for each configured vCPU.
    assert CpuMap.len() >= 2 + vm.vcpus_count

    # Pin uVM threads to physical cores.
    current_cpu_id = 0
    assert vm.pin_vmm(current_cpu_id), "Failed to pin firecracker thread."
    current_cpu_id += 1
    assert vm.pin_api(current_cpu_id), "Failed to pin fc_api thread."
    for idx_vcpu in range(vm.vcpus_count):
        current_cpu_id += 1
        assert vm.pin_vcpu(
            idx_vcpu, current_cpu_id + idx_vcpu
        ), f"Failed to pin fc_vcpu {idx_vcpu} thread."

    st_core.name = "snapshot_create_SnapshotType.FULL_latency"
    st_core.iterations = SAMPLE_COUNT
    st_core.custom["guest_config"] = microvm_cfg.strip(".json")
    st_core.custom["snapshot_type"] = "FULL"

    prod = producer.LambdaProducer(
        func=snapshot_create_producer,
        func_kwargs={
            "vm": vm,
            "target_version": None,
        },
    )

    cons = consumer.LambdaConsumer(
        func=lambda cons, result: cons.consume_stat(
            st_name="max", ms_name="latency", value=result
        ),
        func_kwargs={},
    )
    cons.set_measurement_def(LATENCY_MEASUREMENT)

    st_core.add_pipe(producer=prod, consumer=cons, tag=microvm_cfg)
    # Gather results and verify pass criteria.
    st_core.run_exercise()
