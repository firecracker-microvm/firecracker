# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import json
import logging
import os
import platform

import pytest

import host_tools.logging as log_tools
from framework.artifacts import NetIfaceConfig
from framework.builder import MicrovmBuilder, SnapshotBuilder
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


def snapshot_create_producer(logger, vm, disks, ssh_key, target_version, metrics_fifo):
    """Produce results for snapshot create tests."""
    snapshot_builder = SnapshotBuilder(vm)
    snapshot_builder.create(
        disks=disks,
        ssh_key=ssh_key,
        target_version=target_version,
        use_ramdisk=True,
    )
    metrics = vm.flush_metrics(metrics_fifo)

    value = metrics["latencies_us"]["full_create_snapshot"] / USEC_IN_MSEC

    logger.info("Latency {} ms".format(value))

    return value


def snapshot_resume_producer(logger, vm_builder, snapshot, use_ramdisk):
    """Produce results for snapshot resume tests."""
    microvm, metrics_fifo = vm_builder.build_from_snapshot(
        snapshot,
        resume=True,
        use_ramdisk=use_ramdisk,
    )

    # Attempt to connect to resumed microvm.
    # Verify if guest can run commands.
    exit_code, _, _ = microvm.ssh.execute_command("ls")
    assert exit_code == 0

    value = 0
    # Parse all metric data points in search of load_snapshot time.
    metrics = microvm.get_all_metrics(metrics_fifo)
    for data_point in metrics:
        metrics = json.loads(data_point)
        cur_value = metrics["latencies_us"]["load_snapshot"] / USEC_IN_MSEC
        if cur_value > 0:
            value = cur_value
            break

    logger.info("Latency {} ms".format(value))
    return value


def test_older_snapshot_resume_latency(
    microvm_factory,
    guest_kernel,
    rootfs,
    firecracker_release,
    io_engine,
    st_core,
    bin_cloner_path,
):
    """
    Test scenario: Older snapshot load performance measurement.

    With each previous firecracker version, create a snapshot and try to
    restore in current version.
    """

    # The guest kernel does not "participate" in snapshot restore, so just pick some
    # arbitrary one
    if "4.14" not in guest_kernel.name():
        pytest.skip()

    logger = logging.getLogger("old_snapshot_load")
    jailer = firecracker_release.jailer()
    fc_version = firecracker_release.base_name()[1:]
    logger.info("Firecracker version: %s", fc_version)
    logger.info("Source Firecracker: %s", firecracker_release.local_path())
    logger.info("Source Jailer: %s", jailer.local_path())

    vcpus, guest_mem_mib = 2, 512
    microvm_cfg = f"{vcpus}vcpu_{guest_mem_mib}mb.json"
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn()
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=guest_mem_mib)
    iface = NetIfaceConfig()
    vm.add_net_iface(iface)
    vm.start()

    # Check if guest works.
    exit_code, _, _ = vm.ssh.execute_command("ls")
    assert exit_code == 0

    # The snapshot builder expects disks as paths, not artifacts.
    disks = [vm.rootfs_file]
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(vm)
    snapshot = snapshot_builder.create(disks, rootfs.ssh_key(), net_ifaces=[iface])
    vm.kill()

    st_core.name = "older_snapshot_resume_latency"
    st_core.iterations = SAMPLE_COUNT
    st_core.custom["guest_config"] = microvm_cfg.strip(".json")
    st_core.custom["io_engine"] = io_engine
    st_core.custom["snapshot_type"] = "FULL"

    prod = producer.LambdaProducer(
        func=snapshot_resume_producer,
        func_kwargs={
            "logger": logger,
            "vm_builder": MicrovmBuilder(bin_cloner_path),
            "snapshot": snapshot,
            "use_ramdisk": False,
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


def test_snapshot_create_latency(
    microvm_factory,
    guest_kernel,
    rootfs,
    firecracker_release,
    st_core,
):
    """
    Test scenario: Full snapshot create performance measurement.

    Testing matrix:
    - Guest kernel: all supported ones
    - Rootfs: Ubuntu 18.04
    - Microvm: 2vCPU with 512 MB RAM
    """

    # The guest kernel does not "participate" in snapshot restore, so just pick some
    # arbitrary one
    if "4.14" not in guest_kernel.name():
        pytest.skip()

    logger = logging.getLogger("snapshot_sequence")

    guest_mem_mib = 512
    vcpus = 2
    microvm_cfg = f"{vcpus}vcpu_{guest_mem_mib}mb.json"
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(use_ramdisk=True)
    vm.basic_config(
        vcpu_count=vcpus,
        mem_size_mib=guest_mem_mib,
        use_initrd=True,
    )

    # Configure metrics system.
    metrics_fifo_path = os.path.join(vm.path, "metrics_fifo")
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = vm.metrics.put(metrics_path=vm.create_jailed_resource(metrics_fifo.path))
    assert vm.api_session.is_status_no_content(response.status_code)

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
            "logger": logger,
            "vm": vm,
            "disks": [vm.rootfs_file],
            "ssh_key": rootfs.ssh_key(),
            "target_version": firecracker_release.snapshot_version,
            "metrics_fifo": metrics_fifo,
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
