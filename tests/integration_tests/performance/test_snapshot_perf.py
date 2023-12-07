# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import pytest

from framework.properties import global_props

# How many latencies do we sample per test.
SAMPLE_COUNT = 3
USEC_IN_MSEC = 1000


def snapshot_create_producer(vm):
    """Produce results for snapshot create tests."""
    vm.snapshot_full()
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


def test_older_snapshot_resume_latency(
    microvm_factory,
    guest_kernel_linux_4_14,
    rootfs,
    firecracker_release,
    io_engine,
    metrics,
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

    vm = microvm_factory.build(
        guest_kernel_linux_4_14,
        rootfs,
        monitor_memory=False,
        fc_binary_path=firecracker_release.path,
        jailer_binary_path=firecracker_release.jailer,
    )
    vm.spawn()
    vm.basic_config(vcpu_count=2, mem_size_mib=512)
    vm.add_net_iface()
    vm.start()
    # Check if guest works.
    exit_code, _, _ = vm.ssh.run("ls")
    assert exit_code == 0
    snapshot = vm.snapshot_full()

    metrics.set_dimensions(
        {
            **vm.dimensions,
            "io_engine": io_engine,
            "performance_test": "test_older_snapshot_resume_latency",
            "firecracker_version": firecracker_release.name,
        }
    )

    for _ in range(SAMPLE_COUNT):
        metrics.put_metric(
            "latency",
            snapshot_resume_producer(microvm_factory, snapshot),
            "Milliseconds",
        )


def test_snapshot_create_latency(
    microvm_factory,
    guest_kernel_linux_4_14,
    rootfs,
    metrics,
):
    """Measure the latency of creating a Full snapshot"""

    vm = microvm_factory.build(guest_kernel_linux_4_14, rootfs, monitor_memory=False)
    vm.spawn()
    vm.basic_config(vcpu_count=2, mem_size_mib=512)
    vm.start()
    vm.pin_threads(0)

    metrics.set_dimensions(
        {**vm.dimensions, "performance_test": "test_snapshot_create_latency"}
    )
    for _ in range(SAMPLE_COUNT):
        metrics.put_metric("latency", snapshot_create_producer(vm), "Milliseconds")
