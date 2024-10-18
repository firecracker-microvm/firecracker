# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

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
    for _ in range(SAMPLE_COUNT):
        metrics.put_metric("latency", snapshot_create_producer(vm), "Milliseconds")
