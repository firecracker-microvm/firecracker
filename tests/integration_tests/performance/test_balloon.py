# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /balloon resources."""

import concurrent
import signal
import time

import pytest

from framework.utils import track_cpu_utilization

NS_IN_MSEC = 1_000_000


def trigger_page_fault_run(vm):
    """
    Clears old data and starts the fast_page_fault_helper script
    """
    vm.ssh.check_output(
        "rm -f /tmp/fast_page_fault_helper.out && /usr/local/bin/fast_page_fault_helper -s"
    )


def get_page_fault_duration(vm):
    """
    Waits for the performance data to be available and will read the duration
    """
    _, duration, _ = vm.ssh.check_output(
        "while [ ! -f /tmp/fast_page_fault_helper.out ]; do sleep 1; done; cat /tmp/fast_page_fault_helper.out"
    )
    return duration


@pytest.mark.parametrize("method", ["reporting", "hinting"])
@pytest.mark.nonci
def test_hinting_reporting_cpu(
    microvm_factory, guest_kernel_linux_6_1, rootfs, method, metrics
):
    """
    Measure the CPU usage when running free page reporting and hinting
    """
    test_microvm = microvm_factory.build(
        guest_kernel_linux_6_1, rootfs, pci=True, monitor_memory=False
    )
    test_microvm.spawn(emit_metrics=False)
    test_microvm.basic_config(vcpu_count=2, mem_size_mib=1024)
    test_microvm.add_net_iface()

    free_page_reporting = method == "reporting"
    free_page_hinting = method == "hinting"
    # Add a deflated memory balloon.
    test_microvm.api.balloon.put(
        amount_mib=0,
        deflate_on_oom=False,
        stats_polling_interval_s=0,
        free_page_reporting=free_page_reporting,
        free_page_hinting=free_page_hinting,
    )
    test_microvm.start()
    test_microvm.pin_threads(0)

    metrics.set_dimensions(
        {
            "performance_test": "test_balloon_cpu",
            # "huge_pages": str(huge_pages),
            "method": method,
            **test_microvm.dimensions,
        }
    )

    test_microvm.ssh.check_output(
        "nohup /usr/local/bin/fast_page_fault_helper >/dev/null 2>&1 </dev/null &"
    )

    # Give helper time to initialize
    time.sleep(5)
    _, pid, _ = test_microvm.ssh.check_output("pidof fast_page_fault_helper")
    test_microvm.ssh.check_output(f"kill -s {signal.SIGUSR1} {pid}")

    cpu_util = None

    if free_page_reporting:
        cpu_util = track_cpu_utilization(test_microvm.firecracker_pid, 5, 0)
    else:
        test_microvm.ssh.check_output(
            "while [ ! -f /tmp/fast_page_fault_helper.out ]; do sleep 1; done;"
        )

        with concurrent.futures.ThreadPoolExecutor() as executor:
            cpu_load_future = executor.submit(
                track_cpu_utilization,
                test_microvm.firecracker_pid,
                2,
                omit=0,
            )
            test_microvm.api.balloon_hinting_start.patch()
            cpu_util = cpu_load_future.result()

    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")


@pytest.mark.parametrize("sleep_duration", [0, 1, 5])
@pytest.mark.nonci
def test_hinting_fault_latency(
    microvm_factory,
    guest_kernel_linux_6_1,
    rootfs,
    metrics,
    sleep_duration,
    huge_pages,
):
    """
    Measure the overhead of running free page reporting with allocation heavy
    workloads.

    Test with different sleep intervals to measure the effect
    depending on frequenecy
    """
    runs = 5
    test_microvm = microvm_factory.build(
        guest_kernel_linux_6_1, rootfs, pci=True, monitor_memory=False
    )
    test_microvm.spawn(emit_metrics=False)
    test_microvm.basic_config(vcpu_count=2, mem_size_mib=1024)
    test_microvm.add_net_iface()

    # Add a deflated memory balloon.
    test_microvm.api.balloon.put(
        amount_mib=0,
        deflate_on_oom=False,
        stats_polling_interval_s=0,
        free_page_reporting=True,
    )
    test_microvm.start()
    test_microvm.pin_threads(0)

    metrics.set_dimensions(
        {
            "performance_test": "test_hinting_fault_latency",
            "sleep_duration": str(sleep_duration),
            **test_microvm.dimensions,
        }
    )

    for i in range(runs):
        trigger_page_fault_run(test_microvm)
        reporting_duration = int(get_page_fault_duration(test_microvm)) / NS_IN_MSEC
        metrics.put_metric("latency", reporting_duration, "Milliseconds")

        if sleep_duration > 0 and (i + 1 < runs):
            time.sleep(sleep_duration)
