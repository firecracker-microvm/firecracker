# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /balloon resources."""

import concurrent
import signal
import time

import pytest

from framework.microvm import HugePagesConfig
from framework.utils import (
    get_stable_rss_mem,
    supports_hugetlbfs_discard,
    track_cpu_utilization,
)

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
    microvm_factory,
    guest_kernel_linux_6_1,
    rootfs,
    method,
    metrics,
    huge_pages,
):
    """
    Measure the CPU usage when running free page reporting and hinting
    """
    test_microvm = microvm_factory.build(
        guest_kernel_linux_6_1,
        rootfs,
        pci=True,
        monitor_memory=False,
    )
    test_microvm.spawn(emit_metrics=False)
    test_microvm.basic_config(vcpu_count=2, mem_size_mib=1024, huge_pages=huge_pages)
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
            "huge_pages": str(huge_pages),
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
        guest_kernel_linux_6_1,
        rootfs,
        pci=True,
        monitor_memory=False,
    )
    test_microvm.spawn(emit_metrics=False)
    test_microvm.basic_config(vcpu_count=2, mem_size_mib=1024, huge_pages=huge_pages)
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


# pylint: disable=C0103
@pytest.mark.parametrize("method", ["traditional", "hinting", "reporting"])
def test_size_reduction(uvm_plain_any, method, huge_pages):
    """
    Verify that ballooning reduces RSS usage on a newly booted guest.
    """
    traditional_balloon = method == "traditional"
    free_page_reporting = method == "reporting"
    free_page_hinting = method == "hinting"

    if huge_pages != HugePagesConfig.NONE:
        if not supports_hugetlbfs_discard():
            pytest.skip("Host does not support hugetlb discard")

        if traditional_balloon:
            pytest.skip("Traditional balloon device won't reduce RSS")

    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config(huge_pages=huge_pages)
    test_microvm.add_net_iface()

    # Add a memory balloon.
    test_microvm.api.balloon.put(
        amount_mib=0,
        deflate_on_oom=True,
        stats_polling_interval_s=0,
        free_page_reporting=free_page_reporting,
        free_page_hinting=free_page_hinting,
    )

    # Start the microvm.
    test_microvm.start()

    get_stable_rss_mem(test_microvm)

    test_microvm.ssh.check_output(
        "nohup /usr/local/bin/fast_page_fault_helper >/dev/null 2>&1 </dev/null &"
    )

    time.sleep(1)

    first_reading = get_stable_rss_mem(test_microvm)

    _, pid, _ = test_microvm.ssh.check_output("pidof fast_page_fault_helper")
    # Kill the application which will free the held memory
    test_microvm.ssh.check_output(f"kill -s {signal.SIGUSR1} {pid}")

    # Sleep to allow guest to clean up
    time.sleep(1)
    # Have the guest drop its caches.
    test_microvm.ssh.run("sync; echo 3 > /proc/sys/vm/drop_caches")
    time.sleep(2)

    # We take the initial reading of the RSS, then calculate the amount
    # we need to inflate the balloon with by subtracting it from the
    # VM size and adding an offset of 10 MiB in order to make sure we
    # get a lower reading than the initial one.
    inflate_size = 256 - int(first_reading / 1024) + 10

    if traditional_balloon:
        # Now inflate the balloon
        test_microvm.api.balloon.patch(amount_mib=inflate_size)
    elif free_page_hinting:
        test_microvm.api.balloon_hinting_start.patch()

    _ = get_stable_rss_mem(test_microvm)

    if traditional_balloon:
        # Deflate the balloon completely.
        test_microvm.api.balloon.patch(amount_mib=0)

    # Check memory usage again.
    second_reading = get_stable_rss_mem(test_microvm)

    # There should be a reduction of at least 10MB.
    assert first_reading - second_reading >= 10000
