# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the metrics system."""

import datetime
import math
import platform


def test_flush_metrics(test_microvm_with_api):
    """
    Check the `FlushMetrics` vmm action.
    """
    microvm = test_microvm_with_api
    microvm.spawn()
    microvm.basic_config()
    microvm.start()

    metrics = microvm.flush_metrics()

    exp_keys = [
        "utc_timestamp_ms",
        "api_server",
        "balloon",
        "block",
        "deprecated_api",
        "get_api_requests",
        "i8042",
        "latencies_us",
        "logger",
        "mmds",
        "net",
        "patch_api_requests",
        "put_api_requests",
        "seccomp",
        "vcpu",
        "vmm",
        "uart",
        "signals",
        "vsock",
        "entropy",
    ]

    if platform.machine() == "aarch64":
        exp_keys.append("rtc")

    assert set(metrics.keys()) == set(exp_keys)

    utc_time = datetime.datetime.now(datetime.timezone.utc)
    utc_timestamp_ms = math.floor(utc_time.timestamp() * 1000)

    # Assert that the absolute difference is less than 1 second, to check that
    # the reported utc_timestamp_ms is actually a UTC timestamp from the Unix
    # Epoch.Regression test for:
    # https://github.com/firecracker-microvm/firecracker/issues/2639
    assert abs(utc_timestamp_ms - metrics["utc_timestamp_ms"]) < 1000
