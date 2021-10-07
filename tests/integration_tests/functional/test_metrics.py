# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the metrics system."""

import datetime
import os
import math
import platform
import host_tools.logging as log_tools


def test_flush_metrics(test_microvm_with_api):
    """
    Check the `FlushMetrics` vmm action.

    @type: functional
    """
    microvm = test_microvm_with_api
    microvm.spawn()
    microvm.basic_config()

    # Configure metrics system.
    metrics_fifo_path = os.path.join(microvm.path, 'metrics_fifo')
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)

    response = microvm.metrics.put(
        metrics_path=microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    microvm.start()

    metrics = microvm.flush_metrics(metrics_fifo)

    exp_keys = [
        'utc_timestamp_ms',
        'api_server',
        'balloon',
        'block',
        'deprecated_api',
        'get_api_requests',
        'i8042',
        'latencies_us',
        'logger',
        'mmds',
        'net',
        'patch_api_requests',
        'put_api_requests',
        'seccomp',
        'vcpu',
        'vmm',
        'uart',
        'signals',
        'vsock'
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
    assert abs(utc_timestamp_ms - metrics['utc_timestamp_ms']) < 1000
