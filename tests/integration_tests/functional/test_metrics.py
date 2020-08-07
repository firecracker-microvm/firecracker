# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the metrics system."""

import os
import json
import host_tools.logging as log_tools


def test_flush_metrics(test_microvm_with_api):
    """Check the `FlushMetrics` vmm action."""
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

    res = metrics_fifo.sequential_reader(1)
    metrics = json.loads(res[0])

    exp_keys = [
        'utc_timestamp_ms',
        'api_server',
        'balloon',
        'block',
        'get_api_requests',
        'i8042',
        'latencies_us',
        'logger',
        'mmds',
        'net',
        'patch_api_requests',
        'put_api_requests',
        'rtc',
        'seccomp',
        'vcpu',
        'vmm',
        'uart',
        'signals',
        'vsock'
    ]

    assert set(metrics.keys()) == set(exp_keys)

    microvm.flush_metrics(metrics_fifo)
