# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that check if the release binary sizes fall within expected size.

This is not representative of the actual memory overhead of Firecracker.

A more representative test is file:../performance/test_memory_overhead.py
"""

import platform

import pytest

MACHINE = platform.machine()


@pytest.mark.timeout(500)
def test_firecracker_binary_size(record_property, metrics, microvm_factory):
    """
    Test if the size of the firecracker binary is within expected ranges.
    """
    fc_binary = microvm_factory.fc_binary_path
    result = fc_binary.stat().st_size
    record_property("firecracker_binary_size", f"{result}B")
    metrics.set_dimensions({"cpu_arch": MACHINE})
    metrics.put_metric("firecracker_binary_size", result, unit="Bytes")


@pytest.mark.timeout(500)
def test_jailer_binary_size(record_property, metrics, microvm_factory):
    """
    Test if the size of the jailer binary is within expected ranges.
    """
    jailer_binary = microvm_factory.jailer_binary_path
    result = jailer_binary.stat().st_size
    record_property("jailer_binary_size", f"{result}B")
    metrics.set_dimensions({"cpu_arch": MACHINE})
    metrics.put_metric("jailer_binary_size", result, unit="Bytes")
