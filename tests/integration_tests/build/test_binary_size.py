# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that check if the release binary sizes fall within expected size."""

import os
import platform

import pytest

import host_tools.cargo_build as host

MACHINE = platform.machine()
""" Platform definition used to select the correct size target"""

SIZES_DICT = {
    "x86_64": {
        "FC_BINARY_SIZE_TARGET": 2649920,
        "JAILER_BINARY_SIZE_TARGET": 965840,
    },
    "aarch64": {
        "FC_BINARY_SIZE_TARGET": 2441008,
        "JAILER_BINARY_SIZE_TARGET": 898656,
    },
}

FC_BINARY_SIZE_TARGET = SIZES_DICT[MACHINE]["FC_BINARY_SIZE_TARGET"]
"""Firecracker target binary size in bytes"""

JAILER_BINARY_SIZE_TARGET = SIZES_DICT[MACHINE]["JAILER_BINARY_SIZE_TARGET"]
"""Jailer target binary size in bytes"""

BINARY_SIZE_TOLERANCE = 0.05
"""Tolerance of 5% allowed for binary size"""


@pytest.mark.timeout(500)
def test_firecracker_binary_size(record_property, metrics):
    """
    Test if the size of the firecracker binary is within expected ranges.

    @type: build
    """
    fc_binary, _ = host.get_firecracker_binaries()

    result = check_binary_size(
        "firecracker",
        fc_binary,
        FC_BINARY_SIZE_TARGET,
        BINARY_SIZE_TOLERANCE,
    )

    record_property(
        "firecracker_binary_size",
        f"{result}B ({FC_BINARY_SIZE_TARGET}B ±{BINARY_SIZE_TOLERANCE:.0%})",
    )
    metrics.set_dimensions({"cpu_arch": MACHINE})
    metrics.put_metric("firecracker_binary_size", result, unit="Bytes")


@pytest.mark.timeout(500)
def test_jailer_binary_size(record_property, metrics):
    """
    Test if the size of the jailer binary is within expected ranges.

    @type: build
    """
    _, jailer_binary = host.get_firecracker_binaries()

    result = check_binary_size(
        "jailer",
        jailer_binary,
        JAILER_BINARY_SIZE_TARGET,
        BINARY_SIZE_TOLERANCE,
    )

    record_property(
        "jailer_binary_size",
        f"{result}B ({JAILER_BINARY_SIZE_TARGET}B ±{BINARY_SIZE_TOLERANCE:.0%})",
    )
    metrics.set_dimensions({"cpu_arch": MACHINE})
    metrics.put_metric("jailer_binary_size", result, unit="Bytes")


def check_binary_size(name, binary_path, size_target, tolerance):
    """Check if the specified binary falls within the expected range."""
    # Get the size of the release binary.
    binary_size = os.path.getsize(binary_path)

    # Get the name of the variable that needs updating.
    namespace = globals()
    size_target_name = [name for name in namespace if namespace[name] is size_target][0]

    # Compute concrete binary size difference.
    delta_size = size_target - binary_size

    binary_low_msg = (
        "Current {} binary size of {} bytes is below the target"
        " of {} bytes with {} bytes.\n"
        "Update the {} threshold".format(
            name, binary_size, size_target, delta_size, size_target_name
        )
    )

    assert binary_size > size_target * (1 - tolerance), binary_low_msg

    binary_high_msg = (
        "Current {} binary size of {} bytes is above the target"
        " of {} bytes with {} bytes.\n".format(
            name, binary_size, size_target, -delta_size
        )
    )

    assert binary_size < size_target * (1 + tolerance), binary_high_msg
    return binary_size
