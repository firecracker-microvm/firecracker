# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that check if the release binary sizes fall within expected size."""

import os
import platform
import pytest

from framework import utils

MACHINE = platform.machine()
""" Platform definition used to select the correct size target"""

if MACHINE == "x86_64":
    SIZE_TARGETS = {"firecracker": 2012944, "jailer": 1087192}
elif MACHINE == "aarch64":
    SIZE_TARGETS = {"firecracker": 2322392, "jailer": 851152}
else:
    raise Exception(f"Unsupported processor model ({PROC_MODEL})")

MAX_DELTA = 0.05
"""Tolerance of 5% allowed for binary size"""


@pytest.mark.timeout(500)
def test_firecracker_binary_size():
    """
    Test if the size of the firecracker binary is within expected ranges.

    @type: build
    """
    check_binary_size("firecracker")


@pytest.mark.timeout(500)
def test_jailer_binary_size():
    """
    Test if the size of the jailer binary is within expected ranges.

    @type: build
    """
    check_binary_size("jailer")


def check_binary_size(name):
    """Check if the specified binary falls within the expected range."""

    build_target = f"{MACHINE}-unknown-linux-musl"
    # Build release binary
    utils.run_cmd(
        f"(cd .. && exec cargo build --all --release --target {build_target})"
    )
    # Strip symbols from binary
    utils.run_cmd(f"(cd .. && exec strip ./target/{build_target}/release/{name})")

    # Get size of release binary.
    size = os.path.getsize(f"../target/{build_target}/release/{name}")

    # Get target
    size_target = SIZE_TARGETS[name]

    # Calculate upper and lower bounds.
    lower_bound = size_target * (1.0 - MAX_DELTA)
    upper_bound = size_target * (1.0 + MAX_DELTA)

    # Compare target to bounds.
    assert (
        size >= lower_bound
    ), f"Current binary size ({size}) is more than {MAX_DELTA:.2f}% below \
            the target ({size_target})"
    assert (
        size <= upper_bound
    ), f"Current binary size ({size}) is more than {MAX_DELTA:.2f}% above \
            the target ({size_target})"
