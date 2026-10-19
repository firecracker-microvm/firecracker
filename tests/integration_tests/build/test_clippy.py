# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust and Python."""

import platform

from host_tools.cargo_build import cargo

MACHINE = platform.machine()
TARGETS = [
    f"{MACHINE}-unknown-linux-gnu",
    f"{MACHINE}-unknown-linux-musl",
]


def test_rust_clippy():
    """
    Test that clippy does not generate any errors/warnings.
    """
    # One invocation for both targets: separate ones would serialize on cargo's
    # build-directory lock, and this one shares the host-side artifacts.
    targets = " ".join(f"--target {target}" for target in TARGETS)
    cargo(
        "clippy",
        f"{targets} --all --all-targets --all-features",
        "-D warnings",
    )
