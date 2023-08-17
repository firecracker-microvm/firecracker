# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust and Python."""


import platform

import pytest

from framework import utils
from host_tools.cargo_build import cargo

SUCCESS_CODE = 0
MACHINE = platform.machine()
TARGETS = [
    "{}-unknown-linux-gnu".format(MACHINE),
    "{}-unknown-linux-musl".format(MACHINE),
]


@pytest.mark.parametrize("target", TARGETS)
def test_rust_clippy(target):
    """
    Test that clippy does not generate any errors/warnings.
    """
    cargo("clippy", f"--target {target} --all --profile test", "-D warnings")

def test_clippy_tracing():
    """
    Tests clippy-tracing
    """

    # TODO Temporary for testing before creating a new docker container.
    utils.run_cmd("cargo install clippy-tracing")

    utils.run_cmd("clippy-tracing --action check --path ../src --exclude vmm_config/logger.rs,virtio_gen,bindings.rs,net_gen,benches")
