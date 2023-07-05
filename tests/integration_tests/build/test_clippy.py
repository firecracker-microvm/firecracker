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

    # This is only temporary for testing before creating a new docker container.
    # TODO Remove this and instead add the tool to the docker container.
    utils.run_cmd("cargo install --git https://github.com/JonathanWoollett-Light/clippy-tracing --rev da3403e4feb6ff3ec6d74d735e374e21e03488f4")

    utils.run_cmd("clippy-tracing --action check path --path ../src --exclude virtio_gen,bindings.rs,net_gen,benches")
