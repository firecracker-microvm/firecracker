# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures that all unit tests pass at integration time."""

import platform

import pytest

import host_tools.cargo_build as host  # pylint:disable=import-error

MACHINE = platform.machine()
# Currently profiling with `aarch64-unknown-linux-musl` is unsupported (see
# https://github.com/rust-lang/rustup/issues/3095#issuecomment-1280705619) therefore we profile and
# run coverage with the `gnu` toolchains and run unit tests with the `musl` toolchains.
TARGETS = [
    "{}-unknown-linux-musl".format(MACHINE),
    "{}-unknown-linux-gnu".format(MACHINE),
]


@pytest.mark.timeout(600)
def test_unittests(test_fc_session_root_path):
    """
    Run unit and doc tests for all supported targets.
    """

    for target in TARGETS:
        extra_args = "--target {} ".format(target)
        host.cargo_test(test_fc_session_root_path, extra_args=extra_args)


def test_benchmarks_compile():
    """Checks that all benchmarks compile"""

    host.cargo("bench", f"--all --no-run --target {TARGETS[0]}")
