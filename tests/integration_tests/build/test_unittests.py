# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures that all unit tests pass at integration time."""

import platform

import pytest

import host_tools.cargo_build as host  # pylint:disable=import-error

MACHINE = platform.machine()
TARGETS = ["{}-unknown-linux-gnu".format(MACHINE),
           "{}-unknown-linux-musl".format(MACHINE)]


@pytest.mark.parametrize(
    "target",
    TARGETS
)
def test_unittests(test_session_root_path, target):
    """Run unit and doc tests for all supported targets."""
    extra_env = ''
    extra_args = "--release --target {} ".format(target)

    if "musl" in target:
        extra_env += "TARGET_CC=musl-gcc"

        if MACHINE == "x86_64":
            pytest.skip("On x86_64 with musl target unit tests"
                        " are already run as part of testing"
                        " code-coverage.")

    host.cargo_test(
        test_session_root_path,
        extra_args=extra_args,
        extra_env=extra_env
    )
