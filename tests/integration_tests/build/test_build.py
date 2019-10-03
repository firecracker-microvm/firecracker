# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that check if both the debug and the release builds pass."""

import itertools
import os
import platform

import pytest

import host_tools.cargo_build as host  # pylint:disable=import-error

MACHINE = platform.machine()
FEATURES = [""]
TARGETS = ["{}-unknown-linux-gnu".format(MACHINE),
           "{}-unknown-linux-musl".format(MACHINE)]


@pytest.mark.parametrize(
    "features, target",
    itertools.product(FEATURES, TARGETS)
)
@pytest.mark.timeout(500)
def test_build(test_session_root_path, features, target):
    """
    Test different builds.

    This will generate build tests using the cartesian product of all
    features and build targets (musl/gnu).
    """
    extra_env = ''
    extra_args = "--target {} --release ".format(target)

    if "musl" in target:
        extra_env += "TARGET_CC=musl-gcc"

    rel_path = host.CARGO_RELEASE_REL_PATH
    if features:
        rel_path += "-{}".format(features)
        extra_args += "--features {} ".format(features)

    build_path = os.path.join(
        test_session_root_path,
        rel_path
    )

    host.cargo_build(build_path, extra_args=extra_args, extra_env=extra_env)
