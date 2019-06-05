# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that check if both the debug and the release builds pass."""

import itertools
import os
import platform

import pytest

import host_tools.cargo_build as host  # pylint:disable=import-error

FEATURES = ["", "vsock"]
BUILD_TYPES = ["debug", "release"]

MACHINE = platform.machine()
TARGETS = ["{}-unknown-linux-gnu".format(MACHINE),
           "{}-unknown-linux-musl".format(MACHINE)]


@pytest.mark.parametrize(
    "features, build_type, target",
    itertools.product(FEATURES, BUILD_TYPES, TARGETS)
)
@pytest.mark.timeout(400)
def test_build(test_session_root_path, features, build_type, target):
    """
    Test different builds.

    This will generate build tests using the cartesian product of all
    features, build types (release/debug) and build targets (musl/gnu).
    """
    extra_env = ''
    extra_args = "--target {} ".format(target)

    if build_type == "release":
        extra_args += "--release "

    if "musl" in target:
        extra_env += "TARGET_CC=musl-gcc"

    # The relative path of the binaries is computed using the build_type
    # (either release or debug) and if any features are provided also using
    # the features names.
    # For example, a default release build with no features will end up in
    # the relative directory "release", but for a vsock release build the
    # relative directory will be "release-vsock".
    rel_path = os.path.join(
        host.CARGO_BUILD_REL_PATH,
        build_type
    )
    if features:
        rel_path += "-{}".format(features)
        extra_args += "--features {} ".format(features)

    build_path = os.path.join(
        test_session_root_path,
        rel_path
    )

    host.cargo_build(build_path, extra_args=extra_args, extra_env=extra_env)
