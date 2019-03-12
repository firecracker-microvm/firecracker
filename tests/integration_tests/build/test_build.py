# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that check if both the debug and the release builds pass."""

import itertools
import os
import pytest

import host_tools.cargo_build as host  # pylint:disable=import-error

FEATURES = ["", "vsock"]
BUILD_TYPES = ["debug", "release"]


@pytest.mark.parametrize(
    "features, build_type",
    itertools.product(FEATURES, BUILD_TYPES)
)
def test_build(test_session_root_path, features, build_type):
    """
    Test different builds.

    Test builds using a cartesian product of possible features and build
    types.
    """
    extra_args = ""

    if build_type == "release":
        extra_args += "--release "

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
        extra_args = "--features {} ".format(features)

    build_path = os.path.join(
        test_session_root_path,
        rel_path
    )

    host.cargo_build(build_path, extra_args=extra_args)


def test_arm_build_release(test_session_root_path):
    """Test cross compilation for arm in release mode."""
    build_path = os.path.join(
        test_session_root_path,
        'arm-build'
    )
    host.cargo_build(
        build_path,
        '--target aarch64-unknown-linux-musl --release'
    )
