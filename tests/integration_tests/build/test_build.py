# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that check if both the debug and the release builds pass."""

import os

import host_tools.cargo_build as host  # pylint:disable=import-error


CARGO_DEBUG_REL_PATH = os.path.join(host.CARGO_BUILD_REL_PATH, 'debug')
CARGO_DEBUG_REL_PATH_FEATURES = os.path.join(
    host.CARGO_BUILD_REL_PATH,
    'debug-features'
)
CARGO_RELEASE_REL_PATH_FEATURES = os.path.join(
    host.CARGO_BUILD_REL_PATH,
    'release-features'
)


def test_build_debug(test_session_root_path):
    """Test if a debug-mode build works."""
    build_path = os.path.join(
        test_session_root_path,
        CARGO_DEBUG_REL_PATH
    )
    host.cargo_build(build_path)


def test_build_debug_with_features(test_session_root_path):
    """Test if a debug-mode build works for supported features."""
    build_path = os.path.join(
        test_session_root_path,
        CARGO_DEBUG_REL_PATH_FEATURES
    )
    # Building with multiple features is as simple as:
    # cargo build --features "feature1 feature2". We are currently
    # supporting only one features: vsock.
    host.cargo_build(build_path, '--features "{}"'.format('vsock'))


def test_build_release(test_session_root_path):
    """Test if a release-mode build works."""
    build_path = os.path.join(
        test_session_root_path,
        host.CARGO_RELEASE_REL_PATH
    )
    host.cargo_build(build_path, '--release')


def test_build_release_with_features(test_session_root_path):
    """Test if a release-mode build works for supported features."""
    build_path = os.path.join(
        test_session_root_path,
        CARGO_RELEASE_REL_PATH_FEATURES
    )
    host.cargo_build(
        build_path,
        '--features "{}"'.format('vsock'),
        '--release'
    )


def test_arm_build_release(test_session_root_path):
    """Test cross compilation for arm in release mode."""
    build_path = os.path.join(
        test_session_root_path,
        'arm-build'
    )
    host.cargo_build(
        build_path,
        '--target aarch64-unknown-linux-musl',
        '--release'
    )
