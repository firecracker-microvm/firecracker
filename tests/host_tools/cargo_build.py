# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functionality for a shared binary build and release path for all tests."""

import os
import platform

import framework.utils as utils

from framework.defs import (
    FC_BINARY_NAME, FC_WORKSPACE_DIR, FC_WORKSPACE_TARGET_DIR,
    JAILER_BINARY_NAME
)

CARGO_BUILD_REL_PATH = 'firecracker_binaries'
"""Keep a single build path across all build tests."""

CARGO_RELEASE_REL_PATH = os.path.join(
    CARGO_BUILD_REL_PATH, 'release'
)
"""Keep a single Firecracker release binary path across all test types."""


DEFAULT_BUILD_TARGET = '{}-unknown-linux-musl'.format(platform.machine())
RELEASE_BINARIES_REL_PATH = '{}/release/'.format(DEFAULT_BUILD_TARGET)

CARGO_UNITTEST_REL_PATH = os.path.join(CARGO_BUILD_REL_PATH, "test")


def cargo_build(path, extra_args='', src_dir='', extra_env=''):
    """Trigger build depending on flags provided."""
    cmd = 'CARGO_TARGET_DIR={} {} cargo build {}'.format(
        path,
        extra_env,
        extra_args
    )
    if src_dir:
        cmd = 'cd {} && {}'.format(src_dir, cmd)

    utils.run_cmd(cmd)


def cargo_test(path, extra_args=''):
    """Trigger unit tests depending on flags provided."""
    path = os.path.join(path, CARGO_UNITTEST_REL_PATH)
    cmd = 'CARGO_TARGET_DIR={} RUST_TEST_THREADS=1 RUST_BACKTRACE=1 ' \
          'RUSTFLAGS="{}" cargo test {} --all --no-fail-fast'.format(
            path, get_rustflags(), extra_args)
    utils.run_cmd(cmd)


def get_firecracker_binaries():
    """Build the Firecracker and Jailer binaries if they don't exist.

    Returns the location of the firecracker related binaries eventually after
    building them in case they do not exist at the specified root_path.
    """
    target = DEFAULT_BUILD_TARGET
    cd_cmd = "cd {}".format(FC_WORKSPACE_DIR)
    flags = 'RUSTFLAGS="{}"'.format(get_rustflags())
    cargo_cmd = "cargo build --release --target {}".format(target)
    cmd = "{} && {} {}".format(cd_cmd, flags, cargo_cmd)

    utils.run_cmd(cmd)

    out_dir = "{target_dir}/{target}/release".format(
        target_dir=FC_WORKSPACE_TARGET_DIR, target=target
    )
    fc_bin_path = "{}/{}".format(out_dir, FC_BINARY_NAME)
    jailer_bin_path = "{}/{}".format(out_dir, JAILER_BINARY_NAME)

    utils.run_cmd(
        "strip --strip-debug {} {}"
        .format(fc_bin_path, jailer_bin_path)
    )

    return fc_bin_path, jailer_bin_path


def get_rustflags():
    """Get the relevant rustflags for building/unit testing."""
    rustflags = "-D warnings"
    if platform.machine() == "aarch64":
        rustflags += " -C link-arg=-lgcc -C link-arg=-lfdt "
    return rustflags
