# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functionality for a shared binary build and release path for all tests."""

import os

from subprocess import run

from framework.defs import FC_BINARY_NAME, JAILER_BINARY_NAME

CARGO_BUILD_REL_PATH = 'firecracker_binaries'
"""Keep a single build path across all build tests."""

CARGO_RELEASE_REL_PATH = os.path.join(
    CARGO_BUILD_REL_PATH, 'release'
)
"""Keep a single Firecracker release binary path across all test types."""

CARGO_RELEASE_VSOCK_REL_PATH = os.path.join(
    CARGO_BUILD_REL_PATH, 'release-vsock'
)
"""Vsock release binaries relative path."""

RELEASE_BINARIES_REL_PATH = 'x86_64-unknown-linux-musl/release/'


class UnknownFeatureException(Exception):
    """Exception Class for invalid build feature."""
    def __init__(self):
        Exception.__init__(
            self,
            "Trying to get build binaries for unknown feature!"
        )


def cargo_build(path, extra_args=''):
    """Trigger build depending on flags provided."""
    cmd = 'CARGO_TARGET_DIR={} cargo build {}'.format(
        path,
        extra_args
    )
    run(cmd, shell=True, check=True)


def get_firecracker_binaries(root_path, features=''):
    """Build the Firecracker and Jailer binaries if they don't exist.

    Returns the location of the firecracker related binaries eventually after
    building them in case they do not exist at the specified root_path.
    """

    if features == '':
        cargo_binaries_rel_path = CARGO_RELEASE_REL_PATH
    elif features == 'vsock':
        cargo_binaries_rel_path = CARGO_RELEASE_VSOCK_REL_PATH
    else:
        raise UnknownFeatureException

    path_to_binaries = os.path.join(
        root_path,
        os.path.join(
            cargo_binaries_rel_path,
            RELEASE_BINARIES_REL_PATH
        )
    )
    fc_binary_path = os.path.join(path_to_binaries, FC_BINARY_NAME)
    jailer_binary_path = os.path.join(path_to_binaries, JAILER_BINARY_NAME)

    if (
            not os.path.isfile(fc_binary_path)
            or
            not os.path.isfile(jailer_binary_path)
    ):
        build_path = os.path.join(
            root_path,
            cargo_binaries_rel_path
        )
        cargo_build(
            build_path,
            extra_args='--release >/dev/null 2>&1'
        )
    return fc_binary_path, jailer_binary_path
