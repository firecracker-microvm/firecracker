"""Functionality for a shared binary build and release path for all tests."""

import os

from subprocess import run

CARGO_BUILD_REL_PATH = 'firecracker_binaries'
"""Keep a single build path across all build tests."""

CARGO_RELEASE_REL_PATH = os.path.join(CARGO_BUILD_REL_PATH, 'release')
"""Keep a single Firecracker release binary path across all test types."""

RELEASE_BINARIES_REL_PATH = 'x86_64-unknown-linux-musl/release/'


def cargo_build(path, flags='', extra_args=''):
    """Use to ensure a single binary build and release path for all tests."""
    cmd = 'CARGO_TARGET_DIR={} cargo build {} {}'.format(
        path,
        flags,
        extra_args
    )
    run(cmd, shell=True, check=True)
