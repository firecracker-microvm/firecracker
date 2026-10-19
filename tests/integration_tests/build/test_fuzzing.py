# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures that firecracker builds with fuzzing feature enabled at integration time."""

import pytest

import host_tools.cargo_build


def test_fuzzing_compiles():
    """Checks that Firecracker compiles with fuzzing enabled"""

    # The functional tests build and run the binaries; a type-check is enough here.
    host_tools.cargo_build.build_fuzzing(check_only=True)


def test_fuzzing_does_not_compile_release():
    """Checks that Firecracker refuses to compile with fuzzing in release mode"""

    # `compile_error!` fires at type-check time; no need for a release build.
    with pytest.raises(ChildProcessError, match="fuzzing.*must not be used in release"):
        host_tools.cargo_build.build_fuzzing(release=True, check_only=True)
