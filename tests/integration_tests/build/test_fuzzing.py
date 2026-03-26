# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures that firecracker builds with fuzzing feature enabled at integration time."""

import pytest

import host_tools.cargo_build


def test_fuzzing_compiles():
    """Checks that Firecracker compiles with fuzzing enabled"""

    host_tools.cargo_build.build_fuzzing()


def test_fuzzing_does_not_compile_release():
    """Checks that Firecracker refuses to compile with fuzzing in release mode"""

    with pytest.raises(ChildProcessError, match="fuzzing.*must not be used in release"):
        host_tools.cargo_build.build_fuzzing(release=True)
