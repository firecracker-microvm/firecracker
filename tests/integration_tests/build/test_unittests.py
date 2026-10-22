# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures that all unit tests pass at integration time."""

import os
import platform

import pytest

import host_tools.cargo_build as host  # pylint:disable=import-error

MACHINE = platform.machine()
TARGET = "{}-unknown-linux-musl".format(MACHINE)


@pytest.mark.timeout(600)
def test_unittests(test_fc_session_root_path, request):
    """
    Run unit and doc tests for all supported targets.

    Skipped when test_coverage is in the same session: it runs the same tests.
    """
    if any(item.name == "test_coverage" for item in request.session.items):
        pytest.skip("test_coverage runs the unit tests in this session")

    host.cargo_test(
        os.path.join(test_fc_session_root_path, "unit-tests"), f"--target {TARGET}"
    )


def test_benchmarks_compile():
    """Checks that all benchmarks compile"""

    host.cargo("bench", f"--all --no-run --target {TARGET}")
