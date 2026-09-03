# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Python."""

import os
import sys
from subprocess import run

import pytest


@pytest.mark.parametrize("formatter", ["black --config tests/pyproject.toml", "isort"])
def test_python_style(formatter):
    """
    Test that python code passes `formatter`
    """
    run(
        f"{formatter} --check --diff tests tools .buildkite",
        stdout=sys.stdout,
        stderr=sys.stderr,
        shell=True,
        cwd="..",
        check=True,
    )


def test_python_pylint():
    """
    Test that python code passes linter checks.
    """
    # `jobs = 0` in pyproject.toml is meant to auto-detect the CPU count, but
    # pylint reads it from cgroup v1 `cpu.shares`, which Docker leaves at 1024,
    # so it settles on one job in the dev container however many CPUs we have.
    jobs = min(len(os.sched_getaffinity(0)), 32)

    # List of linter commands that should be executed for each file
    linter_cmd = f"pylint --rcfile tests/pyproject.toml -j {jobs} --output-format=colorized tests/ tools/ .buildkite/*.py"
    run(
        linter_cmd,
        # we let pytest capture stdout/stderr for us
        stdout=sys.stdout,
        stderr=sys.stderr,
        shell=True,
        cwd="..",
        check=True,
    )
