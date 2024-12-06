# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Python."""

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
    # List of linter commands that should be executed for each file
    linter_cmd = "pylint --rcfile tests/pyproject.toml --output-format=colorized tests/ tools/ .buildkite/*.py"
    run(
        linter_cmd,
        # we let pytest capture stdout/stderr for us
        stdout=sys.stdout,
        stderr=sys.stderr,
        shell=True,
        cwd="..",
        check=True,
    )
