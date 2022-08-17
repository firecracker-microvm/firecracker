# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Python."""

from framework import utils


def test_python_style():
    """
    Test that python code passes style checks.

    @type: style
    """
    # Runs command
    utils.run_cmd("black . --check --diff")
