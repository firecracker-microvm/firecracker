# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for markdown style checks."""

from framework import utils


def test_markdown_style():
    """
    Test that markdown files adhere to the style rules.
    """
    # Get all *.md files from the project
    md_files = utils.get_files_from(
        find_path="..", pattern="*.md", exclude_names=["build"]
    )

    # Assert if somehow no markdown files were found.
    assert len(md_files) != 0

    # Run commands
    cmd = "mdl -c ../.mdlrc "
    for fname in md_files:
        cmd += fname + " "
    _, output, _ = utils.run_cmd(cmd)
    assert output == ""
