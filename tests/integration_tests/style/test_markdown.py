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

    needs_format = False

    # Run commands
    for md_file in md_files:
        rc, output, _ = utils.run_cmd(
            f"bash -c 'diff -u --color {md_file} <(mdformat - < {md_file})'",
            ignore_return_code=True,
        )
        if rc != 0:
            print(output)
            needs_format = True

    assert (
        not needs_format
    ), "Some markdown files need formatting. Either run `mdformat .` in the repository root, or apply the above diffs manually."
