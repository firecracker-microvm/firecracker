# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for markdown style checks."""

from framework import utils, utils_repo


def test_markdown_style():
    """
    Test that markdown files adhere to the style rules.
    """
    # Get all *.md files from the project
    md_files = list(utils_repo.git_repo_files(root="..", glob="*.md"))

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
    ), "Some markdown files need formatting. Either run `./tools/devtool sh mdformat .` in the repository root, or apply the above diffs manually."
