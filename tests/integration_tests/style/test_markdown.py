# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for markdown style checks."""

import re

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
        )
        if rc != 0:
            print(output)
            needs_format = True

    assert (
        not needs_format
    ), "Some markdown files need formatting. Either run `./tools/devtool sh mdformat .` in the repository root, or apply the above diffs manually."


def test_markdown_internal_links():
    """Make sure markdown internal links work"""

    for md_file in utils_repo.git_repo_files(root="..", glob="*.md"):
        txt = md_file.read_text(encoding="utf-8")
        for link in re.findall(r"\[.+?\]\((?P<link>.+?)\)", txt, re.DOTALL):
            if not re.match("(mailto:|https?://)", link):
                # internal link, ignore anchors (#) and query (?)
                parts = link.split("#", maxsplit=1)
                parts = parts[0].split("?", maxsplit=1)
                path = md_file.parent / parts[0]
                assert path.exists(), f"{md_file} {link} {path}"
