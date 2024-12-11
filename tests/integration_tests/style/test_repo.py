# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests enforcing git repository structure"""

import re
import subprocess
from pathlib import Path

import yaml

from framework import utils_repo


def test_repo_no_spaces_in_paths():
    """
    Ensure there are no spaces in paths.
    """
    # pylint: disable-next=subprocess-run-check
    res = subprocess.run(
        "git ls-files | grep '[[:space:]]'",
        cwd="..",
        capture_output=True,
        shell=True,
    )
    # If grep doesn't find any, it will exit with status 1. Otherwise 0
    assert res.returncode == 1, "Some files have spaces:\n" + res.stdout.decode()


def test_repo_validate_yaml():
    """
    Ensure all YAML files are valid
    """

    for path in utils_repo.git_repo_files(root="..", glob="*.y*ml"):
        yaml.safe_load(path.open(encoding="utf-8"))


def test_repo_validate_changelog():
    """Make sure the CHANGELOG.md file follows the Keep a Changelog format"""

    changelog_path = Path("../CHANGELOG.md")
    changelog = changelog_path.read_text(encoding="utf-8").splitlines()
    errors = []
    for lineno, line in enumerate(changelog, start=1):
        if line.startswith("## "):
            if not re.match(r"^## \[.+\]$", line):
                msg = "Level 2 headings (versions) should be wrapped in []"
                errors.append((lineno, msg, line))
        if line.startswith("### "):
            if not re.match(r"^### (Added|Changed|Deprecated|Removed|Fixed)$", line):
                msg = "Unknown Level 3 heading"
                errors.append((lineno, msg, line))

    for lineno, msg, line in errors:
        print(msg)
        print(f"\t{lineno}:{line}")
    assert len(errors) == 0
