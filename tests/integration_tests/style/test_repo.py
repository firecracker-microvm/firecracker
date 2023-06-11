# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests enforcing git repository structure"""

import subprocess
from pathlib import Path

import yaml


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

    repo_root = Path("..")
    for path in repo_root.rglob("*.y*ml"):
        yaml.safe_load(path.open(encoding="utf-8"))
