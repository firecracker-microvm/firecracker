# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests enforcing git repository structure"""

import subprocess

from framework.utils import run_cmd


def test_repo_no_spaces_in_paths():
    """
    Ensure there are no spaces in paths.

    @type: style
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


def test_repo_not_dirty():
    """
    Ensure there are no dirty files in repo.

    @type: style
    """
    _, stdout, _ = run_cmd("git diff --stat")
    assert stdout == "", "Repository is dirty: \n{}".format(stdout)
