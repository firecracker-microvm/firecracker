# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring desired style for commit messages."""

import os

from framework import utils


def test_gitlint():
    """
    Test that all commit messages pass the gitlint rules.
    """
    os.environ["LC_ALL"] = "C.UTF-8"
    os.environ["LANG"] = "C.UTF-8"

    rc, _, stderr = utils.run_cmd(
        "gitlint --commits origin/main..HEAD -C ../.gitlint --extra-path framework/gitlint_rules.py",
    )
    assert rc == 0, "Commit message violates gitlint rules: {}".format(stderr)
