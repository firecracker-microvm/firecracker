# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring desired style for commit messages."""

import os

from framework import utils
from framework.ab_test import DEFAULT_A_REVISION
from framework.properties import global_props


def test_gitlint():
    """
    Test that all commit messages pass the gitlint rules.
    """
    os.environ["LC_ALL"] = "C.UTF-8"
    os.environ["LANG"] = "C.UTF-8"

    base = global_props.buildkite_merge_queue_base or f"origin/{DEFAULT_A_REVISION}"
    rc, _, stderr = utils.run_cmd(
        f"gitlint --commits {base}..HEAD -C ../.gitlint --extra-path framework/gitlint_rules.py",
    )
    assert rc == 0, "Commit message violates gitlint rules: {}".format(stderr)
