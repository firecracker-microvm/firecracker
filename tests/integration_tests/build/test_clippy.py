# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust and Python."""


import platform
import pytest
import framework.utils as utils

SUCCESS_CODE = 0
MACHINE = platform.machine()
TARGETS = ["{}-unknown-linux-gnu".format(MACHINE),
           "{}-unknown-linux-musl".format(MACHINE)]


@pytest.mark.parametrize(
    "target",
    TARGETS
)
def test_rust_clippy(target):
    """Fails if clippy generates any error, warnings are ignored."""
    utils.run_cmd(
        'cargo clippy --target {} --all --profile test'
        ' -- -D warnings'.format(target))
