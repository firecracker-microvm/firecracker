# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures that all unit tests pass at integration time."""

from framework import utils


def test_unittests():
    """
    Run unit and doc tests for all supported targets.

    @type: build
    """
    utils.run_cmd("cargo test --all --no-fail-fast -- --test-threads=1")
