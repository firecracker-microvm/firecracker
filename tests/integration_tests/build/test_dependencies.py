# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Enforces controls over dependencies."""

from host_tools.cargo_build import cargo


def test_unused_dependencies():
    """
    Test that there are no unused dependencies.
    """
    cargo("udeps", "--all", nightly=True)
