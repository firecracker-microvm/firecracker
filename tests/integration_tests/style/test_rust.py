# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust."""

from framework import utils


def test_rust_order():
    """
    Tests that `Cargo.toml` dependencies are alphabetically ordered.

    @type: style
    """

    # Runs `cargo-sort` with the current working directory (`cwd`) as the repository root.
    _, _, _ = utils.check_output(
        cmd="cargo-sort --workspace --check --grouped", cwd=".."
    )


def test_rust_style():
    """
    Test that rust code passes style checks.
    """

    #  ../src/io_uring/src/bindings.rs
    config = open("fmt.toml", encoding="utf-8").read().replace("\n", ",")
    # Check that the output is empty.
    _, stdout, _ = utils.check_output(f"cargo fmt --all -- --check --config {config}")

    # rustfmt prepends `"Diff in"` to the reported output.
    assert "Diff in" not in stdout
