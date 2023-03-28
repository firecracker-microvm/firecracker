# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust."""

import subprocess

from framework import utils


def test_rust_style():
    """
    Test that rust code passes style checks.

    @type: style
    """

    #  ../src/io_uring/src/bindings.rs
    config = open("fmt.toml", encoding="utf-8").read().replace("\n", ",")
    # Check that the output is empty.
    _, stdout, _ = utils.run_cmd(f"cargo fmt --all -- --check --config {config}")

    # rustfmt prepends `"Diff in"` to the reported output.
    assert "Diff in" not in stdout


def test_ensure_mod_tests():
    """
    Check that files containing unit tests have a 'tests' module defined.

    @type: style
    """
    excluding = [
        "_gen/",
        "/tests/",
        "/test_utils",
        "build/",
        "src/io_uring/src/bindings.rs",
    ]

    # Files with `#[test]` without `mod tests`.
    cmd = 'find ../src -type f -name "*.rs" |xargs grep --files-without-match "mod tests {" |xargs grep --files-with-matches "#\\[test\\]"'
    res = subprocess.run(cmd, shell=True, capture_output=True, check=True)
    tests_without_mods = res.stdout.decode("utf-8").split("\n")

    # Files with `#[test]` without `mod tests` excluding file paths which contain any string from
    # `excluding` or are empty.
    final = [
        f
        for f in tests_without_mods
        if not any(x in f for x in excluding) and len(f) > 0
    ]

    # Assert `final` is empty.
    assert (
        final == []
    ), "`#[test]`s found in files without `mod tests`s. Code coverage requires that tests are in test modules."
