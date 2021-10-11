# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust."""

import framework.utils as utils


def test_rust_style():
    """
    Test that rust code passes style checks.

    @type: style
    """
    # Check that the output is empty.
    _, stdout, _ = utils.run_cmd(
        'cargo fmt --all -- --check')

    # rustfmt prepends `"Diff in"` to the reported output.
    assert "Diff in" not in stdout


def test_ensure_mod_tests():
    """
    Check that files containing unit tests have a 'tests' module defined.

    @type: style
    """
    # List all source files containing rust #[test] attribute,
    # (excluding generated files and integration test directories).
    # Take the list and check each file contains 'mod tests {', output file
    # name if it doesn't.
    cmd = (
        '/bin/bash '
        '-c '
        '"grep '
        '--files-without-match '
        '\'mod tests {\' '
        '\\$(grep '
        '--files-with-matches '
        '--recursive '
        '--exclude-dir=src/*_gen/* '
        '\'\\#\\[test\\]\' ../src/*/src)" '
        '| grep -v "../src/io_uring/src/bindings.rs"'
    )

    # The outer grep returns 0 even if it finds files without the match, so we
    # ignore the return code.
    result = utils.run_cmd(cmd, no_shell=False, ignore_return_code=True)

    stdout = result.stdout.strip()

    error_msg = (
        'Tests found in files without a "tests" module:\n {}'
        'To ensure code coverage is reported correctly, please check that '
        'your tests are in a module named "tests".'.format(stdout)
    )

    assert not stdout, error_msg
