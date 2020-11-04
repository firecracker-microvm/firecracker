# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust."""

import os
import framework.utils as utils

AMAZON_COPYRIGHT_YEARS = (2018, 2019, 2020)
AMAZON_COPYRIGHT = (
    "Copyright {} Amazon.com, Inc. or its affiliates. All Rights Reserved."
)
AMAZON_LICENSE = (
    "SPDX-License-Identifier: Apache-2.0"
)
CHROMIUM_COPYRIGHT = (
    "Copyright 2017 The Chromium OS Authors. All rights reserved."
)
CHROMIUM_LICENSE = (
    "Use of this source code is governed by a BSD-style license that can be"
)
TUNTAP_COPYRIGHT = (
    "Copyright TUNTAP, 2017 The Chromium OS Authors. All rights reserved."
)
TUNTAP_LICENSE = (
    "Use of this source code is governed by a BSD-style license that can be"
)

EXCLUDED_DIRECTORIES = ((os.path.join(os.getcwd(), 'build')))


def _has_amazon_copyright(string):
    for year in AMAZON_COPYRIGHT_YEARS:
        if AMAZON_COPYRIGHT.format(year) in string:
            return True
    return False


def _validate_license(filename):
    """Validate licenses in all .rs, .py. and .sh file.

    Python and Rust files should have the licenses on the first 2 lines
    Shell files license is located on lines 3-4 to account for shebang
    """
    if filename.startswith(EXCLUDED_DIRECTORIES):
        return True
    if filename.endswith(('.rs', '.py', '.sh')):
        with open(filename) as file:
            if filename.endswith('.sh'):
                # Move iterator to third line without reading file into memory
                file.readline()
                file.readline()
            copy = file.readline()
            local_license = file.readline()
            has_amazon_copyright = (
                    _has_amazon_copyright(copy) and
                    AMAZON_LICENSE in local_license
            )
            has_chromium_copyright = (
                    CHROMIUM_COPYRIGHT in copy and
                    CHROMIUM_LICENSE in local_license
            )
            has_tuntap_copyright = (
                    TUNTAP_COPYRIGHT in copy and
                    TUNTAP_LICENSE in local_license
            )
            return (
                    has_amazon_copyright or
                    has_chromium_copyright or
                    has_tuntap_copyright
            )
    return True


def test_rust_style():
    """Fail if there's misbehaving Rust style in this repo."""
    # Check that the output is empty.
    _, stdout, _ = utils.run_cmd(
        'cargo fmt --all -- --check')

    # rustfmt prepends `"Diff in"` to the reported output.
    assert "Diff in" not in stdout


def test_ensure_mod_tests():
    """Check that files containing unit tests have a 'tests' module defined."""
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
    )

    # The outer grep returns 0 even if it finds files without the match, so we
    # ignore the return code.
    result = utils.run_cmd(cmd, no_shell=False, ignore_return_code=True)

    error_msg = (
        'Tests found in files without a "tests" module:\n {}'
        'To ensure code coverage is reported correctly, please check that '
        'your tests are in a module named "tests".'.format(result.stdout)
    )

    assert not result.stdout, error_msg


def test_for_valid_licenses():
    """Fail if a file lacks an Amazon or Chromium OS license."""
    for subdir, _, files in os.walk(os.getcwd()):
        for file in files:
            filepath = os.path.join(subdir, file)
            assert _validate_license(filepath) is True, \
                "%s has invalid license" % filepath
