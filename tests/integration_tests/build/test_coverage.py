# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests pertaining to line/branch test coverage for the Firecracker code base.

# TODO

- Put the coverage in `s3://spec.firecracker` and update it automatically.
  target should be put in `s3://spec.firecracker` and automatically updated.
"""


import os
import platform
import re
import pytest

import framework.utils as utils
import host_tools.cargo_build as host  # pylint: disable=import-error

COVERAGE_TARGET_PCT = 84.47
COVERAGE_MAX_DELTA = 0.05

CARGO_KCOV_REL_PATH = os.path.join(host.CARGO_BUILD_REL_PATH, 'kcov')

KCOV_COVERAGE_FILE = 'index.js'
"""kcov will aggregate coverage data in this file."""

KCOV_COVERED_LINES_REGEX = r'"covered_lines":"(\d+)"'
"""Regex for extracting number of total covered lines found by kcov."""

KCOV_TOTAL_LINES_REGEX = r'"total_lines" : "(\d+)"'
"""Regex for extracting number of total executable lines found by kcov."""


@pytest.mark.timeout(400)
@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="kcov hangs on aarch64"
)
def test_coverage(test_session_root_path, test_session_tmp_path):
    """Test line coverage with kcov.

    The result is extracted from the $KCOV_COVERAGE_FILE file created by kcov
    after a coverage run.
    """
    exclude_pattern = (
        '${CARGO_HOME:-$HOME/.cargo/},'
        'build/,'
        'tests/,'
        'usr/lib/gcc,'
        'lib/x86_64-linux-gnu/,'
        # The following files/directories are auto-generated
        'bootparam.rs,'
        'elf.rs,'
        'mpspec.rs,'
        'msr_index.rs,'
        '_gen'
    )
    exclude_region = '\'mod tests {\''

    cmd = (
        'CARGO_TARGET_DIR={} cargo kcov --all '
        '--output {} -- '
        '--exclude-pattern={} '
        '--exclude-region={} --verify'
    ).format(
        os.path.join(test_session_root_path, CARGO_KCOV_REL_PATH),
        test_session_tmp_path,
        exclude_pattern,
        exclude_region
    )
    # By default, `cargo kcov` passes `--exclude-pattern=$CARGO_HOME --verify`
    # to kcov. To pass others arguments, we need to include the defaults.
    utils.run_cmd(cmd)

    coverage_file = os.path.join(test_session_tmp_path, KCOV_COVERAGE_FILE)
    with open(coverage_file) as cov_output:
        contents = cov_output.read()
        covered_lines = int(re.findall(KCOV_COVERED_LINES_REGEX, contents)[0])
        total_lines = int(re.findall(KCOV_TOTAL_LINES_REGEX, contents)[0])
        coverage = covered_lines / total_lines * 100
    print("Number of executable lines: {}".format(total_lines))
    print("Number of covered lines: {}".format(covered_lines))
    print("Thus, coverage is: {:.2f}%".format(coverage))

    coverage_low_msg = (
        'Current code coverage ({:.2f}%) is below the target ({}%).'
        .format(coverage, COVERAGE_TARGET_PCT)
    )

    min_coverage = COVERAGE_TARGET_PCT - COVERAGE_MAX_DELTA
    assert coverage >= min_coverage, coverage_low_msg

    # Get the name of the variable that needs updating.
    namespace = globals()
    cov_target_name = [name for name in namespace if namespace[name]
                       is COVERAGE_TARGET_PCT][0]

    coverage_high_msg = (
        'Current code coverage ({:.2f}%) is above the target ({}%).\n'
        'Please update the value of {}.'
        .format(coverage, COVERAGE_TARGET_PCT, cov_target_name)
    )

    assert coverage - COVERAGE_TARGET_PCT <= COVERAGE_MAX_DELTA,\
        coverage_high_msg
