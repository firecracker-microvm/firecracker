"""
Tests pertaining to line/branch test coverage for the Firecracker code base.

# TODO

- Put the coverage in `s3://spec.firecracker` and update it automatically.
  target should be put in `s3://spec.firecracker` and automatically updated.
"""


import os
import re
from subprocess import run

import pytest

from host_tools.cargo_build import CARGO_BUILD_REL_PATH


CARGO_KCOV_REL_PATH = os.path.join(CARGO_BUILD_REL_PATH, "kcov")


@pytest.mark.timeout(240)
def test_coverage(test_session_root_path, testsession_tmp_path):
    """
    Test line coverage with kcov. The result is extracted from the index.json
    created by kcov after a coverag run.
    """

    COVERAGE_TARGET_PCT = 70
    # TODO: Put the coverage in s3 and update it automatically.

    COVERAGE_FILE = 'index.json'
    """ kcov will aggregate coverage data in this file. """

    COVERAGE_REGEX = r'"covered":"(\d+\.\d)"'
    """ Regex for extracting coverage data from a kcov output file. """

    exclude_pattern = (
        '${CARGO_HOME:-$HOME/.cargo/},'
        'tests/,'
        'usr/lib/gcc,'
        'lib/x86_64-linux-gnu/,'
        'pnet'
    )

    cmd = "CARGO_TARGET_DIR={} cargo kcov --all --output {} -- \
        --exclude-pattern={} --verify".format(
        os.path.join(test_session_root_path, CARGO_KCOV_REL_PATH),
        testsession_tmp_path,
        exclude_pattern
    )
    run(cmd, shell=True, check=True)
    # By default, `cargo kcov` passes `--exclude-pattern=$CARGO_HOME --verify`
    # to kcov. To pass others arguments, we need to include the defaults.
    coverage_file = os.path.join(testsession_tmp_path, COVERAGE_FILE)
    with open(coverage_file) as cov_output:
        coverage = float(re.findall(COVERAGE_REGEX, cov_output.read())[0])
    print("Coverage is: " + str(coverage))
    assert(coverage >= COVERAGE_TARGET_PCT)
