"""
Tests pertaining to line/branch test coverage for the Firecracker code base.

# TODO

- Put the coverage in `s3://spec.firecracker` and update it automatically.
  target should be put in `s3://spec.firecracker` and automatically updated.
- Remove the taskset workaround once the kcov fix is picked up by cargo-kcov.
"""


import re
from subprocess import run

import pytest


@pytest.mark.timeout(240)
def test_coverage(testsession_tmp_path):
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
    run(
        'taskset --cpu-list 0-63 '
        'cargo kcov --all --target=x86_64-unknown-linux-musl '
        '    --output ' + testsession_tmp_path +
        '    -- --exclude-pattern=' + exclude_pattern + ' --verify ',
        # '>/dev/null 2>&1',
        # HACK: we need a consistent way to control test output.
        shell=True,
        check=True
    )
    # By default, `cargo kcov` passes `--exclude-pattern=$CARGO_HOME --verify`
    # to kcov. To pass others arguments, we need to include the defaults.
    #
    # TODO: remove the taskset once kcov is fixed.

    with open(testsession_tmp_path + COVERAGE_FILE) as cov_output:
        coverage = float(re.findall(COVERAGE_REGEX, cov_output.read())[0])
    print("Coverage is: " + str(coverage))
    assert coverage >= COVERAGE_TARGET_PCT
