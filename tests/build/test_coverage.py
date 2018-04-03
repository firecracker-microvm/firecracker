import re
import shutil
from subprocess import run

import pytest


COVERAGE_TARGET_PCT = 90
COVERAGE_REGEX = r'"covered":"(\d+\.\d)"'
COVERAGE_RESULTS_DIR = 'build/test_coverage_output'
SUCCESS_CODE = 0


def install_cargo_kcov_if_needed():
    # TODO: Move this to a fixture.
    # cargo kcov may not be available yet.
    # grep will return exitcode 1 if it is not in the component list.
    cargo_kcov_check = run(
        'cargo install --list | grep cargo-kcov',
        shell=True
    )

    if not cargo_kcov_check.returncode == SUCCESS_CODE:
        # Rust kcov usage is done via cargo-kcov. For more information see
        # github.com/kennytm/cargo-kcov
        # For OS-specific dependencies see
        # github.com/SimonKagstrom/kcov/blob/master/INSTALL.md
        run('cargo install cargo-kcov', shell=True, check=True)
        run('cargo kcov --print-install-kcov-sh | sh', shell=True, check=True)
        run('rm -rf kcov-* v*.tar.gz', shell=True, check=True)


@pytest.mark.timeout(240)
def test_coverage():
    install_cargo_kcov_if_needed()

    # Run kcov. pytest will handle any errors.
    run(
        'cargo kcov --all --output ' + COVERAGE_RESULTS_DIR,
        shell=True,
        check=True
    )

    # Get the kcov coverage.
    with open(COVERAGE_RESULTS_DIR + '/index.json') as cov_output:
        coverage = float(re.findall(COVERAGE_REGEX, cov_output.read())[0])

    # Clean up
    # TODO: Move the cleanup to a test fixture we don't deal with cleanup here
    shutil.rmtree(COVERAGE_RESULTS_DIR)

    # Assert on the coverage target.
    assert coverage >= COVERAGE_TARGET_PCT
