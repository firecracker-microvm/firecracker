import re
from subprocess import run

import pytest


COVERAGE_TARGET_PCT = 90
COVERAGE_REGEX = '"covered":"(\d+\.\d)"'
SUCCESS_CODE = 0

def fail_without_kcov():
    # Raises if there's no kcov, and pytest will handle that.
    run('command -v kcov', shell=True, check=True)

def install_cargo_kcov_if_needed():
    # cargo kcov may not be available yet.
    # grep will return exitcode 1 if it is not in the component list.
    cargo_kcov_check = run(
        'cargo install --list | grep cargo-kcov',
        shell=True
    )

    if not cargo_kcov_check.returncode == SUCCESS_CODE:
        # Rust kcov usage is done via cargo-kcov. For more information see
        # github.com/kennytm/cargo-kcov
        # For OS-specific dependenceis see
        # github.com/SimonKagstrom/kcov/blob/master/INSTALL.md
        run('cargo install cargo-kcov', shell=True, check=True)
        run('cargo kcov --print-install-kcov-sh | sh', shell=True, check=True)

@pytest.mark.timeout(240)
def test_coverage():
    fail_without_kcov()
    install_cargo_kcov_if_needed()

    # Run kcov. pytest will handle any errors.
    # TODO: Currently fails intermittently at
    # github.com/SimonKagstrom/kcov/blob/master/src/engines/ptrace.cc#L145
    run('cargo kcov --all --output cov', shell=True, check=True)

    # Get the kcov coverage.
    with open('cov/index.json') as cov_output:
        coverage = float(re.findall(COVERAGE_REGEX, cov_output.read())[0])

    # Assert on the coverage target.
    assert coverage >= COVERAGE_TARGET_PCT
