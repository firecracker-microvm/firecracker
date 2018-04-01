from subprocess import run

import pytest


COVERAGE_TARGET = 0.9
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
        # Rust kcov usage is done via cargo-kcov.
        # See https://github.com/kennytm/cargo-kcov for information.
        run('cargo install cargo-kcov', shell=True, check=True)

@pytest.mark.timeout(240)
def test_coverage():
    fail_without_kcov()
    install_cargo_kcov_if_needed()

    # Run kcov. pytest will handle any errors.
    # TODO: Currently fails in myseterious ways.
    run('cargo kcov --all', shell=True, check=True)

    # Get the kcov coverage.
    # TODO: Actually get the coverage.
    coverage = 0.9

    # Assert on the coverage target.
    assert coverage >= COVERAGE_TARGET
