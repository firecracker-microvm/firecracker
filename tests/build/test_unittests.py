""" Runs unit tests at integration time. """

from subprocess import run

import pytest


@pytest.mark.timeout(240)
def test_unittests():
    """ Runs all unit tests from all Rust crates in the repo. """
    run(
       'RUST_BACKTRACE=1 cargo test --all --quiet --no-fail-fast',
       # '    >/dev/null 2>&1',
       # HACK: we need a consistent way to control test output.
       shell=True,
       check=True
    )
