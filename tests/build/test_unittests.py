"""
Runs unit tests at integration time.

# TODO

- Run with `--release` once  `https://github.com/edef1c/libfringe/issues/75`
  is fixed
"""

from subprocess import run

import pytest


@pytest.mark.timeout(240)
def test_unittests():
    """ Runs all unit tests from all Rust crates in the repo. """
    run(
       'CARGO_INCREMENTAL=0 RUST_BACKTRACE=1 cargo test --all --no-fail-fast',
       shell=True,
       check=True
    )

    run(
        'cargo clean',
        shell=True,
        check=True
    )
