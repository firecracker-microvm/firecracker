from subprocess import run

import pytest


@pytest.mark.timeout(240)
def test_unittests():
    # If cargo test will raise errors, pytest will handle them.
    run(
       'RUST_BACKTRACE=1 cargo test --all --quiet --no-fail-fast',
       shell=True,
       check=True
    )
