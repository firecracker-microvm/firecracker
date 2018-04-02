from subprocess import run

import pytest


@pytest.mark.timeout(240)
def test_unittests():
    # If cargo test will raise errors, pytest will handle them.
    # TODO: This requires acatans@ patch to not error out due to concurrent
    # resources creation.
    run(
       'RUST_BACKTRACE=1 cargo test --all --quiet --no-fail-fast',
       shell=True,
       check=True
    )
