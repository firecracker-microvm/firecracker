from subprocess import run

import pytest


def build(flags):
    # if run will raise errors, pytest will handle them.
    run('cargo build --quiet ' + flags, shell=True, check=True)


@pytest.mark.timeout(240)
def test_build_debug():
    build('')


@pytest.mark.timeout(240)
def test_build_release():
    build('--release')
