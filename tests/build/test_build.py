""" Tests if both the debug and the release builds pass. """

from subprocess import run

import pytest


def build(flags=''):
    run(
        'cargo build --target=x86_64-unknown-linux-musl --quiet ' + flags +
        ' >/dev/null 2>&1',
        shell=True,
        check=True
    )


@pytest.mark.timeout(240)
def test_build_debug():
    build()


@pytest.mark.timeout(240)
def test_build_release():
    build('--release')
