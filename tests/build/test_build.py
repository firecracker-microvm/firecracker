""" Tests if both the debug and the release builds pass. """

import os

import pytest

from host_tools.cargo_build import cargo_build, CARGO_BUILD_REL_PATH,\
    CARGO_RELEASE_REL_PATH

CARGO_DEBUG_REL_PATH = os.path.join(CARGO_BUILD_REL_PATH, "debug")


@pytest.mark.timeout(240)
def test_build_debug(test_session_root_path):
    build_path = os.path.join(
        test_session_root_path,
        CARGO_DEBUG_REL_PATH
    )
    cargo_build(build_path)


def test_build_release(test_session_root_path):
    build_path = os.path.join(
        test_session_root_path,
        CARGO_RELEASE_REL_PATH
    )
    cargo_build(build_path, '--release')
