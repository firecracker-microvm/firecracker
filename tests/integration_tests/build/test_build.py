"""Tests that check if both the debug and the release builds pass."""

import os

import pytest

import host_tools.cargo_build as host  # pylint:disable=import-error


CARGO_DEBUG_REL_PATH = os.path.join(host.CARGO_BUILD_REL_PATH, 'debug')


@pytest.mark.timeout(240)
def test_build_debug(test_session_root_path):
    """Test if a debug-mode build works."""
    build_path = os.path.join(
        test_session_root_path,
        CARGO_DEBUG_REL_PATH
    )
    host.cargo_build(build_path)


def test_build_release(test_session_root_path):
    """Test if a release-mode build works."""
    build_path = os.path.join(
        test_session_root_path,
        host.CARGO_RELEASE_REL_PATH
    )
    host.cargo_build(build_path, '--release')
