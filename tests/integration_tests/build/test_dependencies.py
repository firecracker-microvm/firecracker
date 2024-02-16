# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Enforces controls over dependencies."""

import os

import pytest

from host_tools import proc
from host_tools.cargo_build import cargo

pytestmark = pytest.mark.skipif(
    "Intel" not in proc.proc_type(), reason="test only runs on Intel"
)


def test_licenses():
    """Ensure license compatibility for Firecracker.

    For a list of currently allowed licenses checkout deny.toml in
    the root directory.
    """
    toml_file = os.path.normpath(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../Cargo.toml")
    )

    _, stdout, stderr = cargo(
        "deny", f"--manifest-path {toml_file} check licenses bans"
    )
    assert "licenses ok" in stdout

    # "cargo deny" should deny licenses by default but for some reason copyleft is allowed
    # by it and if we add a dependency which has copyleft licenses "cargo deny" won't report
    # it unless it is explicitly told to do so from the deny.toml.
    # Our current deny.toml seems to cover all the cases we need but,
    # if there is an exception like copyleft (where we don't want and don't deny
    # in deny.toml and is allowed by cardo deny), we don't want to be left in the dark.
    # For such cases check "cargo deny" output, make sure that there are no warnings reported
    # related to the license and take appropriate actions i.e. either add them to allow list
    # or remove them if they are incompatible with our licenses.
    license_res = [line for line in stderr.split("\n") if "license" in line]
    assert not license_res
