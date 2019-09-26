# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring security vulnerabilities are not present in dependencies."""

from subprocess import run, PIPE

import os
import platform

import pytest


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="The audit is based on cargo.lock which "
           "is identical on all platforms"
)
def test_cargo_audit():
    """Fail if there are crates with security vulnerabilities."""
    cargo_lock_path = os.path.normpath(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            '../../../Cargo.lock')
    )
    process = run(
        'cargo audit -q -f {}'.format(cargo_lock_path),
        shell=True,
        check=True,
        stdout=PIPE
    )
    assert process.returncode == 0
