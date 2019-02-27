# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that check if building the documentation works."""

import os


from subprocess import run

import host_tools.cargo_build as host  # pylint: disable=import-error

CARGO_DOC_REL_PATH = os.path.join(host.CARGO_BUILD_REL_PATH, 'doc')


def test_doc(test_session_root_path):
    """Test successful documentation build."""
    cmd = (
        'cargo doc --target-dir {}'
    ).format(
        os.path.join(test_session_root_path, CARGO_DOC_REL_PATH)
    )
    run(cmd, shell=True, check=True)
