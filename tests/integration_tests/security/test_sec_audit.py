# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring security vulnerabilities are not present in dependencies."""


import platform
import pytest

import framework.utils as utils
import framework.defs as defs


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="The audit is based on cargo.lock which "
           "is identical on all platforms"
)
def test_cargo_audit():
    """
    Run cargo audit to check for crates with security vulnerabilities.

    @type: security
    """
    # Run command and raise exception if non-zero return code
    utils.run_cmd(
        'cargo audit --deny warnings -q', cwd=defs.FC_WORKSPACE_DIR)
