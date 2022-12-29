# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring security vulnerabilities are not present in dependencies."""


import pytest

from framework.utils_cpuid import CpuVendor, get_cpu_vendor
from framework import utils
from framework import defs


@pytest.mark.skipif(
    get_cpu_vendor() != CpuVendor.INTEL,
    reason="The audit is based on cargo.lock which " "is identical on all platforms",
)
def test_cargo_audit():
    """
    Run cargo audit to check for crates with security vulnerabilities.

    @type: security
    """
    # Run command and raise exception if non-zero return code
    utils.run_cmd(
        "cargo audit --deny warnings -q  --ignore RUSTSEC-2021-0145",
        cwd=defs.FC_WORKSPACE_DIR,
    )
