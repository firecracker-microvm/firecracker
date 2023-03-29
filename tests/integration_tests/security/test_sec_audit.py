# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring security vulnerabilities are not present in dependencies."""


import pytest

from framework import defs
from framework.utils_cpuid import CpuVendor, get_cpu_vendor
from host_tools.cargo_build import cargo


@pytest.mark.skipif(
    get_cpu_vendor() != CpuVendor.INTEL,
    reason="The audit is based on cargo.lock which " "is identical on all platforms",
)
def test_cargo_audit():
    """
    Run cargo audit to check for crates with security vulnerabilities.
    """
    # Run command and raise exception if non-zero return code
    cargo(
        "audit",
        "--deny warnings -q",
        cwd=defs.FC_WORKSPACE_DIR,
    )
