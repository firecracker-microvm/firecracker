# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring security vulnerabilities are not present in dependencies."""
import json

import pytest

from framework.ab_test import (
    git_ab_test_host_command_if_pr,
    set_did_not_grow_comparator,
)
from framework.utils import CommandReturn
from framework.utils_cpuid import CpuVendor, get_cpu_vendor


@pytest.mark.skipif(
    get_cpu_vendor() != CpuVendor.INTEL,
    reason="The audit is based on cargo.lock which is identical on all platforms",
)
def test_cargo_audit():
    """
    Run cargo audit to check for crates with security vulnerabilities.
    """

    def set_of_vulnerabilities(output: CommandReturn):
        output = json.loads(output.stdout)

        return set(
            frozenset(vulnerability)
            for vulnerability in output["vulnerabilities"]["list"]
        ).union(
            frozenset(warning)
            for warning_kind, warnings in output["warnings"].items()
            for warning in warnings
        )

    git_ab_test_host_command_if_pr(
        "cargo audit --deny warnings -q --json",
        comparator=set_did_not_grow_comparator(set_of_vulnerabilities),
    )
