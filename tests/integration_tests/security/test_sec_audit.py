# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring security vulnerabilities are not present in dependencies."""

import json

import pytest

from framework import utils
from framework.ab_test import (
    git_ab_test_host_command_if_pr,
    set_did_not_grow_comparator,
)
from framework.defs import FC_WORKSPACE_DIR
from framework.utils_cpuid import CpuVendor, get_cpu_vendor


@pytest.mark.skipif(
    get_cpu_vendor() != CpuVendor.INTEL,
    reason="The audit is based on cargo.lock which is identical on all platforms",
)
def test_cargo_audit():
    """
    Run cargo audit to check for crates with security vulnerabilities.
    """

    def set_of_vulnerabilities(output: utils.CommandReturn):
        # The `stdout` will contain one `json` payload per line
        findings = set()
        for line in output.stderr.splitlines():
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            # There is also `summary` type, which is of not interest for us
            if entry["type"] != "diagnostic":
                continue
            fields = entry["fields"]
            advisory = fields.get("advisory") or {}
            # Identify a finding by its code, advisory id and affected crate;
            # Findings without an advisory (e.g. yanked crates) fall back to
            # the crate from the dependency graph.
            krate = (fields.get("graphs") or [{}])[0].get("Krate", {})
            findings.add(
                (
                    fields.get("code"),
                    advisory.get("id"),
                    advisory.get("package") or krate.get("name"),
                )
            )
        return findings

    utils.run_cmd("cargo install --locked cargo-deny --debug")
    toml_file = FC_WORKSPACE_DIR / "Cargo.toml"

    git_ab_test_host_command_if_pr(
        f"RUSTUP_LOG=warn cargo deny --manifest-path {toml_file} -f json check advisories",
        comparator=set_did_not_grow_comparator(set_of_vulnerabilities),
    )
