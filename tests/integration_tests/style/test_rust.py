# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust."""
from collections import defaultdict

from framework import utils
from host_tools.fcmetrics import extract_fields, find_metrics_files, is_metric_used


def test_rust_order():
    """Tests that `Cargo.toml` dependencies are alphabetically ordered."""

    # Runs `cargo-sort` with the current working directory (`cwd`) as the repository root.
    _, _, _ = utils.check_output(
        cmd="cargo-sort --workspace --check --grouped", cwd=".."
    )


def test_rust_style():
    """Test that rust code passes style checks."""
    # Check that the output is empty.
    _, stdout, _ = utils.check_output("cargo fmt --all -- --check")

    # rustfmt prepends `"Diff in"` to the reported output.
    assert "Diff in" not in stdout


def test_unused_metrics():
    """Tests that all metrics defined in Firecracker's metrics.rs files actually have code
    paths that increment them."""
    metrics_files = find_metrics_files()
    unused = defaultdict(list)

    assert metrics_files

    for file_path in metrics_files:
        fields = extract_fields(file_path)
        if not fields:
            continue

        for field, ty in fields:
            if not is_metric_used(field, ty):
                unused[file_path].append((field, ty))

    # Grouped output
    for file_path, fields in unused.items():
        print(f"📄 Defined in: {file_path}")
        print("Possibly Unused: \n")
        for field, field_type in fields:
            print(f"   ❌ {field} ({field_type})")

        print()

    assert (
        not unused
    ), "Unused metrics founds, see stdout. Please either hook them up, or remove them"
