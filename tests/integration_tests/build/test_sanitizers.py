# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run Rust integration tests under sanitizers."""

import platform
from uuid import uuid4

import pytest

from framework import defs
from host_tools.cargo_build import cargo

TARGET = f"{platform.machine()}-unknown-linux-gnu"
SANITIZERS = ("address",)
REPO_ROOT = defs.FC_WORKSPACE_DIR


@pytest.mark.nonci
@pytest.mark.timeout(3600)
@pytest.mark.parametrize("sanitizer", SANITIZERS)
def test_rust_integration_tests_under_sanitizer(sanitizer):
    """Run vmm Rust integration tests under the specified sanitizer."""
    target_flag_var = f"CARGO_TARGET_{TARGET.upper().replace('-', '_')}_RUSTFLAGS"
    target_dir = (
        defs.LOCAL_BUILD_PATH
        / "cargo_target"
        / "sanitizers"
        / (f"{sanitizer}-{uuid4().hex}")
    )
    cargo(
        "test",
        f"--target {TARGET} -p vmm --test integration_tests",
        "--test-threads=1",
        nightly=True,
        cwd=str(REPO_ROOT),
        env={
            "CARGO_TARGET_DIR": str(target_dir),
            target_flag_var: f"-Zsanitizer={sanitizer}",
        },
    )
