# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run Rust integration tests under sanitizers."""

import platform

import pytest

from framework import defs
from host_tools.cargo_build import cargo, get_rustflags

TARGET = f"{platform.machine()}-unknown-linux-gnu"
SANITIZERS = ("address",)
REPO_ROOT = defs.FC_WORKSPACE_DIR
VMM_TEST_TARGETS = sorted((REPO_ROOT / "src" / "vmm" / "tests").glob("*.rs"))


@pytest.mark.nonci
@pytest.mark.timeout(3600)
@pytest.mark.parametrize("sanitizer", SANITIZERS)
def test_rust_integration_tests_under_sanitizer(sanitizer):
    """Run vmm Rust integration tests under the specified sanitizer."""
    cargo_args = " ".join(
        [
            f"--target {TARGET}",
            "-p vmm",
            *(f"--test {path.stem}" for path in VMM_TEST_TARGETS),
        ]
    )
    target_dir = defs.LOCAL_BUILD_PATH / "cargo_target" / "sanitizers" / sanitizer
    rustflags = get_rustflags() + f"-Zsanitizer={sanitizer}"
    cargo(
        "test",
        cargo_args,
        "--test-threads=1",
        nightly=True,
        cwd=str(REPO_ROOT),
        env={
            "CARGO_TARGET_DIR": str(target_dir),
            "RUSTFLAGS": rustflags,
        },
    )
