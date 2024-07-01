# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests enforcing code coverage for production code."""
import os
import warnings

import pytest

from framework import utils
from framework.properties import global_props
from host_tools import proc
from host_tools.cargo_build import cargo

PROC_MODEL = proc.proc_type()

# Toolchain target architecture.
if "Intel" in PROC_MODEL:
    VENDOR = "Intel"
    ARCH = "x86_64"
elif "AMD" in PROC_MODEL:
    VENDOR = "AMD"
    ARCH = "x86_64"
elif "ARM" in PROC_MODEL:
    VENDOR = "ARM"
    ARCH = "aarch64"
else:
    raise Exception(f"Unsupported processor model ({PROC_MODEL})")

# Toolchain target.
# Currently profiling with `aarch64-unknown-linux-musl` is unsupported (see
# https://github.com/rust-lang/rustup/issues/3095#issuecomment-1280705619) therefore we profile and
# run coverage with the `gnu` toolchains and run unit tests with the `musl` toolchains.
TARGET = f"{ARCH}-unknown-linux-gnu"


@pytest.mark.timeout(600)
def test_coverage(monkeypatch):
    """Test code coverage"""
    # Re-direct to repository root.
    monkeypatch.chdir("..")

    # Generate test profiles.
    cargo(
        "test",
        f"--all --target {TARGET}",
        "--test-threads=1",
        env={
            "RUSTFLAGS": "-Cinstrument-coverage",
            "LLVM_PROFILE_FILE": "coverage-%p-%m.profraw",
        },
    )

    lcov_file = "./build/cargo_target/coverage.lcov"

    # Generate coverage report.
    cmd = f"""
        grcov . \
            -s . \
            --binary-path ./build/cargo_target/{TARGET}/debug/ \
            --excl-start "mod tests" \
            --ignore "build/*" \
            --ignore "**/tests/*" \
            --ignore "**/test_utils*" \
            --ignore "**/mock_*" \
            --ignore "src/firecracker/examples/*" \
            -t lcov \
            --ignore-not-existing \
            -o {lcov_file}"""

    # Ignore code not relevant for the intended platform
    # - CPUID and CPU template
    # - Static CPU templates intended for specific CPU vendors
    if "AMD" == VENDOR:
        cmd += " \
            --ignore **/intel* \
            --ignore *t2* \
            --ignore *t2s* \
            --ignore *t2cl* \
            --ignore *c3* \
            "
    elif "Intel" == VENDOR:
        cmd += " \
            --ignore **/amd* \
            --ignore *t2a* \
            "

    utils.check_output(cmd)

    # Only upload if token is present and we're in EC2
    if "CODECOV_TOKEN" in os.environ and global_props.is_ec2:
        pr_number = os.environ.get("BUILDKITE_PULL_REQUEST")
        branch = os.environ.get("BUILDKITE_BRANCH")

        if not branch:
            branch = utils.check_output("git rev-parse --abbrev-ref HEAD").stdout

        codecov_cmd = f"codecov -f {lcov_file} -F {global_props.host_linux_version}-{global_props.instance}"

        if pr_number and pr_number != "false":
            codecov_cmd += f" -P {pr_number}"
        else:
            codecov_cmd += f" -B {branch}"

        utils.check_output(codecov_cmd)
    else:
        warnings.warn(
            "Not uploading coverage report due to missing CODECOV_TOKEN environment variable"
        )
