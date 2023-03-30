# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests enforcing code coverage for production code."""

import pytest
from framework import utils
from host_tools import proc

# We have different coverages based on the host kernel version. This is
# caused by io_uring, which is only supported by FC for kernels newer
# than 5.10.

# AMD has a slightly different coverage due to
# the appearance of the brand string. On Intel,
# this contains the frequency while on AMD it does not.
# Checkout the cpuid crate. In the future other
# differences may appear.
if utils.is_io_uring_supported():
    COVERAGE_DICT = {"Intel": 83.11, "AMD": 81.52, "ARM": 82.49}
else:
    COVERAGE_DICT = {"Intel": 80.24, "AMD": 78.68, "ARM": 79.45}

PROC_MODEL = proc.proc_type()

# Toolchain target architecture.
if ("Intel" in PROC_MODEL) or ("AMD" in PROC_MODEL):
    ARCH = "x86_64"
elif "ARM" in PROC_MODEL:
    ARCH = "aarch64"
else:
    raise Exception(f"Unsupported processor model ({PROC_MODEL})")

# Toolchain target.
# Currently profiling with `aarch64-unknown-linux-musl` is unsupported (see
# https://github.com/rust-lang/rustup/issues/3095#issuecomment-1280705619) therefore we profile and
# run coverage with the `gnu` toolchains and run unit tests with the `musl` toolchains.
TARGET = f"{ARCH}-unknown-linux-gnu"

# We allow coverage to have a max difference of `COVERAGE_MAX_DELTA` as percentage before failing
# the test (currently 0.05%).
COVERAGE_MAX_DELTA = 0.0005


@pytest.mark.timeout(400)
def test_coverage(monkeypatch, record_property):
    """Test code coverage

    @type: build
    """
    # Get coverage target.
    processor_model = [item for item in COVERAGE_DICT if item in PROC_MODEL]
    assert len(processor_model) == 1, "Could not get processor model!"
    coverage_target = COVERAGE_DICT[processor_model[0]]

    # Re-direct to repository root.
    monkeypatch.chdir("..")

    # Generate test profiles.
    utils.run_cmd(
        f'\
        RUSTFLAGS="-Cinstrument-coverage" \
        LLVM_PROFILE_FILE="coverage-%p-%m.profraw" \
        cargo test --all --target={TARGET} -- --test-threads=1 \
    '
    )

    # Generate coverage report.
    utils.run_cmd(
        f"""
        grcov . \
            -s . \
            --binary-path ./build/cargo_target/{TARGET}/debug/ \
            --excl-start "mod tests" \
            --ignore "build/*" \
            --ignore "**/tests/*" \
            --ignore "**/test_utils*" \
            -t html \
            --ignore-not-existing \
            -o ./build/cargo_target/{TARGET}/debug/coverage"""
    )

    # Extract coverage from html report.
    #
    # The line looks like `<abbr title="44724 / 49237">90.83 %</abbr></p>` and is the first
    # occurrence of the `<abbr>` element in the file.
    #
    # When we update grcov to 0.8.* we can update this to pull the coverage from a generated .json
    # file.
    index = open(
        f"./build/cargo_target/{TARGET}/debug/coverage/index.html", encoding="utf-8"
    )
    index_contents = index.read()
    end = index_contents.find(" %</abbr></p>")
    start = index_contents[:end].rfind(">")
    coverage_str = index_contents[start + 1 : end]
    coverage = float(coverage_str)

    # Compare coverage.
    high = coverage_target * (1.0 + COVERAGE_MAX_DELTA)
    low = coverage_target * (1.0 - COVERAGE_MAX_DELTA)

    # Record coverage.
    record_property(
        "coverage", f"{coverage}% {coverage_target}% ±{COVERAGE_MAX_DELTA:.2%}%"
    )

    # Assert coverage within delta.
    assert (
        coverage >= low
    ), f"Current code coverage ({coverage:.2f}%) is more than {COVERAGE_MAX_DELTA:.2%}% below the target ({coverage_target:.2f}%)"
    assert (
        coverage <= high
    ), f"Current code coverage ({coverage:.2f}%) is more than {COVERAGE_MAX_DELTA:.2%}% above the target ({coverage_target:.2f}%)"
