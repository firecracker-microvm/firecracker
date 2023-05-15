# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests enforcing code coverage for production code."""

import pytest

import framework.utils_cpuid as cpuid_utils
from framework import utils
from host_tools import proc
from host_tools.cargo_build import cargo

# We have different coverages based on the host kernel version. This is
# caused by io_uring, which is only supported by FC for kernels newer
# than 5.10.


def is_on_skylake():
    """Test is executed on a Skylake host."""
    return "8175M CPU" in cpuid_utils.get_cpu_model_name()


# AMD has a slightly different coverage due to
# the appearance of the brand string. On Intel,
# this contains the frequency while on AMD it does not.
# Checkout the cpuid crate. In the future other
# differences may appear.
if utils.is_io_uring_supported():
    COVERAGE_DICT = {"Intel": 83.59, "AMD": 83.18, "ARM": 83.04}
else:
    COVERAGE_DICT = {"Intel": 80.85, "AMD": 80.39, "ARM": 80.05}

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

# We allow coverage to have a max difference of `COVERAGE_MAX_DELTA` as percentage before failing
# the test (currently 0.05%).
COVERAGE_MAX_DELTA = 0.05


@pytest.mark.timeout(600)
def test_coverage(monkeypatch, record_property, metrics):
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
    cargo(
        "test",
        f"--all --target {TARGET}",
        "--test-threads=1",
        env={
            "RUSTFLAGS": "-Cinstrument-coverage",
            "LLVM_PROFILE_FILE": "coverage-%p-%m.profraw",
        },
    )

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
            -t html \
            --ignore-not-existing \
            -o ./build/cargo_target/{TARGET}/debug/coverage"""

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

    utils.run_cmd(cmd)

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

    # Record coverage.
    record_property(
        "coverage", f"{coverage}% {coverage_target}% ±{COVERAGE_MAX_DELTA:.2f}%"
    )
    metrics.set_dimensions({"cpu_arch": ARCH})
    metrics.put_metric("code_coverage", coverage, unit="Percent")

    assert coverage == pytest.approx(
        coverage_target, abs=COVERAGE_MAX_DELTA
    ), f"Current code coverage ({coverage:.2f}%) deviates more than {COVERAGE_MAX_DELTA:.2f}% from target ({coverage_target:.2f})"
