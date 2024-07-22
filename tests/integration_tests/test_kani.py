# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Proofs ensuring memory safety properites, user-defined assertions,
absence of panics and some types of unexpected behavior (e.g., arithmetic overflows).
"""
import os
import platform

import pytest

from framework import utils

PLATFORM = platform.machine()


@pytest.mark.timeout(1800)
@pytest.mark.skipif(PLATFORM != "x86_64", reason="Kani proofs run only on x86_64.")
@pytest.mark.skipif(
    os.environ.get("BUILDKITE") != "true",
    reason="Kani's memory requirements likely cannot be satisfied locally",
)
def test_kani(results_dir):
    """
    Test all Kani proof harnesses.
    """
    # -Z stubbing is required to enable the stubbing feature
    # -Z function-contracts is required to enable the function contracts feature
    # --restrict-vtable is required for some virtio queue proofs, which go out of memory otherwise
    # -j enables kani harnesses to be verified in parallel (required to keep CI time low)
    # --output-format terse is required by -j
    # --enable-unstable is needed to enable `-Z` flags
    _, stdout, _ = utils.check_output(
        "cargo kani --enable-unstable -Z stubbing -Z function-contracts --restrict-vtable -j --output-format terse"
    )

    (results_dir / "kani_log").write_text(stdout, encoding="utf-8")
