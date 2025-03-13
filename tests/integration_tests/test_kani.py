# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Proofs ensuring memory safety properties, user-defined assertions,
absence of panics and some types of unexpected behavior (e.g., arithmetic overflows).
"""
import os
import platform

import pytest

from framework import utils

PLATFORM = platform.machine()

TIMEOUT = 3600


# The `check_output` timeout will always fire before this one, but we need to
# set a timeout here to override the default pytest timeout of 180s.
@pytest.mark.timeout(TIMEOUT)
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
    # -Z restrict-vtable is required for some virtio queue proofs, which go out of memory otherwise
    # -j enables kani harnesses to be verified in parallel (required to keep CI time low)
    # --output-format terse is required by -j
    # -Z unstable-options is needed to enable the other `-Z` flags
    _, stdout, _ = utils.check_output(
        "cargo kani -Z unstable-options -Z stubbing -Z function-contracts -Z restrict-vtable -j --output-format terse",
        timeout=TIMEOUT,
    )

    (results_dir / "kani_log").write_text(stdout, encoding="utf-8")
