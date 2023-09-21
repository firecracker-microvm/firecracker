# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Proofs ensuring memory safety properites, user-defined assertions,
absence of panics and some types of unexpected behavior (e.g., arithmetic overflows).
"""
import platform

import pytest

from framework import utils

PLATFORM = platform.machine()


@pytest.mark.timeout(1800)
@pytest.mark.skipif(PLATFORM != "x86_64", reason="Kani proofs run only on x86_64.")
def test_kani(results_dir):
    """
    Test all Kani proof harnesses.
    """
    # --enable-stubbing is required to enable the stubbing feature
    # --restrict-vtable is required for some virtio queue proofs, which go out of memory otherwise
    # -j enables kani harnesses to be verified in parallel (required to keep CI time low)
    # --output-format terse is required by -j
    # --enable-unstable is needed for each of the above
    rc, stdout, stderr = utils.run_cmd(
        "cargo kani --enable-unstable --enable-stubbing --restrict-vtable -j --output-format terse"
    )

    assert rc == 0, stderr

    (results_dir / "kani_log").write_text(stdout, encoding="utf-8")
