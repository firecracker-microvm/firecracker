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
CRATES_WITH_PROOFS = ["dumbo", "vmm"]


@pytest.mark.timeout(1800)
@pytest.mark.skipif(PLATFORM != "x86_64", reason="Kani proofs run only on x86_64.")
@pytest.mark.parametrize("crate", CRATES_WITH_PROOFS)
def test_kani(results_dir, crate):
    """
    Test all Kani proof harnesses.
    """
    # --enable-stubbing is required to enable the stubbing feature
    # --restrict-vtable is required for some virtio queue proofs, which go out of memory otherwise
    # -j enables kani harnesses to be verified in parallel (required to keep CI time low)
    # --output-format terse is required by -j
    # --enable-unstable is needed for each of the above
    rc, stdout, stderr = utils.run_cmd(
        f"cargo kani -p {crate} --enable-unstable --enable-stubbing --restrict-vtable -j --output-format terse"
    )

    assert rc == 0, stderr

    (results_dir / f"kani_log_{crate}").write_text(stdout, encoding="utf-8")
