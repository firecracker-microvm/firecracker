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
CRATES_WITH_PROOFS = ["dumbo", "rate_limiter"]


@pytest.mark.timeout(1800)
@pytest.mark.skipif(PLATFORM != "x86_64", reason="Kani proofs run only on x86_64.")
@pytest.mark.parametrize("crate", CRATES_WITH_PROOFS)
def test_kani(results_dir, crate):
    """
    Test all Kani proof harnesses.
    """
    rc, stdout, stderr = utils.run_cmd(
        f"cargo kani -p {crate} --enable-unstable --enable-stubbing"
    )

    assert rc == 0, stderr

    (results_dir / f"kani_log_{crate}").write_text(stdout, encoding="utf-8")
