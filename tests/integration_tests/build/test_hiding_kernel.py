# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test which checks that the secret hiding kernel variants build successfully."""

from pathlib import Path

import pytest

from framework import utils

# Tests run with `tests/` as the working directory, so the hiding CI assets live
# one level up under `resources/`.
HIDING_CI_DIR = Path("../resources/hiding_ci")
KERNELS_DIR = HIDING_CI_DIR / "kernels"


def _discover_variants():
    """Discover the kernel variants available under hiding_ci/kernels."""
    if not KERNELS_DIR.is_dir():
        return []
    return sorted(p.name for p in KERNELS_DIR.iterdir() if p.is_dir())


@pytest.mark.timeout(600)
@pytest.mark.secret_hiding
@pytest.mark.parametrize("variant", _discover_variants())
def test_build_hiding_kernel(variant):
    """
    In the test we will run our kernel build script for each secret hiding
    variant to check it succeeds and builds the hidden kernel
    """

    # We have some extra deps for building the kernel that are not in the dev container
    utils.check_output("apt update")
    utils.check_output(
        "apt install -y build-essential libncurses-dev bison flex libssl-dev libelf-dev bc dwarves libncurses5-dev kmod fakeroot"
    )

    # We have to configure git otherwise patch application fails
    # the git log still credits the original author
    utils.check_output('git config --global user.name "Firecracker CI"')
    utils.check_output('git config --global user.email "ci@email.com"')

    utils.check_output(
        f"cd {HIDING_CI_DIR}; ./build_and_install_kernel.sh {variant} --no-install --tidy"
    )
