# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test which checks that the secret hiding enable kernel builds successfully."""

import pytest

from framework import utils


@pytest.mark.timeout(600)
@pytest.mark.secret_hiding
def test_build_hiding_kernel():
    """
    In the test we will run our kernel build script to check it succeeds and builds the hidden kernel
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
        "cd ../resources/hiding_ci; ./build_and_install_kernel.sh --no-install --tidy"
    )
