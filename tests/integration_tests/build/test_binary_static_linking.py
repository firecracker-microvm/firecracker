# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests to check if the release binary is statically linked.

"""

import pytest

from framework import utils


@pytest.mark.timeout(500)
def test_firecracker_binary_static_linking(microvm_factory):
    """
    Test to make sure the firecracker binary is statically linked.
    """
    fc_binary_path = microvm_factory.fc_binary_path
    _, stdout, stderr = utils.check_output(f"file {fc_binary_path}")
    assert "" in stderr
    # expected "statically linked" for aarch64 and
    # "static-pie linked" for x86_64
    assert "statically linked" in stdout or "static-pie linked" in stdout
