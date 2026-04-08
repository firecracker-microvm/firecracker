# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for VFIO passthrough API."""

import re
from pathlib import Path

import pytest


def test_api_vfio(uvm):
    """
    Test VFIO passthrough API commands.
    """

    vm = uvm
    vm.spawn()
    vm.basic_config()

    # Missing required field 'sbdf'
    expected_msg = re.escape("missing field `sbdf`")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.vfio.put(id="dev0")

    # Valid VFIO device configs and overwrites
    vm.api.vfio.put(id="nvme0", sbdf="0000:01:02.03")
    vm.api.vfio.put(id="nvme0", sbdf="01:02.03")

    # Adding a second device should be OK
    vm.api.vfio.put(id="nvme1", sbdf="0000:01:02.04")

    # Empty id should fail
    expected_msg = re.escape("The ID cannot be empty.")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.vfio.put(id="", sbdf="0000:01:02.05")
