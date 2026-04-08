# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for VFIO passthrough API."""

import re
from pathlib import Path

import pytest


def create_vfio_path(vm, path):
    """Create a minimal sysfs entry for the VFIO device inside the jailer chroot."""
    chroot = Path(vm.jailer.chroot_path())
    dev_sysfs = chroot / path.lstrip("/")
    dev_sysfs.mkdir(parents=True, exist_ok=True)


def test_api_vfio(uvm_plain):
    """
    Test VFIO passthrough API commands.
    """

    FAKE_PATH = "fake_path"

    vm = uvm_plain
    create_vfio_path(vm, FAKE_PATH)
    vm.spawn()
    vm.basic_config()

    # Missing required field 'path'
    expected_msg = re.escape("missing field `path_on_host`")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.vfio.put(id="dev0")

    # Valid VFIO device config
    vm.api.vfio.put(id="nvme0", path_on_host=FAKE_PATH)

    # Overwriting an existing device should be OK
    vm.api.vfio.put(id="nvme0", path_on_host=FAKE_PATH)

    # Adding a second device should be OK
    vm.api.vfio.put(id="nvme1", path_on_host=FAKE_PATH)

    # Empty id should fail
    expected_msg = re.escape("The ID cannot be empty.")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.vfio.put(id="", path_on_host=FAKE_PATH)

    # Empty path should fail
    expected_msg = re.escape("Cannot verify path to the VFIO device")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.vfio.put(id="dev1", path_on_host="")

    # Invalid VFIO device config
    invalid_device_path = "invalid_path"
    expected_msg = re.escape("Cannot verify path to the VFIO device")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.vfio.put(id="nvme0", path_on_host=invalid_device_path)
