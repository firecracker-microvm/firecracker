# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for VFIO passthrough API."""

import re
from pathlib import Path

import pytest


def test_api_vfio(microvm_factory, guest_kernel, rootfs):
    """
    Test VFIO passthrough API commands.
    """

    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
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


def test_vfio_incompatible_devices_no_pci(microvm_factory, guest_kernel, rootfs):
    """
    Test that adding VFIO device without PCI fails at API level.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=False)
    vm.jailer.setup()
    vm.spawn()
    vm.basic_config()

    expected_msg = re.escape("VFIO devices attached, but PCI disabled")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.vfio.put(id="nvme0", sbdf="0000:01:02.03")


def test_vfio_incompatible_devices_vfio_balloon(microvm_factory, guest_kernel, rootfs):
    """
    Test that adding balloon after VFIO fails at API level.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.jailer.setup()
    vm.spawn()
    vm.basic_config()

    vm.api.vfio.put(id="nvme0", sbdf="0000:01:02.03")
    expected_msg = re.escape(
        "VFIO devices are not compatible with memory balloon device"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.balloon.put(
            amount_mib=0, deflate_on_oom=False, stats_polling_interval_s=1
        )


def test_vfio_incompatible_devices_balloon_vfio(microvm_factory, guest_kernel, rootfs):
    """
    Test that adding VFIO after balloon fails at API level.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.jailer.setup()
    vm.spawn()
    vm.basic_config()

    vm.api.balloon.put(amount_mib=0, deflate_on_oom=False, stats_polling_interval_s=1)
    expected_msg = re.escape(
        "VFIO devices are not compatible with memory balloon device"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.vfio.put(id="nvme0", sbdf="0000:01:02.03")


def test_vfio_incompatible_devices_vfio_mem_hot_plug(
    microvm_factory, guest_kernel, rootfs
):
    """
    Test that adding memory hotplug after VFIO fails at API level.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.jailer.setup()
    vm.spawn()
    vm.basic_config()

    vm.api.vfio.put(id="nvme0", sbdf="0000:01:02.03")
    expected_msg = re.escape(
        "VFIO devices are not compatible with memory hot-plugging device"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.memory_hotplug.put(
            total_size_mib=256, slot_size_mib=256, block_size_mib=64
        )


def test_vfio_incompatible_devices_mem_hot_plug_vfio(
    microvm_factory, guest_kernel, rootfs
):
    """
    Test that adding VFIO after memory hotplug fails at API level.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.jailer.setup()
    vm.spawn()
    vm.basic_config()

    vm.api.memory_hotplug.put(total_size_mib=256, slot_size_mib=256, block_size_mib=64)
    expected_msg = re.escape(
        "VFIO devices are not compatible with memory hot-plugging device"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.vfio.put(id="nvme0", sbdf="0000:01:02.03")
