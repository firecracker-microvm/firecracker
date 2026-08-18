# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for a device passthrough API."""

import re

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel, pin_pci


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_api_device_passthrough(uvm):
    """
    Test device passthrough API commands.
    """

    vm = uvm
    vm.spawn()
    vm.basic_config()

    # Missing required field 'sbdf'
    expected_msg = re.escape("missing field `sbdf`")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="dev0")

    # Valid passthrough device configs and overwrites
    vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")
    vm.api.device_passthrough.put(id="nvme0", sbdf="01:02.03")

    # Duplicate SBDF
    expected_msg = re.escape("Duplicate device passthrough SBDF")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="nvme1", sbdf="01:02.03")

    # Adding a second device should be OK
    vm.api.device_passthrough.put(id="nvme1", sbdf="0000:01:02.04")

    # Empty id should fail
    expected_msg = re.escape("The ID cannot be empty.")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="", sbdf="0000:01:02.05")


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_api_device_passthrough_runtime(uvm):
    """
    Test device passthrough API commands during runtime.
    """

    vm = uvm
    vm.spawn()
    vm.basic_config()

    # Not a runtime API
    vm.start()
    expected_msg = re.escape(
        "The requested operation is not supported after starting the microVM"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="nvme69", sbdf="01:02.03")


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_no_pci(
    microvm_factory, guest_kernel, rootfs
):
    """
    Test that adding device without PCI fails at API level.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=False)
    vm.jailer.setup()
    vm.spawn()
    vm.basic_config()

    expected_msg = re.escape("Passthrough devices attached, but PCI disabled")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_dp_then_balloon(
    microvm_factory, guest_kernel, rootfs
):
    """
    Test that adding balloon after passthrough device fails at API level.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.jailer.setup()
    vm.spawn()
    vm.basic_config()

    vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")
    expected_msg = re.escape(
        "Passthrough devices are not compatible with memory balloon device"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.balloon.put(
            amount_mib=0, deflate_on_oom=False, stats_polling_interval_s=1
        )


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_balloon_then_dp(
    microvm_factory, guest_kernel, rootfs
):
    """
    Test that adding passthrough device after balloon fails at API level.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.jailer.setup()
    vm.spawn()
    vm.basic_config()

    vm.api.balloon.put(amount_mib=0, deflate_on_oom=False, stats_polling_interval_s=1)
    expected_msg = re.escape(
        "Passthrough devices are not compatible with memory balloon device"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_dp_then_mem_hot_plug(
    microvm_factory, guest_kernel, rootfs
):
    """
    Test that adding memory hotplug after passthrough device fails at API level.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.jailer.setup()
    vm.spawn()
    vm.basic_config()

    vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")
    expected_msg = re.escape(
        "Passthrough devices are not compatible with memory hot-plugging device"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.memory_hotplug.put(
            total_size_mib=256, slot_size_mib=256, block_size_mib=64
        )


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_mem_hot_plug_then_dp(
    microvm_factory, guest_kernel, rootfs
):
    """
    Test that adding passthrough device after memory hotplug fails at API level.
    """
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.jailer.setup()
    vm.spawn()
    vm.basic_config()

    vm.api.memory_hotplug.put(total_size_mib=256, slot_size_mib=256, block_size_mib=64)
    expected_msg = re.escape(
        "Passthrough devices are not compatible with memory hot-plugging device"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")
