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

    # Unknown field
    expected_msg = re.escape("unknown field `foo`")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="dev0", sbdf="01:02.03", foo="bar")

    # Id in the path differs from the id in the body
    expected_msg = re.escape(
        "The id from the path does not match the id from the body!"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.request(
            "PUT", "/device-passthrough/dev1", id="dev0", sbdf="01:02.03"
        )

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

    # Failed requests do not change the config. SBDFs are normalized.
    assert vm.api.vm_config.get().json()["device-passthrough"] == [
        {"id": "nvme0", "sbdf": "0000:01:02.3"},
        {"id": "nvme1", "sbdf": "0000:01:02.4"},
    ]


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_missing_host_device(uvm):
    """
    Test that starting a VM with a passthrough device absent on the host fails.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config()

    vm.api.device_passthrough.put(id="nvme0", sbdf="0000:ff:1f.7")
    expected_msg = re.escape("Start microvm error")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.start()


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


@pin_pci(False)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_no_pci(uvm):
    """
    Test that adding a passthrough device without PCI enabled fails at API level.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config()

    expected_msg = re.escape("Passthrough devices attached, but PCI disabled")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
@pytest.mark.parametrize(
    "sbdf",
    ["", "aaaaaaaaaaa", "01:02", "0000:01:20.0", "0000:01:02.8", "0000:100:02.0"],
)
def test_device_passthrough_incompatible_devices_invalid_sbdf(uvm, sbdf):
    """
    Test that adding a passthrough device with invalid SBDF fails at API level.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config()

    expected_msg = re.escape("Invalid device passthrough SBDF")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="nvme0", sbdf=sbdf)


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_dp_then_balloon(uvm):
    """
    Test that adding balloon after passthrough device fails at API level.
    """
    vm = uvm
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


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_balloon_then_dp(uvm):
    """
    Test that adding a passthrough device after balloon fails at API level.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config()

    vm.api.balloon.put(amount_mib=0, deflate_on_oom=False, stats_polling_interval_s=1)
    expected_msg = re.escape(
        "Passthrough devices are not compatible with memory balloon device"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_dp_then_mem_hot_plug(uvm):
    """
    Test that adding memory hotplug after passthrough device fails at API level.
    """
    vm = uvm
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


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_mem_hot_plug_then_dp(uvm):
    """
    Test that adding a passthrough device after memory hotplug fails at API level.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config()

    vm.api.memory_hotplug.put(total_size_mib=256, slot_size_mib=256, block_size_mib=64)
    expected_msg = re.escape(
        "Passthrough devices are not compatible with memory hot-plugging device"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_dp_then_pmem(uvm):
    """
    Test that adding pmem after passthrough device fails at API level.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config()

    vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")
    expected_msg = re.escape("Passthrough devices are not compatible with pmem device")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.pmem.put(id="pmem0", path_on_host="pmem0")


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_device_passthrough_incompatible_devices_pmem_then_dp(uvm):
    """
    Test that adding a passthrough device after pmem fails at API level.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config()

    vm.api.pmem.put(id="pmem0", path_on_host="pmem0")
    expected_msg = re.escape("Passthrough devices are not compatible with pmem device")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.device_passthrough.put(id="nvme0", sbdf="0000:01:02.03")
