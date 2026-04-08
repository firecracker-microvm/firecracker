# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for device passthrough."""

import json
import re

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel, pin_pci


def vfio_device_test(test):
    """
    Mark a test which needs a host VFIO device. Skip it if no VFIO device is
    configured. These tests must run sequentially since we only have 1 device
    to work with.
    """
    for mark in [pytest.mark.vfio, pytest.mark.usefixtures("vfio_nvme"), pin_pci(True)]:
        test = mark(test)
    return test


# Shadow the conftest `uvm_booted` for the whole module, so VFIO tests get a
# booted microVM with the passthrough NVMe device attached.
@pytest.fixture
def uvm_booted(uvm_configured, vfio_nvme):
    """Booted microVM with the VFIO NVMe device attached."""
    uvm_configured.add_net_iface()
    uvm_configured.add_passthrough_device("nvme0", vfio_nvme)
    uvm_configured.start()
    return uvm_configured


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


@pin_pci(True)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_vfio_nvme_not_present_without_config(uvm):
    """NVMe device does NOT appear when no VFIO device is configured."""
    vm = uvm
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    vm.start()

    rc, _, _ = vm.ssh.run("test -e /dev/nvme0n1")
    assert rc != 0

    _, stdout, _ = vm.ssh.check_output("lspci -nn")
    assert "Non-Volatile memory controller" not in stdout


@vfio_device_test
def test_vfio_nvme_visible(uvm_booted, vfio_nvme):
    """The passthrough device appears on the guest PCI bus."""
    vm = uvm_booted
    assert vm.api.vm_config.get().json()["device-passthrough"] == [
        {"id": "nvme0", "sbdf": vfio_nvme}
    ]

    _, stdout, _ = vm.ssh.check_output("lspci -nn")
    assert "Non-Volatile memory controller" in stdout

    vm.ssh.check_output("test -d /sys/class/nvme/nvme0")
    vm.ssh.check_output("test -b /dev/nvme0n1")

    _, stdout, _ = vm.ssh.check_output("lsblk -Jb")
    blocks = json.loads(stdout)["blockdevices"]
    nvme = [b for b in blocks if b["name"] == "nvme0n1"]
    assert len(nvme) == 1
    assert int(nvme[0]["size"]) > 0

    # NVMe driver registers per queue MSI-X interrupts
    vm.ssh.check_output("grep nvme0q /proc/interrupts")


@vfio_device_test
def test_vfio_nvme_read(uvm_booted):
    """The guest can read data from the passthrough NVMe device."""
    vm = uvm_booted
    _, stdout, _ = vm.ssh.check_output(
        "dd if=/dev/nvme0n1 of=/dev/null bs=4k count=256 2>&1"
    )
    assert "256+0 records in" in stdout


@vfio_device_test
@pytest.mark.parametrize("bs,count", [("4k", 1), ("1M", 64)])
def test_vfio_nvme_write_readback(uvm_booted, bs, count):
    """Write data and read it back to confirm DMA in both directions."""
    vm = uvm_booted
    vm.ssh.check_output(f"dd if=/dev/urandom of=/tmp/pattern bs={bs} count={count}")
    vm.ssh.check_output(
        f"dd if=/tmp/pattern of=/dev/nvme0n1 bs={bs} count={count} oflag=direct"
    )
    # Stream the readback since guest /tmp can not hold 2 copies of the data.
    # There is no `cmp` binary in AL2023 rootfs, so compare hashes instead.
    _, pattern_hash, _ = vm.ssh.check_output("md5sum < /tmp/pattern")
    _, readback_hash, _ = vm.ssh.check_output(
        f"dd if=/dev/nvme0n1 bs={bs} count={count} iflag=direct | md5sum"
    )
    assert pattern_hash == readback_hash, "write/readback mismatch"


@vfio_device_test
def test_vfio_nvme_snapshot(uvm_booted):
    """Snapshots are rejected with a passthrough device and the VM keeps working."""
    vm = uvm_booted
    vm.pause()
    with pytest.raises(
        RuntimeError,
        match=r"Devices without snapshot support are present: passthrough device\(id: nvme0\)",
    ):
        vm.api.snapshot_create.put(
            mem_file_path="memfile", snapshot_path="statefile", snapshot_type="Full"
        )
    vm.resume()
    vm.ssh.check_output("dd if=/dev/nvme0n1 of=/dev/null bs=4k count=1 iflag=direct")
