# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for device passthrough."""

import json
import os
import re
import stat
from pathlib import Path

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel, pin_pci

VFIO_SBDF = os.environ.get("FC_VFIO_PCI_SBDF")
VFIO_SYSFS = os.environ.get("FC_VFIO_PCI_SYSFS_PATH")


def vfio_device_test(test):
    """
    Mark a test which needs a host VFIO device. Skip it if no VFIO device was
    passed through env variables. Also use `xdist_group` to make sure these
    tests run sequentially since we only have 1 device to work with.
    """
    for mark in [
        pytest.mark.skipif(
            VFIO_SBDF is None, reason="No VFIO device configured (set FC_VFIO_PCI_SBDF)"
        ),
        pytest.mark.xdist_group("vfio"),
        pytest.mark.vfio,
        pin_pci(True),
    ]:
        test = mark(test)
    return test


@pytest.fixture
def uvm_with_vfio(uvm):
    """Boot a microVM with the VFIO NVMe device attached."""
    vm = uvm

    # Set up the jailer chroot directory before spawning
    vm.jailer.setup()

    chroot = Path(vm.jailer.chroot_path())
    dev_sysfs = chroot / f"sys/bus/pci/devices/{VFIO_SBDF}"
    dev_sysfs.mkdir(parents=True, exist_ok=True)

    # Create VFIO device nodes inside the jailer chroot
    group_id = os.readlink(f"{VFIO_SYSFS}/iommu_group").split("/")[-1]
    vfio_dir = chroot / "dev" / "vfio"
    vfio_dir.mkdir(parents=True, exist_ok=True)
    for name in ["vfio", group_id]:
        src = Path(f"/dev/vfio/{name}")
        dst = vfio_dir / name
        st = src.stat()
        os.mknod(dst, stat.S_IFCHR | 0o600, st.st_rdev)
        os.chown(dst, vm.jailer.uid, vm.jailer.gid)

    # Create iommu_group symlink for the VFIO device.
    # The VFIO code readlink()s this to get the group ID from the basename.
    (dev_sysfs / "iommu_group").symlink_to(f"../iommu_groups/{group_id}")
    os.lchown(dev_sysfs / "iommu_group", vm.jailer.uid, vm.jailer.gid)

    vm.spawn()
    vm.basic_config(mem_size_mib=512)
    vm.add_net_iface()
    vm.api.device_passthrough.put(id="nvme0", sbdf=VFIO_SBDF)
    vm.start()
    return vm


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


@vfio_device_test
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_vfio_nvme_not_present_without_config(uvm):
    """NVMe device does NOT appear when no VFIO device is configured."""
    vm = uvm
    vm.spawn()
    vm.basic_config(mem_size_mib=512)
    vm.add_net_iface()
    vm.start()

    rc, _, _ = vm.ssh.run("test -e /dev/nvme0n1")
    assert rc != 0

    _, stdout, _ = vm.ssh.check_output("lspci -nn")
    assert "Non-Volatile memory controller" not in stdout


@vfio_device_test
def test_vfio_nvme_visible(uvm_with_vfio):
    """The passthrough device appears on the guest PCI bus."""
    vm = uvm_with_vfio
    assert vm.api.vm_config.get().json()["device-passthrough"] == [
        {"id": "nvme0", "sbdf": VFIO_SBDF}
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
def test_vfio_nvme_read(uvm_with_vfio):
    """The guest can read data from the passthrough NVMe device."""
    vm = uvm_with_vfio
    _, stdout, _ = vm.ssh.check_output(
        "dd if=/dev/nvme0n1 of=/dev/null bs=4k count=256 2>&1"
    )
    assert "256+0 records in" in stdout


@vfio_device_test
@pytest.mark.parametrize("bs,count", [("4k", 1), ("1M", 64)])
def test_vfio_nvme_write_readback(uvm_with_vfio, bs, count):
    """Write data and read it back to confirm DMA in both directions."""
    vm = uvm_with_vfio
    vm.ssh.check_output(f"dd if=/dev/urandom of=/tmp/pattern bs={bs} count={count}")
    vm.ssh.check_output(
        f"dd if=/tmp/pattern of=/dev/nvme0n1 bs={bs} count={count} oflag=direct"
    )
    vm.ssh.check_output(
        f"dd if=/dev/nvme0n1 of=/tmp/readback bs={bs} count={count} iflag=direct"
    )
    # There is no `cmp` binary in AL2023 rootfs, so use a workaround
    _, stdout, _ = vm.ssh.check_output("md5sum /tmp/pattern /tmp/readback")
    hashes = [line.split()[0] for line in stdout.strip().splitlines()]
    assert hashes[0] == hashes[1], "write/readback mismatch"


@vfio_device_test
def test_vfio_nvme_snapshot(uvm_with_vfio):
    """Snapshots are rejected with a passthrough device and the VM keeps working."""
    vm = uvm_with_vfio
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
