# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for VFIO passthrough."""

import json
import os
import re
import stat
from pathlib import Path

import pytest

VFIO_SBDF = os.environ.get("FC_VFIO_PCI_SBDF")
VFIO_SYSFS = os.environ.get("FC_VFIO_PCI_SYSFS_PATH")

# Skip tests if no VFIO device was passed through env variables. Also use
# `xdist_group` to make sure all tests here run sequentially since we only have
# 1 device to work with
pytestmark = [
    pytest.mark.skipif(
        VFIO_SBDF is None, reason="No VFIO device configured (set FC_VFIO_PCI_SBDF)"
    ),
    pytest.mark.xdist_group("vfio"),
    pytest.mark.vfio,
]


@pytest.fixture
def uvm_with_vfio(microvm_factory, guest_kernel, rootfs):
    """Boot a microVM with the VFIO NVMe device attached."""
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)

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
    vm.api.vfio.put(id="nvme0", sbdf=VFIO_SBDF)
    vm.start()
    return vm


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
    vm.api.vfio.put(id="nvme1", sbdf="0000:01:02.03")

    # Empty id should fail
    expected_msg = re.escape("The ID cannot be empty.")
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.vfio.put(id="", sbdf="0000:01:02.03")


def test_vfio_nvme_not_present_without_config(microvm_factory, guest_kernel, rootfs):
    """NVMe device does NOT appear when no VFIO device is configured."""
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.spawn()
    vm.basic_config(mem_size_mib=512)
    vm.add_net_iface()
    vm.start()

    rc, _, _ = vm.ssh.run("test -e /dev/nvme0n1")
    assert rc != 0

    _, stdout, _ = vm.ssh.check_output("lspci -nn")
    assert "Non-Volatile memory controller" not in stdout


def test_vfio_nvme_visible(uvm_with_vfio):
    """The passthrough device appears on the guest PCI bus."""
    vm = uvm_with_vfio
    _, stdout, _ = vm.ssh.check_output("lspci -nn")
    assert "Non-Volatile memory controller" in stdout

    vm.ssh.check_output("test -d /sys/class/nvme/nvme0")
    vm.ssh.check_output("test -b /dev/nvme0n1")

    _, stdout, _ = vm.ssh.check_output("lsblk -Jb")
    blocks = json.loads(stdout)["blockdevices"]
    nvme = [b for b in blocks if b["name"] == "nvme0n1"]
    assert len(nvme) == 1
    assert int(nvme[0]["size"]) > 0


def test_vfio_nvme_read(uvm_with_vfio):
    """The guest can read data from the passthrough NVMe device."""
    vm = uvm_with_vfio
    _, stdout, _ = vm.ssh.check_output(
        "dd if=/dev/nvme0n1 of=/dev/null bs=4k count=256 2>&1"
    )
    assert "256+0 records in" in stdout


def test_vfio_nvme_write_readback(uvm_with_vfio):
    """Write data and read it back to confirm DMA in both directions."""
    vm = uvm_with_vfio
    vm.ssh.check_output("dd if=/dev/urandom of=/tmp/pattern bs=4k count=1")
    vm.ssh.check_output("dd if=/tmp/pattern of=/dev/nvme0n1 bs=4k count=1 oflag=direct")
    vm.ssh.check_output(
        "dd if=/dev/nvme0n1 of=/tmp/readback bs=4k count=1 iflag=direct"
    )
    # There is no `cmp` binary in AL2023 rootfs, so use a workaround
    _, stdout, _ = vm.ssh.check_output("md5sum /tmp/pattern /tmp/readback")
    hashes = [line.split()[0] for line in stdout.strip().splitlines()]
    assert hashes[0] == hashes[1], "write/readback mismatch"
