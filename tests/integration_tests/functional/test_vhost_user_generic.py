# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the generic vhost-user device."""

import shutil
from pathlib import Path

import pytest

from host_tools.fcmetrics import FcDeviceMetrics


# virtio-block device type ID
VIRTIO_BLK_TYPE = 2


@pytest.fixture
def uvm_vhost_user_generic_plain(microvm_factory, guest_kernel, pci_enabled):
    """Builds a plain VM with no root volume"""
    return microvm_factory.build(
        guest_kernel, None, pci=pci_enabled, monitor_memory=False
    )


@pytest.fixture
def uvm_vhost_user_generic_booted_ro(uvm_vhost_user_generic_plain, rootfs):
    """Returns a VM with a generic vhost-user block rootfs (read-only)"""
    vm = uvm_vhost_user_generic_plain

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    # The generic device does not set root= in the kernel command line
    # automatically, so we pass it explicitly via boot_args.
    boot_args = "reboot=k panic=1 nomodule swiotlb=noforce console=ttyS0 root=/dev/vda ro"
    if not vm.pci_enabled:
        boot_args += " pci=off"
    vm.basic_config(add_root_device=False, boot_args=boot_args)
    vm.add_vhost_user_generic_device(
        "rootfs",
        rootfs,
        device_type=VIRTIO_BLK_TYPE,
        num_queues=1,
        is_read_only=True,
    )
    vm.add_net_iface()
    vm.start()

    return vm


@pytest.fixture
def uvm_vhost_user_generic_booted_rw(uvm_vhost_user_generic_plain, rootfs):
    """Returns a VM with a generic vhost-user block rootfs (read-write)"""
    vm = uvm_vhost_user_generic_plain

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    boot_args = "reboot=k panic=1 nomodule swiotlb=noforce console=ttyS0 root=/dev/vda rw"
    if not vm.pci_enabled:
        boot_args += " pci=off"
    vm.basic_config(add_root_device=False, boot_args=boot_args)
    # Create a rw rootfs file that is unique to the microVM
    rootfs_rw = Path(vm.chroot()) / "rootfs"
    shutil.copy(rootfs, rootfs_rw)
    vm.add_vhost_user_generic_device(
        "rootfs",
        rootfs_rw,
        device_type=VIRTIO_BLK_TYPE,
        num_queues=1,
        is_read_only=False,
    )
    vm.add_net_iface()
    vm.start()

    return vm


def _check_block_size(ssh_connection, dev_path, size):
    """
    Checks the size of the block device.
    """
    _, stdout, stderr = ssh_connection.run("blockdev --getsize64 {}".format(dev_path))
    assert stderr == ""
    assert stdout.strip() == str(size)


def _check_drives(test_microvm, assert_dict, keys_array):
    """
    Checks the info on the block devices.
    """
    _, stdout, stderr = test_microvm.ssh.run("blockdev --report")
    assert stderr == ""
    blockdev_out_lines = stdout.splitlines()
    for key in keys_array:
        line = int(key.split("-")[0])
        col = int(key.split("-")[1])
        blockdev_out_line_cols = blockdev_out_lines[line].split()
        assert blockdev_out_line_cols[col] == assert_dict[key]


def test_vhost_user_generic_block(uvm_vhost_user_generic_booted_ro):
    """
    Test booting a VM with a generic vhost-user device
    configured as a virtio-block root device (read-only).
    """

    vm = uvm_vhost_user_generic_booted_ro
    vhost_user_generic_metrics = FcDeviceMetrics(
        "vhost_user_generic", 1, aggr_supported=False
    )

    assert_dict = {
        "1-0": "ro",
        "1-6": "/dev/vda",
    }
    _check_drives(vm, assert_dict, assert_dict.keys())
    vhost_user_generic_metrics.validate(vm)


def test_vhost_user_generic_block_rw(uvm_vhost_user_generic_booted_rw):
    """
    Test booting a VM with a generic vhost-user device
    configured as a virtio-block root device (read-write).
    """

    vm = uvm_vhost_user_generic_booted_rw

    assert_dict = {
        "1-0": "rw",
        "1-6": "/dev/vda",
    }
    _check_drives(vm, assert_dict, assert_dict.keys())


def test_vhost_user_generic_disconnect(uvm_vhost_user_generic_booted_ro):
    """
    Test that even if backend is killed, Firecracker is still responsive.
    """

    vm = uvm_vhost_user_generic_booted_ro

    # Killing the backend
    vm.disks_vhost_user["rootfs"].kill()
    del vm.disks_vhost_user["rootfs"]

    # Verify that Firecracker is still responsive
    _config = vm.api.vm_config.get().json()
