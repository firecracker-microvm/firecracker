# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for initrd."""
import pytest

from framework.microvm import HugePagesConfig, Serial

INITRD_FILESYSTEM = "rootfs"


@pytest.fixture
def uvm_with_initrd(microvm_factory, guest_kernel, record_property, artifact_dir):
    """
    See file:../docs/initrd.md
    """
    fs = artifact_dir / "initramfs.cpio"
    record_property("rootfs", fs.name)
    uvm = microvm_factory.build(guest_kernel)
    uvm.initrd_file = fs
    yield uvm


@pytest.mark.parametrize("huge_pages", HugePagesConfig)
def test_microvm_initrd_with_serial(uvm_with_initrd, huge_pages):
    """
    Test that a boot using initrd successfully loads the root filesystem.
    """
    vm = uvm_with_initrd
    vm.help.enable_console()
    vm.spawn()
    vm.memory_monitor = None

    vm.basic_config(
        add_root_device=False,
        vcpu_count=1,
        boot_args="console=ttyS0 reboot=k panic=1 pci=off",
        use_initrd=True,
        huge_pages=huge_pages,
    )

    vm.start()
    serial = Serial(vm)
    serial.open()
    serial.rx(token="# ")
    serial.tx("mount |grep rootfs")
    serial.rx(token=f"rootfs on / type {INITRD_FILESYSTEM}")
