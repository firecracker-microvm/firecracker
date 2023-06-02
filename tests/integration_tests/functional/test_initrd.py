# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for initrd."""

from framework.microvm import Serial

INITRD_FILESYSTEM = "rootfs"


def test_microvm_initrd_with_serial(uvm_with_initrd):
    """
    Test that a boot using initrd successfully loads the root filesystem.
    """
    vm = uvm_with_initrd
    vm.jailer.daemonize = False
    vm.spawn()
    vm.memory_monitor = None

    vm.basic_config(
        add_root_device=False,
        vcpu_count=1,
        boot_args="console=ttyS0 reboot=k panic=1 pci=off",
        use_initrd=True,
    )

    vm.start()
    serial = Serial(vm)
    serial.open()
    serial.rx(token="# ")
    serial.tx("mount |grep rootfs")
    serial.rx(token=f"rootfs on / type {INITRD_FILESYSTEM}")
