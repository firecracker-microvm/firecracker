# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for adding the maximum number of devices to a microVM."""

import platform

import pytest


def max_devices(uvm):
    """
    Returns the maximum number of devices supported by the platform.
    """
    if uvm.pci_enabled:
        # On PCI, we only have one bus, so 32 minus the bus itself
        return 31

    match platform.machine():
        case "aarch64":
            # On aarch64, IRQs are available from 32 to 127. We always use one IRQ each for
            # the VMGenID, VMClock, RTC and serial devices, so the maximum number of devices
            # supported at the same time is 92.
            return 92
        case "x86_64":
            # IRQs are available from 5 to 23. We always use one IRQ for VMGenID and VMClock
            # devices, so the maximum number of devices supported at the same time is 17.
            return 17
        case _:
            raise ValueError("Unknown platform")


def test_attach_maximum_devices(uvm_plain_any):
    """
    Test attaching maximum number of devices to the microVM.
    """
    test_microvm = uvm_plain_any
    test_microvm.memory_monitor = None
    test_microvm.spawn()

    # The default 256mib is not enough for 94 ssh connections on aarch64.
    test_microvm.basic_config(mem_size_mib=512)

    max_devices_attached = max_devices(test_microvm)
    # Add (`MAX_DEVICES_ATTACHED` - 1) devices because the rootfs
    # has already been configured in the `basic_config()`function.
    for _ in range(max_devices_attached - 1):
        test_microvm.add_net_iface()
    test_microvm.start()

    # Test that network devices attached are operational.
    for i in range(max_devices_attached - 1):
        # Verify if guest can run commands.
        test_microvm.ssh_iface(i).check_output("sync")


def test_attach_too_many_devices(uvm_plain):
    """
    Test attaching to a microVM more devices than available IRQs.
    """
    test_microvm = uvm_plain
    test_microvm.memory_monitor = None
    test_microvm.spawn()

    # Set up a basic microVM.
    test_microvm.basic_config()

    max_devices_attached = max_devices(test_microvm)

    # Add `MAX_DEVICES_ATTACHED` network devices on top of the
    # already configured rootfs.
    for _ in range(max_devices_attached):
        test_microvm.add_net_iface()

    # Attempting to start a microVM with more than
    # `MAX_DEVICES_ATTACHED` devices should fail.
    error_str = (
        ("Could not find an available device slot on the PCI bus.")
        if test_microvm.pci_enabled
        else (
            "Failed to allocate requested resource: The requested resource"
            " is not available."
        )
    )
    with pytest.raises(RuntimeError, match=error_str):
        test_microvm.start()
