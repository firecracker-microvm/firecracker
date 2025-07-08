# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for adding the maximum number of devices to a microVM."""

import platform

import pytest


# IRQs are available from 5 to 23. We always use one IRQ for VMGenID device, so
# the maximum number of devices supported at the same time is 18.
def max_devices(uvm):
    """
    Returns the maximum number of devices supported by the platform.
    """
    if uvm.pci_enabled:
        return 31

    match platform.machine():
        case "aarch64":
            return 64
        case "x86_64":
            return 18
        case _:
            raise ValueError("Unknown platform")


def test_attach_maximum_devices(microvm_factory, guest_kernel, rootfs, pci_enabled):
    """
    Test attaching maximum number of devices to the microVM.
    """
    test_microvm = microvm_factory.build(
        kernel=guest_kernel, rootfs=rootfs, monitor_memory=False
    )
    test_microvm.spawn(pci=pci_enabled)

    # Set up a basic microVM.
    test_microvm.basic_config(mem_size_mib=1024)

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


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Firecracker has a bug in aarch that limits devices to 64, from the theoretical 96.",
)
def test_attach_too_many_devices(microvm_factory, guest_kernel, rootfs, pci_enabled):
    """
    Test attaching to a microVM more devices than available IRQs.
    """
    test_microvm = microvm_factory.build(
        kernel=guest_kernel, rootfs=rootfs, monitor_memory=False
    )
    test_microvm.spawn(pci=pci_enabled)

    # Set up a basic microVM.
    test_microvm.basic_config(mem_size_mib=1024)

    max_devices_attached = max_devices(test_microvm)

    # Add `MAX_DEVICES_ATTACHED` network devices on top of the
    # already configured rootfs.
    for _ in range(max_devices_attached):
        test_microvm.add_net_iface()

    # Attempting to start a microVM with more than
    # `MAX_DEVICES_ATTACHED` devices should fail.
    error_str = (
        ("Could not find an available device slot on the PCI bus.")
        if pci_enabled
        else (
            "Failed to allocate requested resource: The requested resource"
            " is not available."
        )
    )
    with pytest.raises(RuntimeError, match=error_str):
        test_microvm.start()
