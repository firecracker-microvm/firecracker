# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for adding the maximum number of devices to a microVM."""

import platform

import pytest

# On x86_64 IRQs are available from 5 to 23, so the maximum number of devices
# supported at the same time is 19.
# On aarch64 IRQ_MAX is 128.
# max_devices_attached = 19


# @pytest.mark.skipif(
#     platform.machine() != "x86_64", reason="Firecracker supports 24 IRQs on x86_64."
# )
def test_attach_maximum_devices(
    microvm_factory, guest_kernel_linux_5_10, rootfs_ubuntu_22
):
    """
    Test attaching maximum number of devices to the microVM.
    """
    # On x86_64 IRQs are available from 5 to 23, so the maximum number of devices
    # supported at the same time is 19.
    # On aarch64 IRQ_MAX is 128.
    if platform.machine() != "x86_64":
        max_devices_attached = 65
    else:
        max_devices_attached = 19
    test_microvm = microvm_factory.build(
        guest_kernel_linux_5_10, rootfs_ubuntu_22, monitor_memory=False
    )
    test_microvm.spawn()

    # Set up a basic microVM.
    test_microvm.basic_config()

    # Add (`max_devices_attached` - 1) devices because the rootfs
    # has already been configured in the `basic_config()`function.
    for _ in range(max_devices_attached - 1):
        test_microvm.add_net_iface()
    test_microvm.start()

    # Test that network devices attached are operational.
    for i in range(max_devices_attached - 1):
        # Verify if guest can run commands.
        try:
            exit_code, _, _ = test_microvm.ssh_iface(i).run("sync")
        except:
            pass
        assert exit_code == 0

    for i in range(max_devices_attached - 2):
        # Verify if guest can run commands.
            exit_code, _, _ = test_microvm.ssh_iface(i).run("sync")

# @pytest.mark.skipif(
#     platform.machine() != "x86_64", reason="Firecracker supports 24 IRQs on x86_64."
# )
def test_attach_too_many_devices(
    microvm_factory, guest_kernel_linux_5_10, rootfs_ubuntu_22
):
    """
    Test attaching to a microVM more devices than available IRQs.
    """
    # On x86_64 IRQs are available from 5 to 23, so the maximum number of devices
    # supported at the same time is 19.
    # On aarch64 IRQ_MAX is 128.
    if platform.machine() != "x86_64":
        max_devices_attached = 128
    else:
        max_devices_attached = 19
    test_microvm = microvm_factory.build(
        guest_kernel_linux_5_10, rootfs_ubuntu_22, monitor_memory=False
    )
    test_microvm.spawn()

    # Set up a basic microVM.
    test_microvm.basic_config()

    # Add `max_devices_attached` network devices on top of the
    # already configured rootfs.
    for _ in range(max_devices_attached):
        test_microvm.add_net_iface()

    # Attempting to start a microVM with more than
    # `max_devices_attached` devices should fail.
    error_str = (
        "Failed to allocate requested resource: The requested resource"
        " is not available."
    )
    with pytest.raises(RuntimeError, match=error_str):
        test_microvm.start()
