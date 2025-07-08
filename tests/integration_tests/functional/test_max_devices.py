# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for adding the maximum number of devices to a microVM."""

import platform

import pytest

# On x86_64, IRQs are available from 5 to 23. We always use one IRQ for VMGenID
# device, so the maximum number of devices supported at the same time is 18.

# On aarch64, IRQs are available from 32 to 127. We always use one IRQ each for
# the VMGenID and RTC devices, so the maximum number of devices supported
# at the same time is 94.
MAX_DEVICES_ATTACHED = {"x86_64": 18, "aarch64": 94}.get(platform.machine())


def test_attach_maximum_devices(microvm_factory, guest_kernel, rootfs):
    """
    Test attaching maximum number of devices to the microVM.
    """
    if MAX_DEVICES_ATTACHED is None:
        pytest.skip("Unsupported platform for this test.")

    test_microvm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    test_microvm.spawn()

    # The default 256mib is not enough for 94 ssh connections on aarch64.
    test_microvm.basic_config(mem_size_mib=512)

    # Add (`MAX_DEVICES_ATTACHED` - 1) devices because the rootfs
    # has already been configured in the `basic_config()`function.
    for _ in range(MAX_DEVICES_ATTACHED - 1):
        test_microvm.add_net_iface()
    test_microvm.start()

    # Test that network devices attached are operational.
    for i in range(MAX_DEVICES_ATTACHED - 1):
        # Verify if guest can run commands.
        test_microvm.ssh_iface(i).check_output("sync")


def test_attach_too_many_devices(microvm_factory, guest_kernel, rootfs):
    """
    Test attaching to a microVM more devices than available IRQs.
    """
    if MAX_DEVICES_ATTACHED is None:
        pytest.skip("Unsupported platform for this test.")

    test_microvm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    test_microvm.spawn()

    # Set up a basic microVM.
    test_microvm.basic_config()

    # Add `MAX_DEVICES_ATTACHED` network devices on top of the
    # already configured rootfs.
    for _ in range(MAX_DEVICES_ATTACHED):
        test_microvm.add_net_iface()

    # Attempting to start a microVM with more than
    # `MAX_DEVICES_ATTACHED` devices should fail.
    error_str = (
        "Failed to allocate requested resource: The requested resource"
        " is not available."
    )
    with pytest.raises(RuntimeError, match=error_str):
        test_microvm.start()
