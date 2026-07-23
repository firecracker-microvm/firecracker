# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test booting a guest from a bzImage kernel (x86_64 direct boot)."""

import platform

import pytest

pytestmark = pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="bzImage direct boot is only supported on x86_64",
)


def test_bzimage_boots_to_userspace(uvm):
    """Boot the bzImage built from the same source as the guest's vmlinux."""
    assert (
        uvm.guest_kernel.bzimage is not None
    ), f"Missing bzImage sibling for {uvm.guest_kernel.vmlinux}"
    uvm.boot_image = uvm.guest_kernel.bzimage

    uvm.spawn(log_level="Debug")
    uvm.basic_config()
    uvm.add_net_iface()
    uvm.start()

    # Reached userspace.
    uvm.ssh.check_output("true")
    # Firecracker took the bzImage load path.
    assert "(bzImage)" in uvm.log_data
