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
    # Every x86_64 vmlinux artifact has a bzImage sibling.
    uvm.kernel_file = uvm.kernel_file.with_name(
        uvm.kernel_file.name.replace("vmlinux-", "bzImage-", 1)
    )

    uvm.spawn(log_level="Debug")
    uvm.basic_config()
    uvm.add_net_iface()
    uvm.start()

    # Reached userspace.
    uvm.ssh.check_output("true")
    # Firecracker took the bzImage load path.
    assert "(bzImage)" in uvm.log_data
