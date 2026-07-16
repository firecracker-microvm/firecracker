# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test booting a guest from a bzImage kernel (x86_64 direct boot)."""

import dataclasses
import platform

import pytest

from framework.artifacts import ALL_GUEST_KERNELS
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend

# Every guest kernel that ships a bzImage sibling. On x86_64 the EFI artifact
# *is* the bzImage, already resolved (with an existence check) by GuestKernel;
# no-ACPI kernels have none, so they drop out here.
BZIMAGE_KERNELS = [
    pytest.param(
        dataclasses.replace(param.values[0], vmlinux=param.values[0].efi_image),
        id=param.values[0].efi_image.name,
    )
    for param in ALL_GUEST_KERNELS
    if param.values[0] is not None and param.values[0].efi_image is not None
]

# Asserts Firecracker took the x86 direct-boot path. Enclave backends boot an
# EFI image out of an EIF, so that path never runs there.
pytestmark = [
    pytest.mark.skipif(
        platform.machine() != "x86_64",
        reason="bzImage direct boot is only supported on x86_64",
    ),
    pin_vm_backend(VM_BACKEND_KVM),
]


@pytest.fixture(params=BZIMAGE_KERNELS)
def guest_kernel(request, record_property):
    """Guest kernels booted from their bzImage sibling."""
    kernel = request.param
    record_property("guest_kernel", kernel.metric_id)
    return kernel


def test_bzimage_boots_to_userspace(uvm):
    """Boot the bzImage built from the same source as the guest's vmlinux."""
    uvm.spawn(log_level="Debug")
    uvm.basic_config()
    uvm.add_net_iface()
    uvm.start()

    # Reached userspace.
    uvm.ssh.check_output("true")
    # Firecracker took the bzImage load path.
    assert "(bzImage)" in uvm.log_data
