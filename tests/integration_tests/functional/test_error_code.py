# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for Firecracker kvm exit handling."""

import platform

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.properties import global_props


@pytest.mark.skipif(
    platform.machine() != "aarch64",
    reason="The error code returned on aarch64 will not be returned on x86 "
    "under the same conditions.",
)
@pytest.mark.skipif(
    global_props.host_linux_version_metrics == "next",
    reason="The test is known to be flaky on Linux next",
)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_enosys_error_code(uvm):
    """
    Test that ENOSYS error is caught and firecracker exits gracefully.
    """
    # On aarch64 we trigger this error by running a C program that
    # maps a file into memory and then tries to load the content from an
    # offset in the file bigger than its length into a register asm volatile
    # ("ldr %0, [%1], 4" : "=r" (ret), "+r" (buf));
    vm = uvm
    vm.spawn()
    vm.memory_monitor = None
    vm.basic_config(
        vcpu_count=1,
        boot_args="reboot=k panic=1 swiotlb=noforce init=/usr/local/bin/devmemread",
    )
    vm.start()

    # Check if FC process is closed
    vm.mark_killed()

    vm.check_log_message(
        "Received ENOSYS error because KVM failed to emulate an instruction."
    )
    vm.check_log_message("Vmm is stopping.")
