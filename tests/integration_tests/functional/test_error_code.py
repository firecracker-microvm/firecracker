# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for Firecracker kvm exit handling."""

import os
import platform
import pytest
from framework.utils import wait_process_termination


@pytest.mark.skipif(
    platform.machine() != "aarch64",
    reason="The error code returned on aarch64 will not be returned on x86 "
           "under the same conditions."
)
def test_enosys_error_code(test_microvm_with_initrd):
    """
    Test that ENOSYS error is caught and firecracker exits gracefully.

    @type: functional
    """
    # On aarch64 we trigger this error by adding to initrd a C program that
    # maps a file into memory and then tries to load the content from an
    # offset in the file bigger than its length into a register asm volatile
    # ("ldr %0, [%1], 4" : "=r" (ret), "+r" (buf));
    vm = test_microvm_with_initrd
    vm.jailer.daemonize = False
    vm.spawn()
    vm.memory_monitor = None

    vm.initrd_file = os.path.join(vm.path, "fsfiles/", "initrd_enosys.img")
    vm.basic_config(
        add_root_device=False,
        vcpu_count=1,
        boot_args='console=ttyS0 reboot=k panic=1 pci=off',
        use_initrd=True
    )

    vm.start()

    # Check if FC process is closed
    wait_process_termination(vm.jailer_clone_pid)

    vm.check_log_message("Received ENOSYS error because KVM failed to"
                         " emulate an instruction.")
    vm.check_log_message("Vmm is stopping.")
