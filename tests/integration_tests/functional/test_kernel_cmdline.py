# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test kernel commandline behavior."""

from framework.microvm import Serial


def test_init_params(test_microvm_with_api):
    """Correct propagation of boot args to the kernel's command line.

    Test that init's parameters (the ones present after "--") do not get
    altered or misplaced.
    """
    vm = test_microvm_with_api
    vm.jailer.daemonize = False
    vm.spawn()
    vm.memory_monitor = None

    # We will override the init with /bin/cat so that we try to read the
    # Ubuntu version from the /etc/issue file.
    vm.basic_config(
        vcpu_count=1,
        boot_args="console=ttyS0 reboot=k panic=1 pci=off"
        " init=/bin/cat -- /etc/issue",
    )

    vm.start()
    serial = Serial(vm)
    serial.open()
    # If the string does not show up, the test will fail.
    serial.rx(token="Ubuntu 22.04")
