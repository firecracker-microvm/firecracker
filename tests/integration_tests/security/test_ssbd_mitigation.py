# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests Speculative Store Bypass mitigations in jailer/Firecracker."""

from framework.utils import run_cmd


def test_ssbd_mitigation(test_microvm_with_initrd):
    """
    Test that SSBD mitigation is enabled.

    @type: security
    """
    vm = test_microvm_with_initrd
    vm.jailer.daemonize = False
    vm.spawn()
    vm.memory_monitor = None

    vm.basic_config(
        add_root_device=False,
        vcpu_count=1,
        boot_args='console=ttyS0 reboot=k panic=1 pci=off',
        use_initrd=True
    )

    vm.start()

    cmd = 'ps -T --no-headers -p {} | awk \'{{print $2}}\''.format(
        vm.jailer_clone_pid
    )
    process = run_cmd(cmd)
    threads_out_lines = process.stdout.splitlines()
    for tid in threads_out_lines:
        # Verify each thread's status
        cmd = 'cat /proc/{}/status | grep Speculation_Store_Bypass'.format(tid)
        _, output, _ = run_cmd(cmd)
        assert "thread force mitigated" in output or \
            "globally mitigated" in output
