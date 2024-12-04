# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Test all vCPUs are configured correctly and work properly.

This test suite aims to catch bugs of Firecracker's vCPU configuration and
CPU templates especially under multi-vCPU setup, by checking that all vCPUs
are operating identically, except for the expected differences.
"""


def test_all_vcpus_online(uvm_any):
    """Check all vCPUs are online inside guest"""
    vm = uvm_any
    for idx in range(vm.vcpus_count):
        assert (
            vm.ssh.check_output(
                f"cat /sys/devices/system/cpu/cpu{idx}/online"
            ).stdout.strip()
            == "1"
        )
