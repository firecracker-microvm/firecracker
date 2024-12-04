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
    assert (
        uvm_any.ssh.check_output("cat /sys/devices/system/cpu/online").stdout.strip()
        == f"0-{uvm_any.vcpus_count - 1}"
    )
