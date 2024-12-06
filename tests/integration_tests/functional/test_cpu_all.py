# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Test all vCPUs are configured correctly and work properly.

This test suite aims to catch bugs of Firecracker's vCPU configuration and
CPU templates especially under multi-vCPU setup, by checking that all vCPUs
are operating identically, except for the expected differences.
"""

import pytest

# Use the maximum number of vCPUs supported by Firecracker
MAX_VCPUS = 32


@pytest.mark.parametrize("vcpu_count", [MAX_VCPUS])
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


@pytest.mark.parametrize("vcpu_count", [MAX_VCPUS])
def test_all_vcpus_have_same_features(uvm_any):
    """
    Check all vCPUs have the same features inside guest.

    This test ensures Firecracker or CPU templates don't configure CPU features
    differently between vCPUs.

    Note that whether the shown CPU features are expected or not should be
    tested in (arch-specific) test_cpu_features_*.py only for vCPU 0. Thus, we
    only test the equivalence of all CPUs in the same guest.
    """
    vm = uvm_any

    # Get features of all CPUs
    features = vm.ssh.check_output(
        "cat /proc/cpuinfo | grep Features"
    ).stdout.splitlines()
    for idx in range(1, vm.vcpus_count):
        assert features[0] == features[idx]
