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
    assert (
        uvm_any.ssh.check_output("cat /sys/devices/system/cpu/online").stdout.strip()
        == f"0-{uvm_any.vcpus_count - 1}"
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
    # Get a feature set for each CPU and deduplicate them.
    unique_feature_lists = uvm_any.ssh.check_output(
        'grep -E "^(flags|Features)" /proc/cpuinfo | uniq'
    ).stdout.splitlines()
    assert len(unique_feature_lists) == 1
