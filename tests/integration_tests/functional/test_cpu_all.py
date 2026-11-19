# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Test all vCPUs are configured correctly and work properly.

This test suite aims to catch bugs of Firecracker's vCPU configuration and
CPU templates especially under multi-vCPU setup, by checking that all vCPUs
are operating identically, except for the expected differences.
"""

import pytest

from framework.utils import CpuMap
from framework.utils_cpu_templates import ALL_CPU_TEMPLATES, pin_cpu_template

# Not pinned: templated variants are deselected on enclaves at collection, and
# the no-template ones run everywhere.
pytestmark = [pin_cpu_template(ALL_CPU_TEMPLATES)]

# Guest kernels are built with CONFIG_NR_CPUS=64, so a guest onlines at most 64.
MAX_GUEST_VCPUS = 64


# Shadows the shared dimension: the ceiling is backend-specific, and only known
# once the backend is. Deliberately a fixture rather than a parametrize, so the
# host's CPU count does not leak into test IDs.
@pytest.fixture
def vcpu_count(vm_backend):
    """The most vCPUs this backend can be given on this host."""
    if not vm_backend.is_enclave:
        # KVM caps at MAX_SUPPORTED_KVM_VCPUS.
        return min(CpuMap.len(), 32)
    # An enclave goes above the KVM cap, but this one asks for no NUMA placement
    # and so lands wholly on parent node 0. test_enclave_max_vcpus covers a
    # host-sized count spread over every node.
    return min(CpuMap.node_len(), MAX_GUEST_VCPUS)


def test_all_vcpus_online(uvm_any):
    """Check all vCPUs are online inside guest"""
    assert (
        uvm_any.ssh.check_output("cat /sys/devices/system/cpu/online").stdout.strip()
        == f"0-{uvm_any.vcpus_count - 1}"
    )


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
