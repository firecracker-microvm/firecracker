# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the /vm/kvm-stats resource."""

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.properties import global_props

HAS_BINARY_STATS = global_props.host_linux_version_tpl >= (5, 14)


def _total_exits(stats):
    return sum(vcpu["stats"]["exits"]["value"] for vcpu in stats["vcpus"])


def _check_stats(vm):
    stats = vm.api.vm_kvm_stats.get().json()
    assert [vcpu["index"] for vcpu in stats["vcpus"]] == [0, 1]
    for vcpu in stats["vcpus"]:
        assert vcpu["stats"]["exits"]["type"] == "cumulative"
        halt_wait = vcpu["stats"]["halt_wait_hist"]
        assert halt_wait["type"] == "log2-histogram"
        assert (halt_wait["unit"], halt_wait["base"], halt_wait["exponent"]) == (
            "seconds",
            10,
            -9,
        )
        assert isinstance(halt_wait["value"], list)

    # Each request rereads the stats, and the running guest keeps exiting.
    vm.ssh.check_output("true")
    assert _total_exits(vm.api.vm_kvm_stats.get().json()) > _total_exits(stats)


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_kvm_stats(uvm):
    """
    Check that KVM's binary statistics are served for the VM and each vCPU
    after boot, and refused before it.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config(vcpu_count=2)
    vm.add_net_iface()

    with pytest.raises(AssertionError):
        vm.api.vm_kvm_stats.get()

    vm.start()

    if not HAS_BINARY_STATS:
        with pytest.raises(AssertionError, match="Linux 5.14"):
            vm.api.vm_kvm_stats.get()
        return

    _check_stats(vm)


@pytest.mark.skipif(not HAS_BINARY_STATS, reason="Needs Linux 5.14 or later")
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_kvm_stats_after_restore(uvm, microvm_factory):
    """
    Check that KVM's binary statistics are served for a restored microVM.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config(vcpu_count=2)
    vm.add_net_iface()
    vm.start()

    restored = microvm_factory.build_from_snapshot(vm.snapshot_full())
    _check_stats(restored)
