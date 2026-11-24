# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the `vcpu_registers` option of snapshot creation."""

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend

# KVM-only: snapshotting is not available on enclave VMs.
pytestmark = pin_vm_backend(VM_BACKEND_KVM)


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_snapshot_vcpu_registers(uvm_configured, microvm_factory):
    """Verify the guest stays reachable after each restore in a same-host pinning cycle."""
    vm = uvm_configured
    vm.add_net_iface()
    vm.start()

    for vcpu_registers in ["Pin", None, "Pin", None]:
        snapshot = vm.snapshot_full(vcpu_registers=vcpu_registers)
        vm.kill()
        vm = microvm_factory.build_from_snapshot(snapshot)
        vm.ssh.check_output("true")
