# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the `vcpu_registers` option of snapshot creation."""

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.utils import check_output, run_cmd
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend

# KVM-only: snapshotting is not available on enclave VMs.
pytestmark = pin_vm_backend(VM_BACKEND_KVM)


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_snapshot_vcpu_registers(uvm_configured, microvm_factory):
    """Check the snapshot pin and guest reachability across repeated same-host restores."""
    vm = uvm_configured
    vm.add_net_iface()
    vm.start()

    unpinned = vm.snapshot_full(vmstate_path="unpinned-vmstate")
    vm.resume()
    check_pin = [
        microvm_factory.binary_path / "snapshot-editor",
        "info-vmstate",
        "check-vcpu-register-pin",
        "--source-path",
    ]
    source = None
    for vcpu_registers in ["Pin", None, "Pin", None]:
        snapshot = vm.snapshot_full(vcpu_registers=vcpu_registers)
        if source is None:
            source = snapshot.vmstate
            rc, _, stderr = run_cmd(
                [*check_pin, source, "--vmstate-path", unpinned.vmstate]
            )
            assert rc != 0 and "not pinned" in stderr
        else:
            check_output([*check_pin, source, "--vmstate-path", snapshot.vmstate])
        vm.kill()
        vm = microvm_factory.build_from_snapshot(snapshot)
        vm.ssh.check_output("true")
