# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for FIPS-mode guest kernels.

Tests verify that:
1. FIPS reseeding is logged on snapshot restore
2. Kernel CSPRNGs are reseeded (diverge across restored VMs)
3. Userspace CSPRNGs are reseeded (diverge across restored VMs)
"""

import pytest

from framework.artifacts import (
    GUEST_KERNEL_DEFAULT,
    pin_guest_kernel,
    pin_pci,
    pin_rootfs_mode,
)

pytestmark = [
    pin_guest_kernel(GUEST_KERNEL_DEFAULT),
    pin_rootfs_mode("rw"),
    pin_pci(False),
]


@pytest.fixture
def uvm_with_fips(uvm):
    """Boot a microVM with FIPS mode enabled."""
    uvm.spawn()
    uvm.basic_config(boot_args="console=ttyS0 reboot=k panic=1 pci=off fips=1")
    uvm.add_net_iface()
    uvm.start()
    return uvm


@pytest.fixture
def fips_snapshot_pair(uvm_with_fips, microvm_factory):
    """Boot a FIPS VM, snapshot it, restore two VMs from the same snapshot."""
    snapshot = uvm_with_fips.snapshot_full()
    uvm_with_fips.kill()

    uvm_a = microvm_factory.build_from_snapshot(snapshot)
    uvm_b = microvm_factory.build_from_snapshot(snapshot)
    yield uvm_a, uvm_b


def test_fips_enabled(uvm_with_fips):
    """Test that FIPS mode is enabled in the guest kernel."""
    _, dmesg, _ = uvm_with_fips.ssh.run("dmesg | grep -i fips")
    assert "fips mode: enabled" in dmesg.lower()


def test_fips_rng_reseed_on_snapshot_restore(uvm_with_fips, microvm_factory):
    """Test that FIPS RNG reseeding is logged on snapshot restore."""
    snapshot = uvm_with_fips.snapshot_full()
    uvm_with_fips.kill()

    restored = microvm_factory.build_from_snapshot(snapshot)
    _, dmesg, _ = restored.ssh.run("dmesg | grep -i fips")
    assert "FIPS RNGs reseeded due to virtual machine fork" in dmesg


def _get_random_sequence(uvm, cmd):
    """Run a command on the VM and return its stripped stdout."""
    return uvm.ssh.check_output(cmd).stdout.strip()


def test_fips_reseeded_kernel_csprng(fips_snapshot_pair):
    """Test that kernel CSPRNG diverges across VMs restored from the same snapshot."""
    uvm_a, uvm_b = fips_snapshot_pair
    cmd = "head -c 32 /dev/urandom | base64"

    seq_a = _get_random_sequence(uvm_a, cmd)
    seq_b = _get_random_sequence(uvm_b, cmd)

    assert (
        seq_a != seq_b
    ), "Kernel CSPRNG produced identical output on two VMs restored from the same snapshot"


def test_fips_reseeded_userspace_csprng(fips_snapshot_pair):
    """Test that userspace CSPRNG diverges across VMs restored from the same snapshot."""
    uvm_a, uvm_b = fips_snapshot_pair
    cmd = 'python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"'

    seq_a = _get_random_sequence(uvm_a, cmd)
    seq_b = _get_random_sequence(uvm_b, cmd)

    assert (
        seq_a != seq_b
    ), "Userspace CSPRNG produced identical output on two VMs restored from the same snapshot"
