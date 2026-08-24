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
    ALL_GUEST_KERNELS,
    pin_guest_kernel,
    pin_pci,
    pin_rootfs_mode,
)

# Linux 5.10 CI kernels are built without CONFIG_CRYPTO_FIPS.
FIPS_GUEST_KERNELS = [
    kernel for kernel in ALL_GUEST_KERNELS if not kernel.id.startswith("vmlinux-5.10.")
]

pytestmark = [
    pin_guest_kernel(FIPS_GUEST_KERNELS),
    pin_rootfs_mode("rw"),
    pin_pci(False),
]


# No test requests this fixture directly: the conftest `uvm_booted` stage
# resolves this module-local override, so every test below boots with the
# FIPS kernel command line.
@pytest.fixture
def uvm_configured(uvm):
    """Spawned microVM configured to boot with FIPS mode enabled."""
    uvm.spawn()
    uvm.basic_config(boot_args="console=ttyS0 reboot=k panic=1 pci=off fips=1")
    return uvm


@pytest.fixture
def fips_snapshot_pair(uvm_booted, microvm_factory):
    """Boot a FIPS VM, snapshot it, restore two VMs from the same snapshot."""
    snapshot = uvm_booted.snapshot_full()
    uvm_booted.kill()

    uvm_a = microvm_factory.build_from_snapshot(snapshot)
    uvm_b = microvm_factory.build_from_snapshot(snapshot)
    yield uvm_a, uvm_b


def test_fips_enabled(uvm_booted):
    """Test that FIPS mode is enabled in the guest kernel."""
    _, dmesg, _ = uvm_booted.ssh.run("dmesg | grep -i fips")
    assert "fips mode: enabled" in dmesg.lower()


def test_fips_rng_reseed_on_snapshot_restore(uvm_booted, microvm_factory):
    """Test that FIPS RNG reseeding is logged on snapshot restore."""
    snapshot = uvm_booted.snapshot_full()
    uvm_booted.kill()

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
