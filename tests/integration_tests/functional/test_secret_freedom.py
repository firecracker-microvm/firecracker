# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test secret-freedom related functionality."""

import platform

import pytest

from framework import defs
from framework.microvm import Serial
from framework.properties import global_props
from integration_tests.performance.test_initrd import INITRD_FILESYSTEM

pytestmark = [
    pytest.mark.skipif(
        global_props.host_linux_version_metrics != "next",
        reason="Secret Freedom is only supported on the in-dev upstream kernels for now",
    ),
    pytest.mark.skipif(
        global_props.instance == "m6g.metal",
        reason="Secret Freedom currently only works on ARM hardware conforming to at least ARMv8.4 as absense of ARM64_HAS_STAGE2_FWB causes kernel panics because of dcache flushing during stage2 page table entry installation",
    ),
]


@pytest.mark.skipif(
    platform.machine() != "aarch64",
    reason="only ARM can boot secret free VMs with I/O devices",
)
def test_secret_free_boot(microvm_factory, guest_kernel_linux_6_1, rootfs):
    """Tests that a VM can boot if all virtio devices are bound to a swiotlb region, and
    that this swiotlb region is actually discovered by the guest."""
    vm = microvm_factory.build(guest_kernel_linux_6_1, rootfs)
    vm.spawn()
    vm.memory_monitor = None
    vm.basic_config(memory_config={"initial_swiotlb_size": 8, "secret_free": True})
    vm.add_net_iface()
    vm.start()


def test_secret_free_initrd(microvm_factory, guest_kernel):
    """
    Test that we can boot a secret hidden initrd (e.g. a VM with no I/O devices)
    """
    fs = defs.ARTIFACT_DIR / "initramfs.cpio"
    uvm = microvm_factory.build(guest_kernel)
    uvm.initrd_file = fs
    uvm.help.enable_console()
    uvm.spawn()
    uvm.memory_monitor = None

    uvm.basic_config(
        add_root_device=False,
        vcpu_count=1,
        boot_args="console=ttyS0 reboot=k panic=1 pci=off no-kvmclock",
        use_initrd=True,
        memory_config={"initial_swiotlb_size": 64, "secret_free": True},
    )

    uvm.start()
    serial = Serial(uvm)
    serial.open()
    serial.rx(token="# ")
    serial.tx("mount |grep rootfs")
    serial.rx(token=f"rootfs on / type {INITRD_FILESYSTEM}")


@pytest.mark.skipif(
    platform.machine() != "aarch64",
    reason="only ARM can boot secret free VMs with I/O devices",
)
def test_secret_free_snapshot_creation(microvm_factory, guest_kernel_linux_6_1, rootfs):
    """Test that snapshot creation works for secret hidden VMs"""
    vm = microvm_factory.build(guest_kernel_linux_6_1, rootfs)
    vm.spawn()
    vm.memory_monitor = None
    vm.basic_config(memory_config={"initial_swiotlb_size": 8, "secret_free": True})
    vm.add_net_iface()
    vm.start()

    snapshot = vm.snapshot_full()

    # After restoration, the VM will not be secret hidden anymore, as that's not supported yet.
    # But we can at least test that in principle, the snapshot creation worked.
    vm = microvm_factory.build_from_snapshot(snapshot)
    vm.ssh.check_output("true")
