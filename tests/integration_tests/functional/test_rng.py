# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the virtio-rng device"""

from pathlib import Path

import pytest

from framework.artifacts import NetIfaceConfig
from framework.properties import get_kernel_version
from framework.utils import check_entropy
from framework.utils_cpuid import get_instance_type

INSTANCE_TYPE = get_instance_type()
HOST_KERNEL = get_kernel_version(level=2)


def _microvm_basic_config(microvm):
    microvm.spawn()
    microvm.basic_config()
    iface = NetIfaceConfig()
    microvm.add_net_iface(iface)


def _microvm_rng_config(microvm):
    _microvm_basic_config(microvm)
    microvm.entropy.put()


def _start_vm_with_rng(microvm):
    _microvm_rng_config(microvm)
    microvm.start()


def _start_vm_without_rng(microvm):
    _microvm_basic_config(microvm)
    microvm.start()


@pytest.mark.skipif(
    INSTANCE_TYPE == "c7g.metal" and HOST_KERNEL == "4.14",
    reason="c7g requires no SVE 5.10 kernel",
)
def test_rng_not_present(test_microvm_with_rng):
    """
    Test a guest microVM *without* an entropy device and ensure that
    we cannot get data from /dev/hwrng
    """

    vm = test_microvm_with_rng
    _start_vm_without_rng(vm)

    # If the guest kernel has been built with the virtio-rng module
    # the device should exist in the guest filesystem but we should
    # not be able to get random numbers out of it.
    cmd = "test -e /dev/hwrng"
    ecode, _, _ = vm.ssh.execute_command(cmd)
    assert ecode == 0

    cmd = "dd if=/dev/hwrng of=/dev/null bs=10 count=1"
    ecode, _, _ = vm.ssh.execute_command(cmd)
    assert ecode == 1


@pytest.mark.skipif(
    INSTANCE_TYPE == "c7g.metal" and HOST_KERNEL == "4.14",
    reason="c7g requires no SVE 5.10 kernel",
)
def test_rng_present(test_microvm_with_rng):
    """
    Test a guest microVM with an entropy defined configured and ensure
    that we can access `/dev/hwrng`

    @type: functional
    """

    vm = test_microvm_with_rng
    _start_vm_with_rng(vm)

    check_entropy(vm.ssh)


@pytest.mark.skipif(
    INSTANCE_TYPE == "c7g.metal" and HOST_KERNEL == "4.14",
    reason="c7g requires no SVE 5.10 kernel",
)
def test_rng_snapshot(test_microvm_with_rng, microvm_factory):
    """
    Test that a virtio-rng device is functional after resuming from
    a snapshot

    @type: functional
    """

    vm = test_microvm_with_rng
    _start_vm_with_rng(vm)

    check_entropy(vm.ssh)

    mem_path = Path(vm.jailer.chroot_path()) / "test.mem"
    snapshot_path = Path(vm.jailer.chroot_path()) / "test.snap"
    vm.pause_to_snapshot(
        mem_file_path=mem_path.name,
        snapshot_path=snapshot_path.name,
    )
    assert mem_path.exists()

    new_vm = microvm_factory.build()
    new_vm.spawn()
    iface = NetIfaceConfig()
    new_vm.create_tap_and_ssh_config(
        host_ip=iface.host_ip,
        guest_ip=iface.guest_ip,
        netmask_len=iface.netmask,
        tapname=iface.tap_name,
    )
    new_vm.ssh_config["ssh_key_path"] = vm.ssh_config["ssh_key_path"]
    new_vm.restore_from_snapshot(
        snapshot_vmstate=snapshot_path,
        snapshot_mem=mem_path,
        snapshot_disks=[vm.rootfs_file],
    )

    check_entropy(new_vm.ssh)
