# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test swiotlb related functionality."""
import re

import pytest

from framework.properties import global_props

pytestmark = pytest.mark.skipif(
    global_props.cpu_architecture != "aarch64", reason="swiotlb only supported on ARM"
)


@pytest.mark.parametrize("swiotlb_size", [1, 64])
def test_swiotlb_boot(microvm_factory, guest_kernel_linux_6_1, rootfs, swiotlb_size):
    """Tests that a VM can boot if all virtio devices are bound to a swiotlb region, and
    that this swiotlb region is actually discovered by the guest."""
    vm = microvm_factory.build(guest_kernel_linux_6_1, rootfs)
    vm.spawn()
    vm.basic_config(memory_config={"initial_swiotlb_size": swiotlb_size})
    vm.add_net_iface()
    vm.start()

    _, dmesg, _ = vm.ssh.check_output("dmesg")

    assert (
        "OF: reserved mem: initialized node bouncy_boi, compatible id restricted-dma-pool"
        in dmesg
    )

    match = re.search(r"Placed swiotlb region at \[(\d+), (\d+)\)", vm.log_data)

    assert match is not None, "Firecracker did not print swiotlb region placement"

    swiotlb_start, swiotlb_end = match.group(1, 2)

    found_any = False

    for match in re.finditer(
        r"Placed virt queue ([a-zA-Z ]+) at \[(\d+), (\d+)\)", vm.log_data
    ):
        found_any = True
        component, start, end = match.group(1, 2, 3)

        assert (
            start >= swiotlb_start and end <= swiotlb_end
        ), f"Guest placed virtio queue component {component} outside of swiotlb region!"

    assert found_any, "Did not find any virtio devices in Firecracker logs"


def test_swiotlb_snapshot(microvm_factory, guest_kernel_linux_6_1, rootfs):
    """Tests that a VM with swiotlb regions attached can be snapshotted and restored
    again, and that the restored VM can still do I/O."""
    vm = microvm_factory.build(guest_kernel_linux_6_1, rootfs)
    vm.spawn()
    vm.basic_config(memory_config={"initial_swiotlb_size": 64})
    vm.add_net_iface()
    vm.start()
    snapshot = vm.snapshot_full()
    vm.kill()

    vm = microvm_factory.build_from_snapshot(snapshot)

    vm.ssh.check_output("true")
