# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for snapshot-editor tool."""

import platform

import pytest

import host_tools.cargo_build as host
from framework import utils

PLATFORM = platform.machine()
MIDR_EL1 = hex(0x603000000013C000)


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
def test_remove_regs(uvm_nano, microvm_factory):
    """
    This test verifies `remove-regs` method of `snapshot-editor`.
    Here we create snapshot and try to romeve MIDR_EL1 register
    from it. Then we try to restore uVM from the snapshot.
    """

    vm = uvm_nano
    vm.add_net_iface()
    vm.start()

    snapshot = vm.snapshot_full()

    snap_editor = host.get_binary("snapshot-editor")

    # Test that MIDR_EL1 is in the snapshot
    cmd = [
        str(snap_editor),
        "info-vmstate",
        "vcpu-states",
        "--vmstate-path",
        str(snapshot.vmstate),
    ]
    _, stdout, _ = utils.check_output(cmd)
    assert MIDR_EL1 in stdout

    # Remove MIDR_EL1 register from the snapshot
    cmd = [
        str(snap_editor),
        "edit-vmstate",
        "remove-regs",
        "--vmstate-path",
        str(snapshot.vmstate),
        "--output-path",
        str(snapshot.vmstate),
        str(MIDR_EL1),
    ]
    utils.check_output(cmd)

    # Test that MIDR_EL1 is not in the snapshot
    cmd = [
        str(snap_editor),
        "info-vmstate",
        "vcpu-states",
        "--vmstate-path",
        str(snapshot.vmstate),
    ]
    _, stdout, _ = utils.check_output(cmd)
    assert MIDR_EL1 not in stdout

    # test that we can restore from a snapshot
    new_vm = microvm_factory.build()
    new_vm.spawn()
    new_vm.restore_from_snapshot(snapshot, resume=True)
    new_vm.wait_for_up()
