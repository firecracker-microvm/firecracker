# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for verifying the PVTime device is enabled on aarch64."""

import pytest

from framework.properties import global_props


@pytest.mark.skipif(
    global_props.cpu_architecture != "aarch64", reason="Only run in aarch64"
)
def test_guest_has_pvtime_enabled(uvm_plain):
    """
    Check that the guest kernel has enabled PV steal time.
    """
    vm = uvm_plain
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    vm.start()

    _, stdout, _ = vm.ssh.run("dmesg | grep 'stolen time PV'")
    assert (
        "stolen time PV" in stdout
    ), "Guest kernel did not report PV steal time enabled"
