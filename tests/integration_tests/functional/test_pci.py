# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the PCI devices"""


def test_pci_root_present(uvm_any_with_pci):
    """
    Test that a guest with PCI enabled has a PCI root device.
    """

    vm = uvm_any_with_pci
    devices = vm.ssh.run("lspci").stdout.strip().split("\n")
    print(devices)
    assert devices[0].startswith(
        "00:00.0 Host bridge: Intel Corporation Device"
    ), "PCI root not found in guest"


def test_pci_disabled(uvm_any_without_pci):
    """
    Test that a guest with PCI disabled does not have a PCI root device but still works.
    """

    vm = uvm_any_without_pci
    _, stdout, _ = vm.ssh.run("lspci")
    assert (
        "00:00.0 Host bridge: Intel Corporation Device" not in stdout
    ), "PCI root not found in guest"
