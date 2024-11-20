# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests ensuring nested virtualization is not present when using CPU templates.

We have tests that ensure CPU templates provide a consistent set of features in
the guest:

- file:../functional/test_cpu_features.py
- file:../functional/test_feat_parity.py
- Commit: 681e781f999e3390b6d46422a3c7b1a7e36e1b24

These already include the absence of VMX/SVM in the guest.

This test is a safety-net to make the test explicit and catch cases where we
start providing the feature by mistake.
"""

import pytest


@pytest.fixture
def uvm_with_cpu_template(microvm_factory, guest_kernel, rootfs, cpu_template_any):
    """A microvm fixture parametrized with all possible templates"""
    vm = microvm_factory.build(guest_kernel, rootfs)
    vm.spawn()
    cpu_template = None
    if isinstance(cpu_template_any, str):
        cpu_template = cpu_template_any
    vm.basic_config(cpu_template=cpu_template)
    if isinstance(cpu_template_any, dict):
        vm.api.cpu_config.put(**cpu_template_any["template"])
    vm.add_net_iface()
    vm.start()
    yield vm


def test_no_nv_when_using_cpu_templates(uvm_with_cpu_template):
    """
    Double-check that guests using CPU templates don't have Nested Virtualization
    enabled.
    """

    vm = uvm_with_cpu_template
    rc, _, _ = vm.ssh.run("[ ! -e /dev/kvm ]")
    assert rc == 0, "/dev/kvm exists"
