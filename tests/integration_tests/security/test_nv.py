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


def test_no_nested_virtualization(uvm_any_booted):
    """Validate that guests don't have Nested Virtualization enabled."""
    uvm_any_booted.ssh.check_output("[ ! -e /dev/kvm ]")
