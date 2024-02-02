# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for microvms with max vcpus(32)."""

MAX_VCPUS = 32


def test_max_vcpus(uvm_plain):
    """
    Test if all configured guest vcpus are online.
    """
    microvm = uvm_plain
    microvm.spawn()

    # Configure a microVM with 32 vCPUs.
    microvm.basic_config(vcpu_count=MAX_VCPUS)
    microvm.add_net_iface()
    microvm.start()

    cmd = "nproc"
    _, stdout, stderr = microvm.ssh.run(cmd)
    assert stderr == ""
    assert int(stdout) == MAX_VCPUS
