# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for microvms with max vcpus(32)."""
import host_tools.network as net_tools  # pylint: disable=import-error

MAX_VCPUS = 32


def test_max_vcpus(test_microvm_with_ssh, network_config):
    """Test if all configured guest vcpus are online."""
    microvm = test_microvm_with_ssh
    microvm.spawn()

    # Configure a microVM with 32 vCPUs.
    microvm.basic_config(vcpu_count=MAX_VCPUS)
    _tap, _, _ = microvm.ssh_network_config(network_config, '1')

    microvm.start()

    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)
    cmd = "nproc"
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert stderr.read().decode("utf-8") == ""
    assert int(stdout.read().decode("utf-8")) == MAX_VCPUS
