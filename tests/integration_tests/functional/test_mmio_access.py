# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests invalid writes to MMIO config space don't panic."""

import host_tools.network as net_tools


def test_mmio_invalid_write(test_microvm_with_ssh, network_config,
                            mmio_config_update_bin):
    """Test invalid write to MMIO config space.

    If a write from within the guest to MMIO config space has
    a length smaller than that space, we should not panic
    (config space won't be updated).
    """
    microvm = test_microvm_with_ssh
    microvm.spawn()

    microvm.basic_config()
    # Configure a network interface.
    _tap, _, _ = microvm.ssh_network_config(network_config, '1')

    microvm.start()

    conn = net_tools.SSHConnection(microvm.ssh_config)

    write_mmio_path = mmio_config_update_bin
    conn.scp_file(write_mmio_path, 'mmio_write')
    cmd = "chmod u+x mmio_write && ./mmio_write"
    # This should be executed successfully.
    _, stdout, stderr = conn.execute_command(cmd)

    assert stderr.read() == ''
    assert stdout.read() == 'Finished.\n'

    # Validate the microVM is still up and running.
    cmd = "ls"
    _, stdout, stderr = conn.execute_command(cmd)
    assert stderr.read() == ""
    assert stdout.read().strip() == "mmio_write"
