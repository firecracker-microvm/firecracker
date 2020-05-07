# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for pausing/resuming a microVM."""

import host_tools.network as net_tools


def test_pause_resume(test_microvm_with_ssh, network_config):
    """Test pausing and resuming the vCPUs."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM and a root file
    # system with the rw permission.
    test_microvm.basic_config()

    # Create tap before configuring interface.
    _tap1, _, _ = test_microvm.ssh_network_config(network_config, '1')

    # Pausing the microVM before being started is not allowed.
    response = test_microvm.vm.patch(state='Paused')
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    # Resuming the microVM before being started is also not allowed.
    response = test_microvm.vm.patch(state='Resumed')
    assert test_microvm.api_session.is_status_bad_request(response.status_code)

    # Start microVM.
    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Verify guest is active.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code == 0

    # Pausing the microVM after it's been started is successful.
    response = test_microvm.vm.patch(state='Paused')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Verify guest is no longer active.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code != 0

    # Pausing the microVM when it is already `Paused` is allowed
    # (microVM remains in `Paused` state).
    response = test_microvm.vm.patch(state='Paused')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Resuming the microVM is successful.
    response = test_microvm.vm.patch(state='Resumed')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Verify guest is active again.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code == 0

    # Resuming the microVM when it is already `Resumed` is allowed
    # (microVM remains in the running state).
    response = test_microvm.vm.patch(state='Resumed')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Verify guest is still active.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code == 0
