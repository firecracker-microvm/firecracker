# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for adding the maximum number of devices to a microVM."""

import platform
import pytest
import host_tools.network as net_tools

# IRQs are available from 5 to 23, so the maximum number of devices
# supported at the same time is 19.
MAX_DEVICES_ATTACHED = 19


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Firecracker supports 24 IRQs on x86_64."
)
def test_attach_maximum_devices(test_microvm_with_ssh, network_config):
    """
    Test attaching maximum number of devices to the microVM.

    @type: functional
    """
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # Set up a basic microVM.
    test_microvm.basic_config()

    # Add (`MAX_DEVICES_ATTACHED` - 1) devices because the rootfs
    # has already been configured in the `basic_config()`function.
    guest_ips = []
    for i in range(MAX_DEVICES_ATTACHED - 1):
        # Create tap before configuring interface.
        _tap, _host_ip, guest_ip = test_microvm.ssh_network_config(
            network_config,
            str(i)
        )
        guest_ips.append(guest_ip)

    test_microvm.start()

    # Test that network devices attached are operational.
    for i in range(MAX_DEVICES_ATTACHED - 1):
        test_microvm.ssh_config['hostname'] = guest_ips[i]
        ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
        # Verify if guest can run commands.
        exit_code, _, _ = ssh_connection.execute_command("sync")
        assert exit_code == 0


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Firecracker supports 24 IRQs on x86_64."
)
def test_attach_too_many_devices(test_microvm_with_ssh, network_config):
    """
    Test attaching to a microVM more devices than available IRQs.

    @type: negative
    """
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # Set up a basic microVM.
    test_microvm.basic_config()

    # Add `MAX_DEVICES_ATTACHED` network devices on top of the
    # already configured rootfs.
    for i in range(MAX_DEVICES_ATTACHED):
        # Create tap before configuring interface.
        _tap, _host_ip, _guest_ip = test_microvm.ssh_network_config(
            network_config,
            str(i)
        )

    # Attempting to start a microVM with more than
    # `MAX_DEVICES_ATTACHED` devices should fail.
    response = test_microvm.actions.put(action_type='InstanceStart')
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "no more IRQs are available" in response.text
