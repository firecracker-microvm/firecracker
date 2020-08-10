# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for Firecracker signal handling."""

import os
from signal import SIGBUS, SIGRTMIN, SIGSEGV
from time import sleep

import pytest

import host_tools.network as net_tools


@pytest.mark.parametrize(
    "signum",
    [SIGBUS, SIGSEGV]
)
def test_sigbus_sigsegv(test_microvm_with_api, signum):
    """Test signal handling for `SIGBUS` and `SIGSEGV`."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # We don't need to monitor the memory for this test.
    test_microvm.memory_monitor = None

    test_microvm.basic_config()

    test_microvm.start()
    firecracker_pid = int(test_microvm.jailer_clone_pid)

    sleep(0.5)
    os.kill(firecracker_pid, signum)

    msg = 'Shutting down VM after intercepting signal {}'.format(signum)

    test_microvm.check_log_message(msg)


def test_handled_signals(test_microvm_with_ssh, network_config):
    """Test that handled signals don't kill the microVM."""
    microvm = test_microvm_with_ssh
    microvm.spawn()

    # We don't need to monitor the memory for this test.
    microvm.memory_monitor = None

    microvm.basic_config(vcpu_count=2)

    # Configure a network interface.
    _tap, _, _ = microvm.ssh_network_config(network_config, '1')

    microvm.start()
    firecracker_pid = int(microvm.jailer_clone_pid)

    # Open a SSH connection to validate the microVM stays alive.
    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)
    # Just validate a simple command: `nproc`
    cmd = "nproc"
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert stderr.read() == ""
    assert int(stdout.read()) == 2

    # We have a handler installed for this signal.
    os.kill(firecracker_pid, SIGRTMIN+1)

    # Validate the microVM is still up and running.
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert stderr.read() == ""
    assert int(stdout.read()) == 2
