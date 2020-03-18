# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for Firecracker signal handling."""

import os
from signal import SIGBUS, SIGRTMIN, SIGSEGV
from time import sleep

import pytest

import host_tools.logging as log_tools
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
    test_microvm.memory_events_queue = None

    test_microvm.basic_config()

    # Configure logging.
    log_fifo_path = os.path.join(test_microvm.path, 'log_fifo')
    log_fifo = log_tools.Fifo(log_fifo_path)
    response = test_microvm.logger.put(
        log_fifo=test_microvm.create_jailed_resource(log_fifo_path),
        level='Error',
        show_level=False,
        show_log_origin=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()
    firecracker_pid = int(test_microvm.jailer_clone_pid)

    sleep(0.5)
    os.kill(firecracker_pid, signum)

    msg = 'Shutting down VM after intercepting signal {}'.format(signum)
    log_fifo.flags = log_fifo.flags & ~os.O_NONBLOCK
    lines = log_fifo.sequential_reader(5)

    msg_found = False
    for line in lines:
        if msg in line:
            msg_found = True
            break
    assert msg_found


def test_handled_signals(test_microvm_with_ssh, network_config):
    """Test that handled signals don't kill the microVM."""
    microvm = test_microvm_with_ssh
    microvm.spawn()

    # We don't need to monitor the memory for this test.
    microvm.memory_events_queue = None

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
    assert stderr.read().decode("utf-8") == ""
    assert int(stdout.read().decode("utf-8")) == 2

    # We have a handler installed for this signal.
    os.kill(firecracker_pid, SIGRTMIN+1)

    # Validate the microVM is still up and running.
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert stderr.read().decode("utf-8") == ""
    assert int(stdout.read().decode("utf-8")) == 2
