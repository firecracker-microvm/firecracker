# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for Firecracker signal handling."""

import json
import os
from signal import SIGBUS, SIGRTMIN, SIGSEGV
from time import sleep
import pytest

import host_tools.network as net_tools
import framework.utils as utils

signum_str = {
    SIGBUS: "sigbus",
    SIGSEGV: "sigsegv",
}


@pytest.mark.parametrize(
    "signum",
    [SIGBUS, SIGSEGV]
)
def test_sigbus_sigsegv(test_microvm_with_api, signum):
    """Test signal handling for `SIGBUS` and `SIGSEGV`."""
    microvm = test_microvm_with_api
    microvm.spawn()

    # We don't need to monitor the memory for this test.
    microvm.memory_monitor = None

    microvm.basic_config()

    # Configure metrics based on a file.
    metrics_path = os.path.join(microvm.path, 'metrics_fifo')
    utils.run_cmd("touch {}".format(metrics_path))
    response = microvm.metrics.put(
        metrics_path=microvm.create_jailed_resource(metrics_path)
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    microvm.start()
    firecracker_pid = int(microvm.jailer_clone_pid)
    sleep(0.5)

    metrics_jail_path = os.path.join(microvm.chroot(), metrics_path)
    metrics_fd = open(metrics_jail_path)

    line_metrics = metrics_fd.readlines()
    assert len(line_metrics) == 1

    os.kill(firecracker_pid, signum)
    msg = 'Shutting down VM after intercepting signal {}'.format(signum)

    microvm.check_log_message(msg)

    metric_line = json.loads(metrics_fd.readlines()[0])
    assert metric_line["signals"][signum_str[signum]] == 1


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
