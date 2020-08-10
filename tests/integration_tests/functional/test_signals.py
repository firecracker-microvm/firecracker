# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for Firecracker signal handling."""

import json
import os
from signal import \
    (SIGBUS, SIGRTMIN, SIGSEGV, SIGXFSZ,
     SIGXCPU, SIGPIPE, SIGHUP, SIGILL)
from time import sleep
import resource as res
import pytest

import host_tools.network as net_tools
import framework.utils as utils

signum_str = {
    SIGBUS: "sigbus",
    SIGSEGV: "sigsegv",
    SIGXFSZ: "sigxfsz",
    SIGXCPU: "sigxcpu",
    SIGPIPE: "sigpipe",
    SIGHUP: "sighup",
    SIGILL: "sigill",
}


@pytest.mark.parametrize(
    "signum",
    [SIGBUS, SIGSEGV, SIGXFSZ, SIGXCPU, SIGPIPE, SIGHUP, SIGILL]
)
def test_generic_signal_handler(test_microvm_with_api, signum):
    """Test signal handling for all handled signals."""
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


def test_sigxfsz_handler(test_microvm_with_api):
    """Test intercepting and handling SIGXFSZ."""
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

    metrics_jail_path = os.path.join(microvm.jailer.chroot_path(),
                                     metrics_path)
    metrics_fd = open(metrics_jail_path)
    line_metrics = metrics_fd.readlines()
    print(line_metrics)
    assert len(line_metrics) == 1

    firecracker_pid = int(microvm.jailer_clone_pid)
    size = os.path.getsize(metrics_jail_path)
    # The SIGXFSZ is triggered because the size of rootfs is bigger than
    # the size of metrics file times 3. Since the metrics file is flushed
    # twice we have to make sure that the limit is bigger than that
    # in order to make sure the SIGXFSZ metric is logged
    res.prlimit(firecracker_pid, res.RLIMIT_FSIZE, (size*3, res.RLIM_INFINITY))

    while True:
        try:
            utils.run_cmd("ps -p {}".format(firecracker_pid))
            sleep(1)
        except ChildProcessError:
            break

    msg = 'Shutting down VM after intercepting signal 25, code 0'
    microvm.check_log_message(msg)
    metric_line = json.loads(metrics_fd.readlines()[0])
    assert metric_line["signals"]["sigxfsz"] == 1


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
