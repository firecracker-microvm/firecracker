# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for shutting down Firecracker/VM."""
import os
import time
import json
import platform

from framework import utils

import host_tools.logging as log_tools
import host_tools.network as net_tools  # pylint: disable=import-error


def test_reboot(test_microvm_with_api, network_config):
    """
    Test reboot from guest.

    @type: functional
    """
    vm = test_microvm_with_api
    vm.jailer.daemonize = False
    vm.spawn()

    # We don't need to monitor the memory for this test because we are
    # just rebooting and the process dies before pmap gets the RSS.
    vm.memory_monitor = None

    # Set up the microVM with 4 vCPUs, 256 MiB of RAM, 0 network ifaces, and
    # a root file system with the rw permission. The network interfaces is
    # added after we get a unique MAC and IP.
    vm.basic_config(vcpu_count=4)
    _tap, _, _ = vm.ssh_network_config(network_config, '1')

    # Configure metrics system.
    metrics_fifo_path = os.path.join(vm.path, 'metrics_fifo')
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = vm.metrics.put(
        metrics_path=vm.create_jailed_resource(metrics_fifo.path)
    )
    assert vm.api_session.is_status_no_content(response.status_code)

    vm.start()

    # Get Firecracker PID so we can count the number of threads.
    firecracker_pid = vm.jailer_clone_pid

    # Get number of threads in Firecracker
    cmd = 'ps -o nlwp {} | tail -1 | awk \'{{print $1}}\''.format(
        firecracker_pid
    )
    _, stdout, _ = utils.run_cmd(cmd)
    nr_of_threads = stdout.rstrip()
    assert int(nr_of_threads) == 6

    # Consume existing metrics
    lines = metrics_fifo.sequential_reader(100)
    assert len(lines) == 1
    # Rebooting Firecracker sends an exit event and should gracefully kill.
    # the instance.
    ssh_connection = net_tools.SSHConnection(vm.ssh_config)

    ssh_connection.execute_command("reboot")

    while True:
        # Pytest's timeout will kill the test even if the loop doesn't exit.
        try:
            os.kill(firecracker_pid, 0)
            time.sleep(0.01)
        except OSError:
            break

    # Consume existing metrics
    lines = metrics_fifo.sequential_reader(100)
    assert len(lines) == 1

    if platform.machine() != "x86_64":
        vm.check_log_message("Received KVM_SYSTEM_EVENT: type: 2, event: 0")
        vm.check_log_message("Vmm is stopping.")

    # Make sure that the FC process was not killed by a seccomp fault
    assert json.loads(lines[0])["seccomp"]["num_faults"] == 0
