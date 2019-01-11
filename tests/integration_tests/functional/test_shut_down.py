# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for shutting down Firecracker/VM."""
import os

from subprocess import run, PIPE
import time

import host_tools.network as net_tools  # pylint: disable=import-error


def test_reboot(test_microvm_with_ssh, network_config):
    """Test reboot from guest kernel."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    # We don't need to monitor the memory for this test because we are
    # just rebooting and the process dies before pmap gets the RSS.
    test_microvm.memory_events_queue = None

    # Set up the microVM with 4 vCPUs, 256 MiB of RAM, 0 network ifaces, and
    # a root file system with the rw permission. The network interfaces is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config(vcpu_count=4)
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')

    test_microvm.start()

    # Get Firecracker PID so we can count the number of threads.
    firecracker_pid = test_microvm.jailer_clone_pid

    # Get number of threads in Firecracker
    cmd = 'ps -o nlwp {} | tail -1 | awk \'{{print $1}}\''.format(
        firecracker_pid
    )
    process = run(cmd, stdout=PIPE, stderr=PIPE, shell=True, check=True)
    nr_of_threads = process.stdout.decode('utf-8').rstrip()
    assert int(nr_of_threads) == 6

    # Rebooting Firecracker sends an exit event and should gracefully kill.
    # the instance.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    ssh_connection.execute_command("reboot")

    while True:
        # Pytest's timeout will kill the test even if the loop doesn't exit.
        try:
            os.kill(firecracker_pid, 0)
            time.sleep(0.01)
        except OSError:
            break
