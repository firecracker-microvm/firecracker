# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for shutting down Firecracker/VM."""

import platform

from packaging import version

from framework import utils


def test_reboot(uvm_plain_any):
    """
    Test reboot from guest.
    """
    vm = uvm_plain_any
    vm.spawn()

    # We don't need to monitor the memory for this test because we are
    # just rebooting and the process dies before pmap gets the RSS.
    vm.memory_monitor = None

    # Set up the microVM with 4 vCPUs, 256 MiB of RAM, 0 network ifaces, and
    # a root file system with the rw permission. The network interfaces is
    # added after we get a unique MAC and IP.
    vm.basic_config(vcpu_count=4)
    vm.add_net_iface()
    vm.start()

    # Get Firecracker PID so we can count the number of threads.
    firecracker_pid = vm.firecracker_pid

    # Get number of threads in Firecracker
    cmd = "ps -o nlwp {} | tail -1 | awk '{{print $1}}'".format(firecracker_pid)
    _, stdout, _ = utils.check_output(cmd)
    nr_of_threads = stdout.rstrip()
    assert int(nr_of_threads) == 6

    # Consume existing metrics
    lines = vm.get_all_metrics()
    assert len(lines) == 1
    # Rebooting Firecracker sends an exit event and should gracefully kill.
    # the instance.
    vm.ssh.run("reboot")

    vm.mark_killed()

    # Consume existing metrics
    datapoints = vm.get_all_metrics()
    assert len(datapoints) == 2

    if platform.machine() != "x86_64":
        message = (
            "Received KVM_SYSTEM_EVENT: type: 2, event: [0]"
            if version.parse(utils.get_kernel_version()) >= version.parse("5.18")
            else "Received KVM_SYSTEM_EVENT: type: 2, event: []"
        )
        vm.check_log_message(message)
        vm.check_log_message("Vmm is stopping.")

    # Make sure that the FC process was not killed by a seccomp fault
    assert datapoints[-1]["seccomp"]["num_faults"] == 0
