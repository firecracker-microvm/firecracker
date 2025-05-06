# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the --seccomp-filter parameter works as expected."""

import platform
import time
from pathlib import Path

import requests

from framework import utils


def install_filter(microvm, bpf_path):
    """Install seccomp filter in microvm."""
    microvm.create_jailed_resource(bpf_path)
    microvm.jailer.extra_args.update({"seccomp-filter": bpf_path.name})


def test_allow_all(uvm_plain, seccompiler):
    """Test --seccomp-filter, allowing all syscalls."""
    seccomp_filter = {
        thread: {"default_action": "allow", "filter_action": "trap", "filter": []}
        for thread in ["vmm", "api", "vcpu"]
    }

    bpf_path = seccompiler.compile(seccomp_filter)
    test_microvm = uvm_plain
    install_filter(test_microvm, bpf_path)
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.start()
    utils.assert_seccomp_level(test_microvm.firecracker_pid, "2")


def test_working_filter(uvm_plain, seccompiler):
    """Test --seccomp-filter, rejecting some dangerous syscalls."""

    seccomp_filter = {
        thread: {
            "default_action": "allow",
            "filter_action": "kill_process",
            "filter": [{"syscall": "clone"}, {"syscall": "execve"}],
        }
        for thread in ["vmm", "api", "vcpu"]
    }

    bpf_path = seccompiler.compile(seccomp_filter)
    test_microvm = uvm_plain
    install_filter(test_microvm, bpf_path)
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.start()

    # level should be 2, with no additional errors
    utils.assert_seccomp_level(test_microvm.firecracker_pid, "2")


def test_failing_filter(uvm_plain, seccompiler):
    """Test --seccomp-filter, denying some needed syscalls."""

    seccomp_filter = {
        "vmm": {"default_action": "allow", "filter_action": "trap", "filter": []},
        "api": {"default_action": "allow", "filter_action": "trap", "filter": []},
        "vcpu": {
            "default_action": "allow",
            "filter_action": "trap",
            "filter": [{"syscall": "ioctl"}],
        },
    }

    bpf_path = seccompiler.compile(seccomp_filter)
    test_microvm = uvm_plain
    install_filter(test_microvm, bpf_path)
    test_microvm.spawn()
    test_microvm.basic_config(vcpu_count=1)

    # Try to start the VM with error checking off, because it will fail.
    try:
        test_microvm.start()
    except requests.exceptions.ConnectionError:
        pass

    # Give time for the process to get killed
    time.sleep(1)

    # Check the logger output
    ioctl_num = 16 if platform.machine() == "x86_64" else 29
    test_microvm.check_log_message(
        f"Shutting down VM after intercepting a bad syscall ({ioctl_num})"
    )

    # Check the metrics
    datapoints = test_microvm.get_metrics()
    num_faults = 0
    for datapoint in datapoints:
        num_faults += datapoint["seccomp"]["num_faults"]
        # exit early to avoid potentially broken JSON entries in the logs
        if num_faults > 0:
            break

    assert num_faults == 1

    test_microvm.mark_killed()


def test_invalid_bpf(uvm_plain):
    """Test that FC does not start, given an invalid binary filter."""
    test_microvm = uvm_plain

    # Configure VM from JSON. Otherwise, the test will error because
    # the process will be killed before configuring the API socket.
    test_microvm.create_jailed_resource(test_microvm.kernel_file)
    test_microvm.create_jailed_resource(test_microvm.rootfs_file)

    vm_config_file = Path("framework/vm_config.json")
    test_microvm.create_jailed_resource(vm_config_file)
    test_microvm.jailer.extra_args = {"config-file": vm_config_file.name}
    test_microvm.jailer.extra_args.update({"no-api": None})

    bpf_path = Path(test_microvm.path) / "bpf.out"
    bpf_path.write_bytes(b"Invalid BPF!")
    test_microvm.create_jailed_resource(bpf_path)
    test_microvm.jailer.extra_args.update({"seccomp-filter": bpf_path.name})

    test_microvm.spawn()
    # give time for the process to get killed
    time.sleep(1)
    assert "Seccomp error: Filter deserialization failed" in test_microvm.log_data

    test_microvm.mark_killed()
