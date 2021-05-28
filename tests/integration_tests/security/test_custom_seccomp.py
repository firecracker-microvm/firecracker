# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the --seccomp-filter parameter works as expected."""

import os
import platform
import json
import tempfile
import time
import psutil
import pytest
import framework.utils as utils
import host_tools.logging as log_tools

from host_tools.cargo_build import run_seccompiler


def _custom_filter_setup(test_microvm, json_filter):
    json_temp = tempfile.NamedTemporaryFile(delete=False)
    json_temp.write(json_filter)
    json_temp.flush()

    bpf_path = os.path.join(test_microvm.path, 'bpf.out')

    run_seccompiler(bpf_path=bpf_path, json_path=json_temp.name)

    os.unlink(json_temp.name)
    test_microvm.create_jailed_resource(bpf_path)
    test_microvm.jailer.extra_args.update({"seccomp-filter": 'bpf.out'})


def _config_file_setup(test_microvm, vm_config_file):
    test_microvm.create_jailed_resource(test_microvm.kernel_file,
                                        create_jail=True)
    test_microvm.create_jailed_resource(test_microvm.rootfs_file,
                                        create_jail=True)

    vm_config_path = os.path.join(test_microvm.path,
                                  os.path.basename(vm_config_file))
    with open(vm_config_file) as f1:
        with open(vm_config_path, "w") as f2:
            for line in f1:
                f2.write(line)
    test_microvm.create_jailed_resource(vm_config_path, create_jail=True)
    test_microvm.jailer.extra_args = {'config-file': os.path.basename(
        vm_config_file)}

    test_microvm.jailer.extra_args.update({'no-api': None})


def test_allow_all(test_microvm_with_api):
    """Test --seccomp-filter, allowing all syscalls."""
    test_microvm = test_microvm_with_api

    _custom_filter_setup(test_microvm, """{
        "Vmm": {
            "default_action": "allow",
            "filter_action": "trap",
            "filter": []
        },
        "Api": {
            "default_action": "allow",
            "filter_action": "trap",
            "filter": []
        },
        "Vcpu": {
            "default_action": "allow",
            "filter_action": "trap",
            "filter": []
        }
    }""".encode('utf-8'))

    test_microvm.spawn()

    test_microvm.basic_config()

    test_microvm.start()

    utils.assert_seccomp_level(test_microvm.jailer_clone_pid, "2")


def test_working_filter(test_microvm_with_api):
    """Test --seccomp-filter, rejecting some dangerous syscalls."""
    test_microvm = test_microvm_with_api

    _custom_filter_setup(test_microvm, """{
        "Vmm": {
            "default_action": "allow",
            "filter_action": "kill",
            "filter": [
                {
                    "syscall": "clone"
                },
                {
                    "syscall": "execve"
                }
            ]
        },
        "Api": {
            "default_action": "allow",
            "filter_action": "kill",
            "filter": [
                {
                    "syscall": "clone"
                },
                {
                    "syscall": "execve"
                }
            ]
        },
        "Vcpu": {
            "default_action": "allow",
            "filter_action": "kill",
            "filter": [
                {
                    "syscall": "clone"
                },
                {
                    "syscall": "execve",
                    "comment": "sample comment"
                }
            ]
        }
    }""".encode("utf-8"))

    test_microvm.spawn()

    test_microvm.basic_config()

    test_microvm.start()

    # seccomp-level should be 2, with no additional errors
    utils.assert_seccomp_level(test_microvm.jailer_clone_pid, "2")


def test_failing_filter(test_microvm_with_api):
    """Test --seccomp-filter, denying some needed syscalls."""
    test_microvm = test_microvm_with_api

    _custom_filter_setup(test_microvm, """{
        "Vmm": {
            "default_action": "allow",
            "filter_action": "trap",
            "filter": []
        },
        "Api": {
            "default_action": "allow",
            "filter_action": "trap",
            "filter": []
        },
        "Vcpu": {
            "default_action": "allow",
            "filter_action": "trap",
            "filter": [
                {
                    "syscall": "ioctl"
                }
            ]
        }
    }""".encode('utf-8'))

    test_microvm.spawn()

    test_microvm.basic_config(vcpu_count=1)

    metrics_fifo_path = os.path.join(test_microvm.path, 'metrics_fifo')
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = test_microvm.metrics.put(
        metrics_path=test_microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the VM with error checking off, because it will fail.
    test_microvm.start(check=False)

    # Give time for the process to get killed
    time.sleep(1)

    test_microvm.expect_kill_by_signal = True
    # Check the logger output
    ioctl_num = 16 if platform.machine() == "x86_64" else 29
    assert "Shutting down VM after intercepting a bad syscall ({})".format(
        str(ioctl_num)) in test_microvm.log_data

    # Check the metrics
    lines = metrics_fifo.sequential_reader(100)

    num_faults = 0
    for line in lines:
        num_faults += json.loads(line)["seccomp"]["num_faults"]

    assert num_faults == 1

    # assert that the process was killed
    assert not psutil.pid_exists(test_microvm.jailer_clone_pid)


@pytest.mark.parametrize(
    "vm_config_file",
    ["framework/vm_config.json"]
)
def test_invalid_bpf(test_microvm_with_ssh, vm_config_file):
    """Test that FC does not start, given an invalid binary filter."""
    test_microvm = test_microvm_with_ssh

    # Configure VM from JSON. Otherwise, the test will error because
    # the process will be killed before configuring the API socket.
    _config_file_setup(test_microvm_with_ssh, vm_config_file)

    bpf_path = os.path.join(test_microvm.path, 'bpf.out')
    file = open(bpf_path, "w")
    file.write("Invalid BPF!")
    file.close()

    test_microvm.create_jailed_resource(bpf_path)
    test_microvm.jailer.extra_args.update({"seccomp-filter": 'bpf.out'})

    test_microvm.spawn()

    # give time for the process to get killed
    time.sleep(1)

    # assert that the process was killed
    assert not psutil.pid_exists(test_microvm.jailer_clone_pid)
