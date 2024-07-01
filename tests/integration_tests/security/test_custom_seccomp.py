# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the --seccomp-filter parameter works as expected."""

import os
import platform
import tempfile
import time

import pytest
import requests

from framework import utils
from host_tools.cargo_build import run_seccompiler_bin


def _custom_filter_setup(test_microvm, json_filter):
    json_temp = tempfile.NamedTemporaryFile(delete=False)
    json_temp.write(json_filter)
    json_temp.flush()

    bpf_path = os.path.join(test_microvm.path, "bpf.out")

    run_seccompiler_bin(bpf_path=bpf_path, json_path=json_temp.name)

    os.unlink(json_temp.name)
    test_microvm.create_jailed_resource(bpf_path)
    test_microvm.jailer.extra_args.update({"seccomp-filter": "bpf.out"})


def _config_file_setup(test_microvm, vm_config_file):
    test_microvm.create_jailed_resource(test_microvm.kernel_file)
    test_microvm.create_jailed_resource(test_microvm.rootfs_file)

    vm_config_path = os.path.join(test_microvm.path, os.path.basename(vm_config_file))
    with open(vm_config_file, encoding="utf-8") as f1:
        with open(vm_config_path, "w", encoding="utf-8") as f2:
            for line in f1:
                f2.write(line)
    test_microvm.create_jailed_resource(vm_config_path)
    test_microvm.jailer.extra_args = {"config-file": os.path.basename(vm_config_file)}

    test_microvm.jailer.extra_args.update({"no-api": None})


def test_allow_all(uvm_plain):
    """
    Test --seccomp-filter, allowing all syscalls.
    """
    test_microvm = uvm_plain

    _custom_filter_setup(
        test_microvm,
        """{
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
    }""".encode(
            "utf-8"
        ),
    )

    test_microvm.spawn()

    test_microvm.basic_config()

    test_microvm.start()

    utils.assert_seccomp_level(test_microvm.firecracker_pid, "2")


def test_working_filter(uvm_plain):
    """
    Test --seccomp-filter, rejecting some dangerous syscalls.
    """
    test_microvm = uvm_plain

    _custom_filter_setup(
        test_microvm,
        """{
        "Vmm": {
            "default_action": "allow",
            "filter_action": "kill_process",
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
            "filter_action": "kill_process",
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
            "filter_action": "kill_process",
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
    }""".encode(
            "utf-8"
        ),
    )

    test_microvm.spawn()

    test_microvm.basic_config()

    test_microvm.start()

    # level should be 2, with no additional errors
    utils.assert_seccomp_level(test_microvm.firecracker_pid, "2")


def test_failing_filter(uvm_plain):
    """
    Test --seccomp-filter, denying some needed syscalls.
    """
    test_microvm = uvm_plain

    _custom_filter_setup(
        test_microvm,
        """{
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
    }""".encode(
            "utf-8"
        ),
    )

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
        "Shutting down VM after intercepting a bad"
        " syscall ({})".format(str(ioctl_num))
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


@pytest.mark.parametrize("vm_config_file", ["framework/vm_config.json"])
def test_invalid_bpf(uvm_plain, vm_config_file):
    """
    Test that FC does not start, given an invalid binary filter.
    """
    test_microvm = uvm_plain

    # Configure VM from JSON. Otherwise, the test will error because
    # the process will be killed before configuring the API socket.
    _config_file_setup(uvm_plain, vm_config_file)

    bpf_path = os.path.join(test_microvm.path, "bpf.out")
    file = open(bpf_path, "w", encoding="utf-8")
    file.write("Invalid BPF!")
    file.close()

    test_microvm.create_jailed_resource(bpf_path)
    test_microvm.jailer.extra_args.update({"seccomp-filter": "bpf.out"})

    test_microvm.spawn()

    # give time for the process to get killed
    time.sleep(1)

    test_microvm.mark_killed()
