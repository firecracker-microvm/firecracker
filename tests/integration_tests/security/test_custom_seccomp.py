# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the --seccomp-filter parameter works as expected."""

import os
import platform
import tempfile
import time
import psutil
import pytest
import framework.utils as utils


def _custom_filter_setup(test_microvm, json_filter):
    json_temp = tempfile.NamedTemporaryFile(delete=False)
    json_temp.write(json_filter)
    json_temp.flush()

    bpf_path = os.path.join(test_microvm.path, 'bpf.out')

    cargo_target = '{}-unknown-linux-musl'.format(platform.machine())
    cmd = 'cargo run -p seccomp --target {} -- --input-file {} --target-arch\
        {} --output-file {}'.format(cargo_target, json_temp.name,
                                    platform.machine(), bpf_path)
    utils.run_cmd(cmd)

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

    # because Firecracker receives empty filters, the seccomp-level will
    # remain 0
    utils.assert_seccomp_level(test_microvm.jailer_clone_pid, "0")


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


@pytest.mark.parametrize(
    "vm_config_file",
    ["framework/vm_config.json"]
)
def test_failing_filter(test_microvm_with_ssh, vm_config_file):
    """Test --seccomp-filter, denying some needed syscalls."""
    test_microvm = test_microvm_with_ssh

    # Configure VM from JSON. Otherwise, the test will error because
    # the process will be killed before configuring the API socket.
    _config_file_setup(test_microvm_with_ssh, vm_config_file)

    _custom_filter_setup(test_microvm, """{
        "Vmm": {
            "default_action": "kill",
            "filter_action": "allow",
            "filter": [
                {
                    "syscall": "read"
                }
            ]
        },
        "Api": {
            "default_action": "kill",
            "filter_action": "allow",
            "filter": [
                {
                    "syscall": "read"
                }
            ]
        },
        "Vcpu": {
            "default_action": "kill",
            "filter_action": "allow",
            "filter": [
                {
                    "syscall": "read"
                }
            ]
        }
    }""".encode('utf-8'))

    test_microvm.spawn()

    # give time for the process to get killed
    time.sleep(1)

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
