# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests microvm start with configuration file as command line parameter."""

import os
import re

from retry.api import retry_call

import pytest

import framework.utils as utils

import host_tools.logging as log_tools


def _configure_vm_from_json(test_microvm, vm_config_file):
    """Configure a microvm using a file sent as command line parameter.

    Create resources needed for the configuration of the microvm and
    set as configuration file a copy of the file that was passed as
    parameter to this helper function.
    """
    test_microvm.create_jailed_resource(test_microvm.kernel_file,
                                        create_jail=True)
    test_microvm.create_jailed_resource(test_microvm.rootfs_file,
                                        create_jail=True)

    # vm_config_file is the source file that keeps the desired vmm
    # configuration. vm_config_path is the configuration file we
    # create inside the jail, such that it can be accessed by
    # firecracker after it starts.
    vm_config_path = os.path.join(test_microvm.path,
                                  os.path.basename(vm_config_file))
    with open(vm_config_file) as f1:
        with open(vm_config_path, "w") as f2:
            for line in f1:
                f2.write(line)
    test_microvm.create_jailed_resource(vm_config_path, create_jail=True)
    test_microvm.jailer.extra_args = {'config-file': os.path.basename(
        vm_config_file)}


@pytest.mark.parametrize(
    "vm_config_file",
    ["framework/vm_config.json"]
)
def test_config_start_with_api(test_microvm_with_ssh, vm_config_file):
    """Test if a microvm configured from file boots successfully."""
    test_microvm = test_microvm_with_ssh

    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.spawn()

    response = test_microvm.machine_cfg.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)


@pytest.mark.parametrize(
    "vm_config_file",
    ["framework/vm_log_config.json"]
)
def test_config_start_no_api(test_microvm_with_ssh, vm_config_file):
    """Test microvm start when API server thread is disabled."""
    test_microvm = test_microvm_with_ssh

    log_fifo_path = os.path.join(test_microvm.path, 'log_fifo')
    metrics_fifo_path = os.path.join(test_microvm.path, 'metrics_fifo')
    log_fifo = log_tools.Fifo(log_fifo_path)
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    test_microvm.create_jailed_resource(log_fifo.path, create_jail=True)
    test_microvm.create_jailed_resource(metrics_fifo.path, create_jail=True)

    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.jailer.extra_args.update({'no-api': None})

    test_microvm.spawn()

    # Get Firecracker PID so we can check the names of threads.
    firecracker_pid = test_microvm.jailer_clone_pid

    # Get names of threads in Firecracker.
    cmd = 'ps -T --no-headers -p {} | awk \'{{print $5}}\''.format(
        firecracker_pid
    )

    # Retry running 'ps' in case it failed to list the firecracker process
    # The regex matches any expression that contains 'firecracker' and does
    # not contain 'fc_api'
    retry_call(
        utils.search_output_from_cmd,
        fkwargs={
            "cmd": cmd,
            "find_regex": re.compile("^(?!.*fc_api)(?:.*)?firecracker",
                                     re.DOTALL)
            },
        exceptions=RuntimeError,
        tries=10,
        delay=1)

    # Check that microvm was successfully booted.
    lines = log_fifo.sequential_reader(1)
    assert lines[0].startswith('Running Firecracker')
