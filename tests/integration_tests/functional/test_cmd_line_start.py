# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests microvm start with configuration file as command line parameter."""

import json
import os
import re

from retry.api import retry_call

import pytest

import framework.utils as utils


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
def test_config_start_with_api(test_microvm_with_api, vm_config_file):
    """
    Test if a microvm configured from file boots successfully.

    @type: functional
    """
    test_microvm = test_microvm_with_api

    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.spawn()

    response = test_microvm.machine_cfg.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert test_microvm.state == "Running"

    # Validate full vm configuration.
    response = test_microvm.full_cfg.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    with open(vm_config_file) as json_file:
        assert response.json() == json.load(json_file)


@pytest.mark.parametrize(
    "vm_config_file",
    ["framework/vm_config.json"]
)
def test_config_start_no_api(test_microvm_with_api, vm_config_file):
    """
    Test microvm start when API server thread is disabled.

    @type: functional
    """
    test_microvm = test_microvm_with_api

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


@pytest.mark.parametrize(
    "vm_config_file",
    ["framework/vm_config.json"]
)
def test_config_start_with_limit(test_microvm_with_api, vm_config_file):
    """
    Negative test for customised request payload limit.

    @type: negative
    """
    test_microvm = test_microvm_with_api

    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.jailer.extra_args.update({'http-api-max-payload-size': "250"})
    test_microvm.spawn()

    response = test_microvm.machine_cfg.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert test_microvm.state == "Running"

    cmd = "curl --unix-socket {} -i".format(test_microvm.api_socket)
    cmd += " -X PUT \"http://localhost/mmds/config\""
    cmd += " -H  \"Content-Length: 260\""
    cmd += " -H \"Accept: application/json\""
    cmd += " -d \"some body\""

    response = "HTTP/1.1 400 \r\n"
    response += "Server: Firecracker API\r\n"
    response += "Connection: keep-alive\r\n"
    response += "Content-Type: application/json\r\n"
    response += "Content-Length: 145\r\n\r\n"
    response += "{ \"error\": \"Request payload with size 260 is larger than "
    response += "the limit of 250 allowed by server.\n"
    response += "All previous unanswered requests will be dropped.\" }"
    _, stdout, _stderr = utils.run_cmd(cmd)
    assert stdout.encode("utf-8") == response.encode("utf-8")


@pytest.mark.parametrize(
    "vm_config_file",
    ["framework/vm_config.json"]
)
def test_config_with_default_limit(test_microvm_with_api, vm_config_file):
    """
    Test for request payload limit.

    @type: functional
    """
    test_microvm = test_microvm_with_api

    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.spawn()

    response = test_microvm.machine_cfg.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert test_microvm.state == "Running"

    data_store = {
        'latest': {
            'meta-data': {
            }
        }
    }
    data_store["latest"]["meta-data"]["ami-id"] = "abc"
    response = test_microvm.mmds.put(json=data_store)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    cmd_err = "curl --unix-socket {} -i".format(test_microvm.api_socket)
    cmd_err += " -X PUT \"http://localhost/mmds/config\""
    cmd_err += " -H  \"Content-Length: 51201\""
    cmd_err += " -H \"Accept: application/json\""
    cmd_err += " -d \"some body\""

    response_err = "HTTP/1.1 400 \r\n"
    response_err += "Server: Firecracker API\r\n"
    response_err += "Connection: keep-alive\r\n"
    response_err += "Content-Type: application/json\r\n"
    response_err += "Content-Length: 149\r\n\r\n"
    response_err += "{ \"error\": \"Request payload with size 51201 is larger "
    response_err += "than the limit of 51200 allowed by server.\n"
    response_err += "All previous unanswered requests will be dropped.\" }"
    _, stdout, _stderr = utils.run_cmd(cmd_err)
    assert stdout.encode("utf-8") == response_err.encode("utf-8")
