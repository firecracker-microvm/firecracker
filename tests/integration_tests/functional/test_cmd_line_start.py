# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests microvm start with configuration file as command line parameter."""

import json
import os
import re
import shutil

from retry.api import retry_call

import pytest

from framework import utils
from framework.artifacts import NetIfaceConfig
from framework.utils import generate_mmds_session_token, \
    generate_mmds_v2_get_request
import host_tools.network as net_tools


def _configure_vm_from_json(test_microvm, vm_config_file):
    """
    Configure a microvm using a file sent as command line parameter.

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
    with open(vm_config_file, encoding='utf-8') as f1:
        with open(vm_config_path, "w", encoding='utf-8') as f2:
            for line in f1:
                f2.write(line)
    test_microvm.create_jailed_resource(vm_config_path, create_jail=True)
    test_microvm.jailer.extra_args = {'config-file': os.path.basename(
        vm_config_file)}


def _add_metadata_file(test_microvm, metadata_file):
    """
    Configure the microvm using a metadata file.

    Given a test metadata file this creates a copy of the file and
    uses the copy to configure the microvm.
    """
    vm_metadata_path = os.path.join(
        test_microvm.path,
        os.path.basename(metadata_file)
    )
    shutil.copyfile(metadata_file, vm_metadata_path)
    test_microvm.metadata_file = vm_metadata_path


def _configure_network_interface(test_microvm):
    """
    Create tap interface before spawning the microVM.

    The network namespace and tap interface have to be created
    beforehand when starting the microVM from a config file.
    """
    # Create network namespace.
    utils.run_cmd(f"ip netns add {test_microvm.jailer.netns}")

    # Create tap device and SSH config.
    net_iface = NetIfaceConfig()
    _tap = test_microvm.create_tap_and_ssh_config(net_iface.host_ip,
                                                  net_iface.guest_ip,
                                                  net_iface.netmask,
                                                  net_iface.tap_name)


def _build_cmd_to_fetch_metadata(ssh_connection, version, ipv4_address):
    """
    Build command to fetch metadata from the guest's side.

    The request is built based on the MMDS version configured.
    If MMDSv2 is used, a session token must be created before
    the `GET` request.
    """
    # Fetch data from MMDS from the guest's side.
    if version == "V1":
        cmd = 'curl -s -H "Accept: application/json" '
        cmd += 'http://{}'.format(ipv4_address)

    else:
        # If MMDS is configured to version 2, so we need to create
        # the session token first.
        token = generate_mmds_session_token(
            ssh_connection,
            ipv4_address,
            token_ttl=60
        )
        cmd = generate_mmds_v2_get_request(ipv4_address, token)

    return cmd


def _get_optional_fields_from_file(vm_config_file):
    """
    Retrieve optional `version` and `ipv4_address` fields from MMDS config.

    Parse the vm config json file and retrieves optional  fields from MMDS
    config. Default values are used for the fields that are not specified.

    :return: a pair of (version, ipv4_address) fields from mmds config.
    """
    # Get MMDS version and IPv4 address configured from the file.
    with open(vm_config_file, encoding='utf-8') as json_file:
        mmds_config = json.load(json_file)["mmds-config"]
        # Default to V1 if version is not specified.
        version = mmds_config.get("version", "V1")
        # Set to default if IPv4 is not specified .
        ipv4_address = mmds_config.get("ipv4_address", "169.254.169.254")

        return version, ipv4_address


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
    with open(vm_config_file, encoding='utf-8') as json_file:
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


def test_start_with_metadata(test_microvm_with_api):
    """
    Test if metadata from file is available via MMDS.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    metadata_file = "../resources/tests/metadata.json"

    _add_metadata_file(test_microvm, metadata_file)

    test_microvm.spawn()

    test_microvm.check_log_message(
        "Successfully added metadata to mmds from file"
    )

    response = test_microvm.machine_cfg.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert test_microvm.state == "Not started"

    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)

    with open(metadata_file, encoding='utf-8') as json_file:
        assert response.json() == json.load(json_file)


def test_start_with_missing_metadata(test_microvm_with_api):
    """
    Test if a microvm is configured with a missing metadata file.

    @type: negative
    """
    test_microvm = test_microvm_with_api
    metadata_file = "../resources/tests/metadata_nonexisting.json"

    vm_metadata_path = os.path.join(
        test_microvm.path,
        os.path.basename(metadata_file)
    )
    test_microvm.metadata_file = vm_metadata_path

    # This will be a FileNotFound on the firecracker socket
    # and not the metadata file
    with pytest.raises(FileNotFoundError):
        test_microvm.spawn()

    test_microvm.check_log_message(
        "Unable to open or read from the mmds content file"
    )
    test_microvm.check_log_message("No such file or directory")


def test_start_with_invalid_metadata(test_microvm_with_api):
    """
    Test if a microvm is configured with a invalid metadata file.

    @type: negative
    """
    test_microvm = test_microvm_with_api
    metadata_file = "../resources/tests/metadata_invalid.json"

    vm_metadata_path = os.path.join(
        test_microvm.path,
        os.path.basename(metadata_file)
    )
    shutil.copy(metadata_file, vm_metadata_path)
    test_microvm.metadata_file = vm_metadata_path

    with pytest.raises(FileNotFoundError):
        test_microvm.spawn()

    test_microvm.check_log_message(
        "MMDS error: metadata provided not valid json"
    )
    test_microvm.check_log_message(
        "EOF while parsing an object"
    )


@pytest.mark.parametrize(
    "vm_config_file",
    [
        "framework/vm_config_with_mmdsv1.json",
        "framework/vm_config_with_mmdsv2.json"
    ]
)
def test_config_start_and_mmds_with_api(test_microvm_with_api, vm_config_file):
    """
    Test MMDS behavior when the microvm is configured from file.

    @type: functional
    """
    test_microvm = test_microvm_with_api

    _configure_vm_from_json(test_microvm, vm_config_file)
    _configure_network_interface(test_microvm)

    # Network namespace has already been created.
    test_microvm.spawn()

    response = test_microvm.machine_cfg.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert test_microvm.state == "Running"

    data_store = {
        'latest': {
            'meta-data': {
                'ami-id': 'ami-12345678',
                'reservation-id': 'r-fea54097'
            }
        }
    }

    # MMDS should be empty by default.
    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == {}

    # Populate MMDS with data.
    response = test_microvm.mmds.put(json=data_store)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Ensure the MMDS contents have been successfully updated.
    response = test_microvm.mmds.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == data_store

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Get MMDS version and IPv4 address configured from the file.
    version, ipv4_address = _get_optional_fields_from_file(vm_config_file)

    cmd = 'ip route add {} dev eth0'.format(ipv4_address)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert stderr.read() == stdout.read() == ''

    # Fetch data from MMDS from the guest's side.
    cmd = _build_cmd_to_fetch_metadata(ssh_connection, version, ipv4_address)
    cmd += '/latest/meta-data/'
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == data_store['latest']['meta-data']

    # Validate MMDS configuration.
    response = test_microvm.full_cfg.get()
    assert test_microvm.api_session.is_status_ok(response.status_code)
    assert response.json()["mmds-config"] == {
        'network_interfaces': ['1'],
        'ipv4_address': ipv4_address,
        'version': version
    }


@pytest.mark.parametrize(
    "vm_config_file",
    [
        "framework/vm_config_with_mmdsv1.json",
        "framework/vm_config_with_mmdsv2.json"
    ]
)
@pytest.mark.parametrize(
    "metadata_file",
    ["../resources/tests/metadata.json"]
)
def test_with_config_and_metadata_no_api(
        test_microvm_with_api,
        vm_config_file,
        metadata_file
):
    """
    Test microvm start when config/mmds and API server thread is disabled.

    Ensures the metadata is stored successfully inside the MMDS and
    is available to reach from the guest's side.

    @type: functional
    """
    test_microvm = test_microvm_with_api

    _configure_vm_from_json(test_microvm, vm_config_file)
    _add_metadata_file(test_microvm, metadata_file)
    _configure_network_interface(test_microvm)
    test_microvm.jailer.extra_args.update({'no-api': None})

    test_microvm.spawn()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Get MMDS version and IPv4 address configured from the file.
    version, ipv4_address = _get_optional_fields_from_file(vm_config_file)

    cmd = 'ip route add {} dev eth0'.format(ipv4_address)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert stderr.read() == stdout.read() == ''

    # Fetch data from MMDS from the guest's side.
    cmd = _build_cmd_to_fetch_metadata(ssh_connection, version, ipv4_address)
    _, stdout, _ = ssh_connection.execute_command(cmd)

    # Compare response against the expected MMDS contents.
    with open(metadata_file, encoding='utf-8') as metadata:
        assert json.load(stdout) == json.load(metadata)
