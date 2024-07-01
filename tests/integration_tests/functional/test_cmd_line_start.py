# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests microvm start with configuration file as command line parameter."""

import json
import os
import platform
import re
import shutil
import time
from pathlib import Path

import pytest
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_fixed

from framework import utils, utils_cpuid
from framework.utils import generate_mmds_get_request, generate_mmds_session_token

# Directory with metadata JSON files
DIR = Path("./data")


def _configure_vm_from_json(test_microvm, vm_config_file):
    """
    Configure a microvm using a file sent as command line parameter.

    Create resources needed for the configuration of the microvm and
    set as configuration file a copy of the file that was passed as
    parameter to this helper function.
    """
    # since we don't use basic-config, we do it by hand
    test_microvm.create_jailed_resource(test_microvm.kernel_file)
    test_microvm.create_jailed_resource(test_microvm.rootfs_file)

    vm_config_file = Path(vm_config_file)
    obj = json.load(vm_config_file.open(encoding="UTF-8"))
    obj["boot-source"]["kernel_image_path"] = str(test_microvm.kernel_file.name)
    obj["drives"][0]["path_on_host"] = str(test_microvm.rootfs_file.name)
    obj["drives"][0]["is_read_only"] = True
    vm_config = Path(test_microvm.chroot()) / vm_config_file.name
    vm_config.write_text(json.dumps(obj))
    test_microvm.jailer.extra_args = {"config-file": vm_config.name}
    return obj


def _add_metadata_file(test_microvm, metadata_file):
    """
    Configure the microvm using a metadata file.

    Given a test metadata file this creates a copy of the file and
    uses the copy to configure the microvm.
    """
    vm_metadata_path = os.path.join(test_microvm.path, os.path.basename(metadata_file))
    shutil.copyfile(metadata_file, vm_metadata_path)
    test_microvm.metadata_file = vm_metadata_path


def _configure_network_interface(test_microvm):
    """
    Create tap interface before spawning the microVM.

    The network namespace is already pre-created.
    The tap interface has to be created beforehand when starting the microVM
    from a config file.
    """

    # Create tap device, and avoid creating it in the guest since it is already
    # specified in the JSON
    test_microvm.add_net_iface(api=False)


def _build_cmd_to_fetch_metadata(ssh_connection, version, ipv4_address):
    """
    Build command to fetch metadata from the guest's side.

    The request is built based on the MMDS version configured.
    If MMDSv2 is used, a session token must be created before
    the `GET` request.
    """
    # Fetch data from MMDS from the guest's side.
    if version == "V2":
        # If MMDS is configured to version 2, so we need to create
        # the session token first.
        token = generate_mmds_session_token(ssh_connection, ipv4_address, token_ttl=60)
    else:
        token = None

    return generate_mmds_get_request(ipv4_address, token)


def _get_optional_fields_from_file(vm_config_file):
    """
    Retrieve optional `version` and `ipv4_address` fields from MMDS config.

    Parse the vm config json file and retrieves optional  fields from MMDS
    config. Default values are used for the fields that are not specified.

    :return: a pair of (version, ipv4_address) fields from mmds config.
    """
    # Get MMDS version and IPv4 address configured from the file.
    with open(vm_config_file, encoding="utf-8") as json_file:
        mmds_config = json.load(json_file)["mmds-config"]
        # Default to V1 if version is not specified.
        version = mmds_config.get("version", "V1")
        # Set to default if IPv4 is not specified .
        ipv4_address = mmds_config.get("ipv4_address", "169.254.169.254")

        return version, ipv4_address


@pytest.mark.parametrize("vm_config_file", ["framework/vm_config.json"])
def test_config_start_with_api(uvm_plain, vm_config_file):
    """
    Test if a microvm configured from file boots successfully.
    """
    test_microvm = uvm_plain
    vm_config = _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.spawn()

    assert test_microvm.state == "Running"

    # Validate full vm configuration.
    response = test_microvm.api.vm_config.get()
    assert response.json() == vm_config


@pytest.mark.parametrize("vm_config_file", ["framework/vm_config.json"])
def test_config_start_no_api(uvm_plain, vm_config_file):
    """
    Test microvm start when API server thread is disabled.
    """
    test_microvm = uvm_plain
    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.jailer.extra_args.update({"no-api": None})
    test_microvm.spawn()

    # Get names of threads in Firecracker.
    cmd = f"ps -T --no-headers -p {test_microvm.firecracker_pid} | awk '{{print $5}}'"

    # Retry running 'ps' in case it failed to list the firecracker process
    # The regex matches any expression that contains 'firecracker' and does
    # not contain 'fc_api'
    for attempt in Retrying(
        retry=retry_if_exception_type(RuntimeError),
        stop=stop_after_attempt(10),
        wait=wait_fixed(1),
        reraise=True,
    ):
        with attempt:
            utils.search_output_from_cmd(
                cmd=cmd,
                find_regex=re.compile("^(?!.*fc_api)(?:.*)?firecracker", re.DOTALL),
            )


@pytest.mark.parametrize("vm_config_file", ["framework/vm_config_network.json"])
def test_config_start_no_api_exit(uvm_plain, vm_config_file):
    """
    Test microvm exit when API server is disabled.
    """
    test_microvm = uvm_plain
    _configure_vm_from_json(test_microvm, vm_config_file)
    _configure_network_interface(test_microvm)
    test_microvm.jailer.extra_args.update({"no-api": None})

    test_microvm.spawn()  # Start Firecracker and MicroVM
    time.sleep(3)  # Wait for startup
    test_microvm.ssh.run("reboot")  # Exit

    test_microvm.mark_killed()  # waits for process to terminate

    # Check error log and exit code
    test_microvm.check_log_message("Firecracker exiting successfully")
    assert test_microvm.get_exit_code() == 0


@pytest.mark.parametrize(
    "vm_config_file",
    [
        "framework/vm_config_missing_vcpu_count.json",
        "framework/vm_config_missing_mem_size_mib.json",
    ],
)
def test_config_bad_machine_config(uvm_plain, vm_config_file):
    """
    Test microvm start when the `machine_config` is invalid.
    """
    test_microvm = uvm_plain
    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.jailer.extra_args.update({"no-api": None})
    test_microvm.spawn()
    test_microvm.check_log_message("Configuration for VMM from one single json failed")

    test_microvm.mark_killed()


@pytest.mark.parametrize(
    "test_config",
    [
        ("framework/vm_config_cpu_template_C3.json", False, True, True),
        ("framework/vm_config_smt_true.json", False, False, True),
    ],
)
def test_config_machine_config_params(uvm_plain, test_config):
    """
    Test microvm start with optional `machine_config` parameters.
    """
    test_microvm = uvm_plain

    # Test configuration determines if the file is a valid config or not
    # based on the CPU
    (vm_config_file, fail_intel, fail_amd, fail_aarch64) = test_config

    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.jailer.extra_args.update({"no-api": None})

    test_microvm.spawn()

    cpu_vendor = utils_cpuid.get_cpu_vendor()

    check_for_failed_start = (
        (cpu_vendor == utils_cpuid.CpuVendor.AMD and fail_amd)
        or (cpu_vendor == utils_cpuid.CpuVendor.INTEL and fail_intel)
        or (platform.machine() == "aarch64" and fail_aarch64)
    )

    if check_for_failed_start:
        test_microvm.check_any_log_message(
            [
                "Failed to build MicroVM from Json",
                "Could not Start MicroVM from one single json",
            ]
        )

        test_microvm.mark_killed()
    else:
        test_microvm.check_log_message(
            "Successfully started microvm that was configured from one single json"
        )


@pytest.mark.parametrize("vm_config_file", ["framework/vm_config.json"])
def test_config_start_with_limit(uvm_plain, vm_config_file):
    """
    Negative test for customised request payload limit.
    """
    test_microvm = uvm_plain

    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.jailer.extra_args.update({"http-api-max-payload-size": "250"})
    test_microvm.spawn()

    assert test_microvm.state == "Running"

    cmd = "curl --unix-socket {} -i".format(test_microvm.api.socket)
    cmd += ' -X PUT "http://localhost/mmds/config"'
    cmd += ' -H  "Content-Length: 260"'
    cmd += ' -H "Accept: application/json"'
    cmd += ' -d "some body"'

    response = "HTTP/1.1 400 \r\n"
    response += "Server: Firecracker API\r\n"
    response += "Connection: keep-alive\r\n"
    response += "Content-Type: application/json\r\n"
    response += "Content-Length: 145\r\n\r\n"
    response += '{ "error": "Request payload with size 260 is larger than '
    response += "the limit of 250 allowed by server.\n"
    response += 'All previous unanswered requests will be dropped." }'
    _, stdout, _stderr = utils.check_output(cmd)
    assert stdout.encode("utf-8") == response.encode("utf-8")


@pytest.mark.parametrize("vm_config_file", ["framework/vm_config.json"])
def test_config_with_default_limit(uvm_plain, vm_config_file):
    """
    Test for request payload limit.
    """
    test_microvm = uvm_plain

    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.spawn()

    assert test_microvm.state == "Running"

    data_store = {"latest": {"meta-data": {}}}
    data_store["latest"]["meta-data"]["ami-id"] = "abc"
    test_microvm.api.mmds.put(json=data_store)

    cmd_err = "curl --unix-socket {} -i".format(test_microvm.api.socket)
    cmd_err += ' -X PUT "http://localhost/mmds/config"'
    cmd_err += ' -H  "Content-Length: 51201"'
    cmd_err += ' -H "Accept: application/json"'
    cmd_err += ' -d "some body"'

    response_err = "HTTP/1.1 400 \r\n"
    response_err += "Server: Firecracker API\r\n"
    response_err += "Connection: keep-alive\r\n"
    response_err += "Content-Type: application/json\r\n"
    response_err += "Content-Length: 149\r\n\r\n"
    response_err += '{ "error": "Request payload with size 51201 is larger '
    response_err += "than the limit of 51200 allowed by server.\n"
    response_err += 'All previous unanswered requests will be dropped." }'
    _, stdout, _stderr = utils.check_output(cmd_err)
    assert stdout.encode("utf-8") == response_err.encode("utf-8")


def test_start_with_metadata(uvm_plain):
    """
    Test if metadata from file is available via MMDS.
    """
    test_microvm = uvm_plain
    metadata_file = DIR / "metadata.json"
    _add_metadata_file(test_microvm, metadata_file)

    test_microvm.spawn()

    test_microvm.check_log_message("Successfully added metadata to mmds from file")

    assert test_microvm.state == "Not started"

    response = test_microvm.api.mmds.get()

    with open(metadata_file, encoding="utf-8") as json_file:
        assert response.json() == json.load(json_file)


def test_start_with_metadata_limit(uvm_plain):
    """
    Test that the metadata size limit is enforced when populating from a file.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.extra_args.update({"mmds-size-limit": "30"})
    metadata_file = DIR / "metadata.json"
    _add_metadata_file(test_microvm, metadata_file)

    test_microvm.spawn()

    test_microvm.check_log_message(
        "Populating MMDS from file failed: The MMDS patch request doesn't fit."
    )

    test_microvm.mark_killed()


def test_start_with_metadata_default_limit(uvm_plain):
    """
    Test that the metadata size limit defaults to the api payload limit.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.extra_args.update({"http-api-max-payload-size": "30"})

    metadata_file = DIR / "metadata.json"

    _add_metadata_file(test_microvm, metadata_file)

    test_microvm.spawn()

    test_microvm.check_log_message(
        "Populating MMDS from file failed: The MMDS patch request doesn't fit."
    )

    test_microvm.mark_killed()


def test_start_with_missing_metadata(uvm_plain):
    """
    Test if a microvm is configured with a missing metadata file.
    """
    test_microvm = uvm_plain
    metadata_file = "../resources/tests/metadata_nonexisting.json"

    vm_metadata_path = os.path.join(test_microvm.path, os.path.basename(metadata_file))
    test_microvm.metadata_file = vm_metadata_path

    try:
        test_microvm.spawn()
    except FileNotFoundError:
        pass
    finally:
        test_microvm.check_log_message(
            "Unable to open or read from the mmds content file"
        )
        test_microvm.check_log_message("No such file or directory")

        test_microvm.mark_killed()


def test_start_with_invalid_metadata(uvm_plain):
    """
    Test if a microvm is configured with a invalid metadata file.
    """
    test_microvm = uvm_plain
    metadata_file = DIR / "metadata_invalid.json"
    vm_metadata_path = os.path.join(test_microvm.path, os.path.basename(metadata_file))
    shutil.copy(metadata_file, vm_metadata_path)
    test_microvm.metadata_file = vm_metadata_path

    try:
        test_microvm.spawn()
    except FileNotFoundError:
        pass
    finally:
        test_microvm.check_log_message("MMDS error: metadata provided not valid json")
        test_microvm.check_log_message("EOF while parsing an object")

        test_microvm.mark_killed()


@pytest.mark.parametrize(
    "vm_config_file",
    ["framework/vm_config_with_mmdsv1.json", "framework/vm_config_with_mmdsv2.json"],
)
def test_config_start_and_mmds_with_api(uvm_plain, vm_config_file):
    """
    Test MMDS behavior when the microvm is configured from file.
    """
    test_microvm = uvm_plain
    _configure_vm_from_json(test_microvm, vm_config_file)
    _configure_network_interface(test_microvm)

    # Network namespace has already been created.
    test_microvm.spawn()

    assert test_microvm.state == "Running"

    data_store = {
        "latest": {
            "meta-data": {"ami-id": "ami-12345678", "reservation-id": "r-fea54097"}
        }
    }

    # MMDS should be empty by default.
    response = test_microvm.api.mmds.get()
    assert response.json() == {}

    # Populate MMDS with data.
    response = test_microvm.api.mmds.put(**data_store)

    # Ensure the MMDS contents have been successfully updated.
    response = test_microvm.api.mmds.get()
    assert response.json() == data_store

    # Get MMDS version and IPv4 address configured from the file.
    version, ipv4_address = _get_optional_fields_from_file(vm_config_file)

    cmd = "ip route add {} dev eth0".format(ipv4_address)
    _, stdout, stderr = test_microvm.ssh.run(cmd)
    assert stderr == stdout == ""

    # Fetch data from MMDS from the guest's side.
    cmd = _build_cmd_to_fetch_metadata(test_microvm.ssh, version, ipv4_address)
    cmd += "/latest/meta-data/"
    _, stdout, _ = test_microvm.ssh.run(cmd)
    assert json.loads(stdout) == data_store["latest"]["meta-data"]

    # Validate MMDS configuration.
    response = test_microvm.api.vm_config.get()
    assert response.json()["mmds-config"] == {
        "network_interfaces": ["1"],
        "ipv4_address": ipv4_address,
        "version": version,
    }


@pytest.mark.parametrize(
    "vm_config_file",
    ["framework/vm_config_with_mmdsv1.json", "framework/vm_config_with_mmdsv2.json"],
)
@pytest.mark.parametrize("metadata_file", [DIR / "metadata.json"])
def test_with_config_and_metadata_no_api(uvm_plain, vm_config_file, metadata_file):
    """
    Test microvm start when config/mmds and API server thread is disabled.

    Ensures the metadata is stored successfully inside the MMDS and
    is available to reach from the guest's side.
    """
    test_microvm = uvm_plain
    _configure_vm_from_json(test_microvm, vm_config_file)
    _add_metadata_file(test_microvm, metadata_file)
    _configure_network_interface(test_microvm)
    test_microvm.jailer.extra_args.update({"no-api": None})
    test_microvm.spawn()

    # Get MMDS version and IPv4 address configured from the file.
    version, ipv4_address = _get_optional_fields_from_file(vm_config_file)

    cmd = "ip route add {} dev eth0".format(ipv4_address)
    _, stdout, stderr = test_microvm.ssh.run(cmd)
    assert stderr == stdout == ""

    # Fetch data from MMDS from the guest's side.
    cmd = _build_cmd_to_fetch_metadata(test_microvm.ssh, version, ipv4_address)
    _, stdout, _ = test_microvm.ssh.run(cmd)

    # Compare response against the expected MMDS contents.
    assert json.loads(stdout) == json.load(Path(metadata_file).open(encoding="UTF-8"))
