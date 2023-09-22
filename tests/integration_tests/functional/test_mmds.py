# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify MMDS related functionality."""

# pylint: disable=too-many-lines
import random
import string
import time

import pytest

from framework.properties import global_props
from framework.utils import (
    configure_mmds,
    generate_mmds_get_request,
    generate_mmds_session_token,
    populate_data_store,
    run_guest_cmd,
)
from host_tools.cargo_build import get_firecracker_binaries

# Minimum lifetime of token.
MIN_TOKEN_TTL_SECONDS = 1
# Maximum lifetime of token.
MAX_TOKEN_TTL_SECONDS = 21600
# Default IPv4 value for MMDS.
DEFAULT_IPV4 = "169.254.169.254"
# MMDS versions supported.
MMDS_VERSIONS = ["V2", "V1"]


def _validate_mmds_snapshot(
    basevm,
    microvm_factory,
    version,
    target_fc_version=None,
    fc_binary_path=None,
    jailer_binary_path=None,
):
    """Test MMDS behaviour across snap-restore."""
    ipv4_address = "169.254.169.250"

    # Configure MMDS version with custom IPv4 address.
    configure_mmds(
        basevm,
        version=version,
        iface_ids=["eth0"],
        ipv4_address=ipv4_address,
    )

    expected_mmds_config = {
        "version": version,
        "ipv4_address": ipv4_address,
        "network_interfaces": ["eth0"],
    }
    response = basevm.api.vm_config.get()
    assert response.json()["mmds-config"] == expected_mmds_config

    data_store = {"latest": {"meta-data": {"ami-id": "ami-12345678"}}}
    populate_data_store(basevm, data_store)

    basevm.start()
    ssh_connection = basevm.ssh
    run_guest_cmd(ssh_connection, f"ip route add {ipv4_address} dev eth0", "")

    # Generate token if needed.
    token = None
    if version == "V2":
        token = generate_mmds_session_token(ssh_connection, ipv4_address, token_ttl=60)

    # Fetch metadata.
    cmd = generate_mmds_get_request(
        ipv4_address,
        token=token,
    )
    run_guest_cmd(ssh_connection, cmd, data_store, use_json=True)

    # Create snapshot.
    snapshot = basevm.snapshot_full(target_version=target_fc_version)

    # Resume microVM and ensure session token is still valid on the base.
    response = basevm.resume()

    # Fetch metadata again using the same token.
    run_guest_cmd(ssh_connection, cmd, data_store, use_json=True)

    # Kill base microVM.
    basevm.kill()

    # Load microVM clone from snapshot.
    microvm = microvm_factory.build(
        fc_binary_path=fc_binary_path, jailer_binary_path=jailer_binary_path
    )
    microvm.spawn()
    microvm.restore_from_snapshot(snapshot)
    microvm.resume()

    ssh_connection = microvm.ssh

    # Check the reported MMDS config.
    response = microvm.api.vm_config.get()
    assert response.json()["mmds-config"] == expected_mmds_config

    if version == "V1":
        # Verify that V2 requests don't work
        assert (
            generate_mmds_session_token(ssh_connection, ipv4_address, token_ttl=60)
            == "Not allowed HTTP method."
        )

        token = None
    else:
        # Attempting to reuse the token across a restore must fail.
        cmd = generate_mmds_get_request(ipv4_address, token=token)
        run_guest_cmd(ssh_connection, cmd, "MMDS token not valid.")

        # Generate token.
        token = generate_mmds_session_token(ssh_connection, ipv4_address, token_ttl=60)

    # Data store is empty after a restore.
    cmd = generate_mmds_get_request(ipv4_address, token=token)
    run_guest_cmd(ssh_connection, cmd, "null")

    # Now populate the store.
    populate_data_store(microvm, data_store)

    # Fetch metadata.
    run_guest_cmd(ssh_connection, cmd, data_store, use_json=True)


@pytest.mark.parametrize("version", MMDS_VERSIONS)
def test_custom_ipv4(test_microvm_with_api, version):
    """
    Test the API for MMDS custom ipv4 support.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    data_store = {
        "latest": {
            "meta-data": {
                "ami-id": "ami-12345678",
                "reservation-id": "r-fea54097",
                "local-hostname": "ip-10-251-50-12.ec2.internal",
                "public-hostname": "ec2-203-0-113-25.compute-1.amazonaws.com",
                "network": {
                    "interfaces": {
                        "macs": {
                            "02:29:96:8f:6a:2d": {
                                "device-number": "13345342",
                                "local-hostname": "localhost",
                                "subnet-id": "subnet-be9b61d",
                            }
                        }
                    }
                },
            }
        }
    }
    populate_data_store(test_microvm, data_store)

    # Attach network device.
    test_microvm.add_net_iface()

    # Invalid values IPv4 address.
    with pytest.raises(RuntimeError):
        test_microvm.api.mmds_config.put(ipv4_address="", network_interfaces=["eth0"])

    with pytest.raises(RuntimeError):
        test_microvm.api.mmds_config.put(
            ipv4_address="1.1.1.1", network_interfaces=["eth0"]
        )

    ipv4_address = "169.254.169.250"
    # Configure MMDS with custom IPv4 address.
    configure_mmds(
        test_microvm, iface_ids=["eth0"], version=version, ipv4_address=ipv4_address
    )

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()
    ssh_connection = test_microvm.ssh

    run_guest_cmd(ssh_connection, f"ip route add {ipv4_address} dev eth0", "")

    token = None
    if version == "V2":
        # Generate token.
        token = generate_mmds_session_token(ssh_connection, ipv4_address, token_ttl=60)

    pre = generate_mmds_get_request(
        ipv4_address,
        token=token,
    )

    cmd = pre + "latest/meta-data/ami-id"
    run_guest_cmd(ssh_connection, cmd, "ami-12345678", use_json=True)

    # The request is still valid if we append a
    # trailing slash to a leaf node.
    cmd = pre + "latest/meta-data/ami-id/"
    run_guest_cmd(ssh_connection, cmd, "ami-12345678", use_json=True)

    cmd = (
        pre + "latest/meta-data/network/interfaces/macs/" "02:29:96:8f:6a:2d/subnet-id"
    )
    run_guest_cmd(ssh_connection, cmd, "subnet-be9b61d", use_json=True)

    # Test reading a non-leaf node WITHOUT a trailing slash.
    cmd = pre + "latest/meta-data"
    run_guest_cmd(ssh_connection, cmd, data_store["latest"]["meta-data"], use_json=True)

    # Test reading a non-leaf node with a trailing slash.
    cmd = pre + "latest/meta-data/"
    run_guest_cmd(ssh_connection, cmd, data_store["latest"]["meta-data"], use_json=True)


@pytest.mark.parametrize("version", MMDS_VERSIONS)
def test_json_response(test_microvm_with_api, version):
    """
    Test the MMDS json response.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    data_store = {
        "latest": {
            "meta-data": {
                "ami-id": "ami-12345678",
                "reservation-id": "r-fea54097",
                "local-hostname": "ip-10-251-50-12.ec2.internal",
                "public-hostname": "ec2-203-0-113-25.compute-1.amazonaws.com",
                "dummy_res": ["res1", "res2"],
            },
            "Limits": {"CPU": 512, "Memory": 512},
            "Usage": {"CPU": 12.12},
        }
    }

    # Attach network device.
    test_microvm.add_net_iface()

    # Configure MMDS version.
    configure_mmds(test_microvm, iface_ids=["eth0"], version=version)

    # Populate data store with contents.
    populate_data_store(test_microvm, data_store)

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()
    ssh_connection = test_microvm.ssh

    cmd = "ip route add {} dev eth0".format(DEFAULT_IPV4)
    run_guest_cmd(ssh_connection, cmd, "")

    token = None
    if version == "V2":
        # Generate token.
        token = generate_mmds_session_token(ssh_connection, DEFAULT_IPV4, token_ttl=60)

    pre = generate_mmds_get_request(DEFAULT_IPV4, token)

    cmd = pre + "latest/meta-data/"
    run_guest_cmd(ssh_connection, cmd, data_store["latest"]["meta-data"], use_json=True)

    cmd = pre + "latest/meta-data/ami-id/"
    run_guest_cmd(ssh_connection, cmd, "ami-12345678", use_json=True)

    cmd = pre + "latest/meta-data/dummy_res/0"
    run_guest_cmd(ssh_connection, cmd, "res1", use_json=True)

    cmd = pre + "latest/Usage/CPU"
    run_guest_cmd(ssh_connection, cmd, 12.12, use_json=True)

    cmd = pre + "latest/Limits/CPU"
    run_guest_cmd(ssh_connection, cmd, 512, use_json=True)


@pytest.mark.parametrize("version", MMDS_VERSIONS)
def test_mmds_response(test_microvm_with_api, version):
    """
    Test MMDS responses to various datastore requests.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    data_store = {
        "latest": {
            "meta-data": {
                "ami-id": "ami-12345678",
                "reservation-id": "r-fea54097",
                "local-hostname": "ip-10-251-50-12.ec2.internal",
                "public-hostname": "ec2-203-0-113-25.compute-1.amazonaws.com",
                "dummy_obj": {
                    "res_key": "res_value",
                },
                "dummy_array": ["arr_val1", "arr_val2"],
            },
            "Limits": {"CPU": 512, "Memory": 512},
            "Usage": {"CPU": 12.12},
        }
    }

    # Attach network device.
    test_microvm.add_net_iface()

    # Configure MMDS version.
    configure_mmds(test_microvm, iface_ids=["eth0"], version=version)
    # Populate data store with contents.
    populate_data_store(test_microvm, data_store)

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()
    ssh_connection = test_microvm.ssh

    cmd = "ip route add {} dev eth0".format(DEFAULT_IPV4)
    run_guest_cmd(ssh_connection, cmd, "")

    token = None
    if version == "V2":
        # Generate token.
        token = generate_mmds_session_token(ssh_connection, DEFAULT_IPV4, token_ttl=60)

    pre = generate_mmds_get_request(DEFAULT_IPV4, token=token, app_json=False)

    cmd = pre + "latest/meta-data/"
    expected = (
        "ami-id\n"
        "dummy_array\n"
        "dummy_obj/\n"
        "local-hostname\n"
        "public-hostname\n"
        "reservation-id"
    )

    run_guest_cmd(ssh_connection, cmd, expected)

    cmd = pre + "latest/meta-data/ami-id/"
    run_guest_cmd(ssh_connection, cmd, "ami-12345678")

    cmd = pre + "latest/meta-data/dummy_array/0"
    run_guest_cmd(ssh_connection, cmd, "arr_val1")

    cmd = pre + "latest/Usage/CPU"
    run_guest_cmd(
        ssh_connection,
        cmd,
        "Cannot retrieve value. The value has" " an unsupported type.",
    )

    cmd = pre + "latest/Limits/CPU"
    run_guest_cmd(
        ssh_connection,
        cmd,
        "Cannot retrieve value. The value has" " an unsupported type.",
    )


@pytest.mark.parametrize("version", MMDS_VERSIONS)
def test_larger_than_mss_payloads(test_microvm_with_api, version):
    """
    Test MMDS content for payloads larger than MSS.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Attach network device.
    test_microvm.add_net_iface()
    # Configure MMDS version.
    configure_mmds(test_microvm, iface_ids=["eth0"], version=version)

    # The MMDS is empty at this point.
    response = test_microvm.api.mmds.get()
    assert response.json() == {}

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()

    # Make sure MTU is 1500 bytes.
    ssh_connection = test_microvm.ssh

    run_guest_cmd(ssh_connection, "ip link set dev eth0 mtu 1500", "")

    cmd = 'ip a s eth0 | grep -i mtu | tr -s " " | cut -d " " -f 4,5'
    run_guest_cmd(ssh_connection, cmd, "mtu 1500\n")

    # These values are usually used by booted up guest network interfaces.
    mtu = 1500
    ipv4_packet_headers_len = 20
    tcp_segment_headers_len = 20
    mss = mtu - ipv4_packet_headers_len - tcp_segment_headers_len

    # Generate a random MMDS content, double of MSS.
    letters = string.ascii_lowercase
    larger_than_mss = "".join(random.choice(letters) for i in range(2 * mss))
    mss_equal = "".join(random.choice(letters) for i in range(mss))
    lower_than_mss = "".join(random.choice(letters) for i in range(mss - 2))
    data_store = {
        "larger_than_mss": larger_than_mss,
        "mss_equal": mss_equal,
        "lower_than_mss": lower_than_mss,
    }
    test_microvm.api.mmds.put(**data_store)

    response = test_microvm.api.mmds.get()
    assert response.json() == data_store

    run_guest_cmd(ssh_connection, f"ip route add {DEFAULT_IPV4} dev eth0", "")

    token = None
    if version == "V2":
        # Generate token.
        token = generate_mmds_session_token(ssh_connection, DEFAULT_IPV4, token_ttl=60)

    pre = generate_mmds_get_request(DEFAULT_IPV4, token=token, app_json=False)

    cmd = pre + "larger_than_mss"
    run_guest_cmd(ssh_connection, cmd, larger_than_mss)

    cmd = pre + "mss_equal"
    run_guest_cmd(ssh_connection, cmd, mss_equal)

    cmd = pre + "lower_than_mss"
    run_guest_cmd(ssh_connection, cmd, lower_than_mss)


@pytest.mark.parametrize("version", MMDS_VERSIONS)
def test_mmds_dummy(test_microvm_with_api, version):
    """
    Test the API and guest facing features of the microVM MetaData Service.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Attach network device.
    test_microvm.add_net_iface()
    # Configure MMDS version.
    configure_mmds(test_microvm, iface_ids=["eth0"], version=version)

    # The MMDS is empty at this point.
    response = test_microvm.api.mmds.get()
    assert response.json() == {}

    # Test that patch return NotInitialized when the MMDS is not initialized.
    dummy_json = {"latest": {"meta-data": {"ami-id": "dummy"}}}
    with pytest.raises(RuntimeError, match="The MMDS data store is not initialized."):
        test_microvm.api.mmds.patch(**dummy_json)

    # Test that using the same json with a PUT request, the MMDS data-store is
    # created.
    response = test_microvm.api.mmds.put(**dummy_json)

    response = test_microvm.api.mmds.get()
    assert response.json() == dummy_json

    response = test_microvm.api.mmds.get()
    assert response.json() == dummy_json

    dummy_json = {
        "latest": {
            "meta-data": {
                "ami-id": "another_dummy",
                "secret_key": "eaasda48141411aeaeae",
            }
        }
    }
    response = test_microvm.api.mmds.patch(**dummy_json)
    response = test_microvm.api.mmds.get()
    assert response.json() == dummy_json


@pytest.mark.parametrize("version", MMDS_VERSIONS)
def test_guest_mmds_hang(test_microvm_with_api, version):
    """
    Test the MMDS json endpoint when Content-Length larger than actual length.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Attach network device.
    test_microvm.add_net_iface()
    # Configure MMDS version.
    configure_mmds(test_microvm, iface_ids=["eth0"], version=version)

    data_store = {"latest": {"meta-data": {"ami-id": "ami-12345678"}}}
    populate_data_store(test_microvm, data_store)

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()
    ssh_connection = test_microvm.ssh

    run_guest_cmd(ssh_connection, f"ip route add {DEFAULT_IPV4} dev eth0", "")

    get_cmd = "curl -m 2 -s"
    get_cmd += " -X GET"
    get_cmd += ' -H  "Content-Length: 100"'
    get_cmd += ' -H "Accept: application/json"'
    get_cmd += ' -d "some body"'
    get_cmd += f" http://{DEFAULT_IPV4}/"

    if version == "V1":
        _, stdout, _ = ssh_connection.run(get_cmd)
        assert "Invalid request" in stdout
    else:
        # Generate token.
        token = generate_mmds_session_token(ssh_connection, DEFAULT_IPV4, token_ttl=60)

        get_cmd += ' -H  "X-metadata-token: {}"'.format(token)
        _, stdout, _ = ssh_connection.run(get_cmd)
        assert "Invalid request" in stdout

        # Do the same for a PUT request.
        cmd = "curl -m 2 -s"
        cmd += " -X PUT"
        cmd += ' -H  "Content-Length: 100"'
        cmd += ' -H  "X-metadata-token: {}"'.format(token)
        cmd += ' -H "Accept: application/json"'
        cmd += ' -d "some body"'
        cmd += " http://{}/".format(DEFAULT_IPV4)

        _, stdout, _ = ssh_connection.run(cmd)
        assert "Invalid request" in stdout


@pytest.mark.parametrize("version", MMDS_VERSIONS)
def test_mmds_limit_scenario(test_microvm_with_api, version):
    """
    Test the MMDS json endpoint when data store size reaches the limit.
    """
    test_microvm = test_microvm_with_api
    # Set a large enough limit for the API so that requests actually reach the
    # MMDS server.
    test_microvm.jailer.extra_args.update(
        {"http-api-max-payload-size": "512000", "mmds-size-limit": "51200"}
    )
    test_microvm.spawn()

    # Attach network device.
    test_microvm.add_net_iface()
    # Configure MMDS version.
    configure_mmds(test_microvm, iface_ids=["eth0"], version=version)

    dummy_json = {"latest": {"meta-data": {"ami-id": "dummy"}}}

    # Populate data-store.
    response = test_microvm.api.mmds.put(**dummy_json)

    # Send a request that will exceed the data store.
    aux = "a" * 51200
    large_json = {"latest": {"meta-data": {"ami-id": "smth", "secret_key": aux}}}
    with pytest.raises(RuntimeError, match="413"):
        response = test_microvm.api.mmds.put(**large_json)

    response = test_microvm.api.mmds.get()
    assert response.json() == dummy_json

    # Send a request that will fill the data store.
    aux = "a" * 51137
    dummy_json = {"latest": {"meta-data": {"ami-id": "smth", "secret_key": aux}}}
    test_microvm.api.mmds.patch(**dummy_json)

    # Try to send a new patch thaw will increase the data store size. Since the
    # actual size is equal with the limit this request should fail with
    # PayloadTooLarge.
    aux = "b" * 10
    dummy_json = {"latest": {"meta-data": {"ami-id": "smth", "secret_key2": aux}}}
    with pytest.raises(RuntimeError, match="413"):
        response = test_microvm.api.mmds.patch(**dummy_json)

    # Check that the patch actually failed and the contents of the data store
    # has not changed.
    response = test_microvm.api.mmds.get()
    assert str(response.json()).find(aux) == -1

    # Delete something from the mmds so we will be able to send new data.
    dummy_json = {"latest": {"meta-data": {"ami-id": "smth", "secret_key": "a"}}}
    test_microvm.api.mmds.patch(**dummy_json)

    # Check that the size has shrunk.
    response = test_microvm.api.mmds.get()
    assert len(str(response.json()).replace(" ", "")) == 59

    # Try to send a new patch, this time the request should succeed.
    aux = "a" * 100
    dummy_json = {"latest": {"meta-data": {"ami-id": "smth", "secret_key": aux}}}
    response = test_microvm.api.mmds.patch(**dummy_json)

    # Check that the size grew as expected.
    response = test_microvm.api.mmds.get()
    assert len(str(response.json()).replace(" ", "")) == 158


@pytest.mark.parametrize("version", MMDS_VERSIONS)
def test_mmds_snapshot(uvm_nano, microvm_factory, version, firecracker_release):
    """
    Test MMDS behavior by restoring a snapshot on current FC versions.

    Ensures that the version is persisted or initialised with the default if
    the firecracker version does not support it.
    """

    uvm_nano.add_net_iface()
    _validate_mmds_snapshot(
        uvm_nano,
        microvm_factory,
        version,
        target_fc_version=firecracker_release.snapshot_version,
        fc_binary_path=firecracker_release.path,
        jailer_binary_path=firecracker_release.jailer,
    )


def test_mmds_older_snapshot(
    microvm_factory, guest_kernel, rootfs, firecracker_release
):
    """
    Test MMDS behavior restoring older snapshots in the current version.

    Ensures that the MMDS version is persisted or initialised with the default
    if the FC version does not support this feature.
    """

    # due to bug fixed in commit 8dab78b
    firecracker_version = firecracker_release.version_tuple
    if global_props.instance == "m6a.metal" and firecracker_version < (1, 3, 3):
        pytest.skip("incompatible with AMD and Firecracker <1.3.3")

    microvm = microvm_factory.build(
        guest_kernel,
        rootfs,
        fc_binary_path=firecracker_release.path,
        jailer_binary_path=firecracker_release.jailer,
    )
    microvm.spawn()
    microvm.basic_config()
    microvm.add_net_iface()

    mmds_version = "V2"
    _validate_mmds_snapshot(
        microvm,
        microvm_factory,
        mmds_version,
        firecracker_release.snapshot_version,
        *get_firecracker_binaries(),
    )


def test_mmds_v2_negative(test_microvm_with_api):
    """
    Test invalid MMDS GET/PUT requests when using V2.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Attach network device.
    test_microvm.add_net_iface()
    # Configure MMDS version.
    configure_mmds(test_microvm, version="V2", iface_ids=["eth0"])

    data_store = {
        "latest": {
            "meta-data": {
                "ami-id": "ami-12345678",
                "reservation-id": "r-fea54097",
                "local-hostname": "ip-10-251-50-12.ec2.internal",
                "public-hostname": "ec2-203-0-113-25.compute-1.amazonaws.com",
            }
        }
    }
    populate_data_store(test_microvm, data_store)

    test_microvm.basic_config(vcpu_count=1)
    test_microvm.start()
    ssh_connection = test_microvm.ssh

    run_guest_cmd(ssh_connection, f"ip route add {DEFAULT_IPV4} dev eth0", "")

    # Check `GET` request fails when token is not provided.
    cmd = generate_mmds_get_request(DEFAULT_IPV4)
    expected = (
        "No MMDS token provided. Use `X-metadata-token` header "
        "to specify the session token."
    )
    run_guest_cmd(ssh_connection, cmd, expected)

    # Generic `GET` request.

    # Check `GET` request fails when token is not valid.
    run_guest_cmd(
        ssh_connection,
        generate_mmds_get_request(DEFAULT_IPV4, token="foo"),
        "MMDS token not valid.",
    )

    # Check `PUT` request fails when token TTL is not provided.
    cmd = f"curl -m 2 -s -X PUT http://{DEFAULT_IPV4}/latest/api/token"
    expected = (
        "Token time to live value not found. Use "
        "`X-metadata-token-ttl-seconds` header to specify "
        "the token's lifetime."
    )
    run_guest_cmd(ssh_connection, cmd, expected)

    # Check `PUT` request fails when `X-Forwarded-For` header is provided.
    cmd = "curl -m 2 -s"
    cmd += " -X PUT"
    cmd += ' -H  "X-Forwarded-For: foo"'
    cmd += f" http://{DEFAULT_IPV4}"
    expected = (
        "Invalid header. Reason: Unsupported header name. " "Key: X-Forwarded-For"
    )
    run_guest_cmd(ssh_connection, cmd, expected)

    # Generic `PUT` request.
    put_cmd = "curl -m 2 -s"
    put_cmd += " -X PUT"
    put_cmd += ' -H  "X-metadata-token-ttl-seconds: {}"'
    put_cmd += f" {DEFAULT_IPV4}/latest/api/token"

    # Check `PUT` request fails when path is invalid.
    # Path is invalid because we remove the last character
    # at the end of the valid uri.
    run_guest_cmd(
        ssh_connection, put_cmd[:-1].format(60), "Resource not found: /latest/api/toke."
    )

    # Check `PUT` request fails when token TTL is not valid.
    ttl_values = [MIN_TOKEN_TTL_SECONDS - 1, MAX_TOKEN_TTL_SECONDS + 1]
    for ttl in ttl_values:
        expected = (
            "Invalid time to live value provided for token: {}. "
            "Please provide a value between {} and {}.".format(
                ttl, MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS
            )
        )
        run_guest_cmd(ssh_connection, put_cmd.format(ttl), expected)

    # Valid `PUT` request to generate token.
    _, stdout, _ = ssh_connection.run(put_cmd.format(1))
    token = stdout
    assert len(token) > 0

    # Wait for token to expire.
    time.sleep(1)
    # Check `GET` request fails when expired token is provided.
    run_guest_cmd(
        ssh_connection,
        generate_mmds_get_request(DEFAULT_IPV4, token=token),
        "MMDS token not valid.",
    )


def test_deprecated_mmds_config(test_microvm_with_api):
    """
    Test deprecated Mmds configs.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    # Attach network device.
    test_microvm.add_net_iface()
    # Use the default version, which is 1 for backwards compatibility.
    response = configure_mmds(test_microvm, iface_ids=["eth0"])
    assert "deprecation" in response.headers

    response = configure_mmds(test_microvm, iface_ids=["eth0"], version="V1")
    assert "deprecation" in response.headers

    response = configure_mmds(test_microvm, iface_ids=["eth0"], version="V2")
    assert "deprecation" not in response.headers

    test_microvm.start()
    datapoints = test_microvm.get_all_metrics()

    assert (
        sum(
            datapoint["deprecated_api"]["deprecated_http_api_calls"]
            for datapoint in datapoints
        )
        == 2
    )
