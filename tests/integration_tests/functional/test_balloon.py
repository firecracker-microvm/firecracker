# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for memory ballooning functionality."""

import os

import host_tools.network as net_tools  # pylint: disable=import-error


def test_balloon(test_microvm_with_ssh_and_balloon, network_config):
    """Verify that inflating a balloon leaves the guest with less memory."""
    test_microvm = test_microvm_with_ssh_and_balloon
    test_microvm.spawn()

    # Set up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    # a root file system with the rw permission. The network interface is
    # added after we get a unique MAC and IP.
    test_microvm.basic_config()

    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
    test_microvm.ssh_config['ssh_key_path'] = os.path.join(
        test_microvm.fsfiles,
        'debian.rootfs.id_rsa'
    )

    # Install deflated balloon.
    response = test_microvm.balloon.put(
        num_pages=0,
        deflate_on_oom=False,
        must_tell_host=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    _, stdout, stderr = ssh_connection.execute_command('free')
    assert stderr.read().decode('utf-8') == ''
    available_mem_deflated = _available_mem(stdout.read().decode('utf-8'))

    # Inflate 64 MB == 16384 page balloon.
    response = test_microvm.balloon.patch(
        num_pages=16384
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    _, stdout, stderr = ssh_connection.execute_command('free')
    assert stderr.read().decode('utf-8') == ''
    available_mem_inflated = _available_mem(stdout.read().decode('utf-8'))
    assert  available_mem_inflated < available_mem_deflated


def _available_mem(free_output):
    for line in free_output.split('\n'):
        if line.startswith('Mem:'):
            # 'available' is the last column.
            return int(line.split()[-1])
    raise Exception('Available memory not found in `free` output')
