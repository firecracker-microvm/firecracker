# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Contains vsock functional tests."""

import threading

from subprocess import run
from time import sleep

import pytest

import host_tools.network as net_tools


def test_vsock_ping_pong(test_microvm_with_ssh, network_config, aux_bin_paths):
    """Test a vsock device.

    Creates a VM which has a vsock device attached, and them attempts
    to communicate over a vsock connection using a simple client/server app.
    """
    vm = test_microvm_with_ssh
    if vm.build_feature != 'vsock':
        pytest.skip("This test is meant only for vsock builds")

    vm.spawn()
    vm.basic_config()
    _tap, _, _ = vm.ssh_network_config(network_config, '1')

    response = vm.vsock.put(
        vsock_id='vsock1',
        guest_cid=100
    )
    assert vm.api_session.is_good_response(response.status_code)

    vm.start()

    test_vsock = aux_bin_paths['test_vsock']
    remote_test_vsock = '/tmp/test_vsock'

    ssh_connection = net_tools.SSHConnection(vm.ssh_config)
    ssh_connection.scp_file(test_vsock, remote_test_vsock)

    server_thread = threading.Thread(
        target=(lambda: run(
            '{} server'.format(test_vsock),
            shell=True,
            check=True)
        )
    )
    server_thread.start()

    # Wait for the server to start.
    sleep(1)

    guest_cmd = '{0} client 2 ; rm {0}'.format(remote_test_vsock)

    _, stdout, stderr = ssh_connection.execute_command(guest_cmd)
    assert stderr.read().decode('utf-8') == ''
    assert stdout.read().decode('utf-8').strip() == '1235'

    server_thread.join()
