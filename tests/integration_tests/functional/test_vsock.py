# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the virtio-vsock device.

In order to test the vsock device connection state machine, these tests will:
- Generate a 20MiB random data blob;
- Use `host_tools/vsock_helper.c` to start a listening echo server inside the
  guest VM;
- Run 50, concurrent, host-initiated connections, each transfering the random
  blob to and from the guest echo server;
- For every connection, check that the data received back from the echo server
  hashes to the same value as the data sent;
- Start a host echo server, and repeat the process for the same number of
  guest-initiated connections.
"""

import os.path

from framework.utils_vsock import make_blob, \
    check_host_connections, check_guest_connections
from host_tools.network import SSHConnection

VSOCK_UDS_PATH = "v.sock"
ECHO_SERVER_PORT = 5252
BLOB_SIZE = 20 * 1024 * 1024


def test_vsock(
        test_microvm_with_ssh,
        network_config,
        bin_vsock_path,
        test_fc_session_root_path
):
    """Vsock tests. See the module docstring for a high-level description."""
    vm = test_microvm_with_ssh
    vm.spawn()

    vm.basic_config()
    _tap, _, _ = vm.ssh_network_config(network_config, '1')
    vm.vsock.put(
        vsock_id="vsock0",
        guest_cid=3,
        uds_path="/{}".format(VSOCK_UDS_PATH)
    )

    vm.start()

    # Generate the random data blob file.
    blob_path, blob_hash = make_blob(test_fc_session_root_path)
    vm_blob_path = "/tmp/vsock/test.blob"

    # Set up a tmpfs drive on the guest, so we can copy the blob there.
    # Guest-initiated connections (echo workers) will use this blob.
    conn = SSHConnection(vm.ssh_config)
    cmd = "mkdir -p /tmp/vsock"
    cmd += " && mount -t tmpfs tmpfs -o size={} /tmp/vsock".format(
        BLOB_SIZE + 1024*1024
    )
    ecode, _, _ = conn.execute_command(cmd)
    assert ecode == 0

    # Copy `vsock_helper` and the random blob to the guest.
    vsock_helper = bin_vsock_path
    conn.scp_file(vsock_helper, '/bin/vsock_helper')
    conn.scp_file(blob_path, vm_blob_path)

    # Test guest-initiated connections.
    path = os.path.join(
        vm.path,
        _make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT)
    )
    check_guest_connections(vm, path, vm_blob_path, blob_hash)

    # Test host-initiated connections.
    path = os.path.join(vm.jailer.chroot_path(), VSOCK_UDS_PATH)
    check_host_connections(vm, path, blob_path, blob_hash)


def _make_host_port_path(uds_path, port):
    """Build the path for a Unix socket, mapped to host vsock port `port`."""
    return "{}_{}".format(uds_path, port)
