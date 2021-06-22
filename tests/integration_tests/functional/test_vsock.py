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

from socket import timeout as SocketTimeout
from framework.utils_vsock import make_blob, \
    check_host_connections, check_guest_connections, \
    HostEchoWorker
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType

from host_tools.network import SSHConnection
import host_tools.logging as log_tools

VSOCK_UDS_PATH = "v.sock"
ECHO_SERVER_PORT = 5252
BLOB_SIZE = 20 * 1024 * 1024
NEGATIVE_TEST_CONNECTION_COUNT = 100
TEST_WORKER_COUNT = 10


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


def negative_test_host_connections(vm, uds_path, blob_path, blob_hash):
    """Negative test for host-initiated connections.

    This will start a daemonized echo server on the guest VM, and then spawn
    `NEGATIVE_TEST_CONNECTION_COUNT` `HostEchoWorker` threads.
    Closes the UDS sockets while data is in flight.
    """
    conn = SSHConnection(vm.ssh_config)
    cmd = "vsock_helper echosrv -d {}". format(ECHO_SERVER_PORT)
    ecode, _, _ = conn.execute_command(cmd)
    assert ecode == 0

    workers = []
    for _ in range(NEGATIVE_TEST_CONNECTION_COUNT):
        worker = HostEchoWorker(uds_path, blob_path)
        workers.append(worker)
        worker.start()

    for wrk in workers:
        wrk.close_uds()
        wrk.join()

    # Validate that Firecracker is still up and running.
    ecode, _, _ = conn.execute_command("sync")
    # Should fail if Firecracker exited from SIGPIPE handler.
    assert ecode == 0

    # Validate vsock emulation still accepts connections and works
    # as expected.
    check_host_connections(vm, uds_path, blob_path, blob_hash)


def test_vsock_epipe(
        test_microvm_with_ssh,
        network_config,
        bin_vsock_path,
        test_fc_session_root_path
):
    """Vsock negative test to validate SIGPIPE/EPIPE handling."""
    vm = test_microvm_with_ssh
    vm.spawn()

    vm.basic_config()
    _tap, _, _ = vm.ssh_network_config(network_config, '1')
    vm.vsock.put(
        vsock_id="vsock0",
        guest_cid=3,
        uds_path="/{}".format(VSOCK_UDS_PATH)
    )

    # Configure metrics to assert against `sigpipe` count.
    metrics_fifo_path = os.path.join(vm.path, 'metrics_fifo')
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = vm.metrics.put(
        metrics_path=vm.create_jailed_resource(metrics_fifo.path)
    )
    assert vm.api_session.is_status_no_content(response.status_code)

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

    path = os.path.join(vm.jailer.chroot_path(), VSOCK_UDS_PATH)
    # Negative test for host-initiated connections that
    # are closed with in flight data.
    negative_test_host_connections(vm, path, blob_path, blob_hash)

    metrics = vm.flush_metrics(metrics_fifo)
    # Validate that at least 1 `SIGPIPE` signal was received.
    # Since we are reusing the existing echo server which triggers
    # reads/writes on the UDS backend connections, these might be closed
    # before a read() or a write() is about to be performed by the emulation.
    # The test uses 100 connections it is enough to close at least one
    # before write().
    #
    # If this ever fails due to 100 closes before read() we must
    # add extra tooling that will trigger only writes().
    assert metrics['signals']['sigpipe'] > 0


def test_vsock_transport_reset(
        bin_cloner_path,
        bin_vsock_path,
        test_fc_session_root_path
):
    """
    Vsock transport reset test.

    Steps:
    1. Start echo server on the guest
    2. Start host workers that ping-pong data between guest and host,
    without closing any of them
    3. Pause VM -> Create snapshot -> Resume VM
    4. Check that worker sockets no longer work by setting a timeout
    so the sockets won't block and do a recv operation.
    5. If the recv operation timeouts, the connection was closed.
       Else, the connection was not closed and the test fails.
    6. Close VM -> Load VM from Snapshot -> check that vsock
       device is still working.
    """
    vm_builder = MicrovmBuilder(bin_cloner_path)
    vm_instance = vm_builder.build_vm_nano()
    test_vm = vm_instance.vm
    root_disk = vm_instance.disks[0]
    ssh_key = vm_instance.ssh_key

    test_vm.vsock.put(
        vsock_id="vsock0",
        guest_cid=3,
        uds_path="/{}".format(VSOCK_UDS_PATH)
    )

    test_vm.start()

    snapshot_builder = SnapshotBuilder(test_vm)
    disks = [root_disk.local_path()]

    # Generate the random data blob file.
    blob_path, blob_hash = make_blob(test_fc_session_root_path)
    vm_blob_path = "/tmp/vsock/test.blob"

    # Set up a tmpfs drive on the guest, so we can copy the blob there.
    # Guest-initiated connections (echo workers) will use this blob.
    conn = SSHConnection(test_vm.ssh_config)
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

    # Start guest echo server.
    path = os.path.join(test_vm.jailer.chroot_path(), VSOCK_UDS_PATH)
    conn = SSHConnection(test_vm.ssh_config)
    cmd = "vsock_helper echosrv -d {}". format(ECHO_SERVER_PORT)
    ecode, _, _ = conn.execute_command(cmd)
    assert ecode == 0

    # Start host workers that connect to the guest server.
    workers = []
    for _ in range(TEST_WORKER_COUNT):
        worker = HostEchoWorker(path, blob_path)
        workers.append(worker)
        worker.start()

    for wrk in workers:
        wrk.join()

    # Create snapshot.
    snapshot = snapshot_builder.create(disks,
                                       ssh_key,
                                       SnapshotType.FULL)
    response = test_vm.vm.patch(state='Resumed')
    assert test_vm.api_session.is_status_no_content(response.status_code)

    # Check that sockets are no longer working on workers.
    for worker in workers:
        # Whatever we send to the server, it should return the same
        # value.
        buf = bytearray("TEST\n".encode('utf-8'))
        worker.sock.send(buf)
        try:
            # Arbitrary timeout, we set this so the socket won't block as
            # it shouldn't receive anything.
            worker.sock.settimeout(0.25)
            response = worker.sock.recv(32)
            # If we reach here, it means the connection did not close.
            assert False, "Connection not closed: {}" \
                          .format(response.decode('utf-8'))
        except SocketTimeout as exc:
            assert True, exc

    # Terminate VM.
    test_vm.kill()

    # Load snapshot.
    test_vm, _ = vm_builder.build_from_snapshot(snapshot,
                                                True,
                                                False)

    # Check that vsock device still works.
    # Test guest-initiated connections.
    path = os.path.join(
        test_vm.path,
        _make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT)
    )
    check_guest_connections(test_vm, path, vm_blob_path, blob_hash)

    # Test host-initiated connections.
    path = os.path.join(test_vm.jailer.chroot_path(), VSOCK_UDS_PATH)
    check_host_connections(test_vm, path, blob_path, blob_hash)
