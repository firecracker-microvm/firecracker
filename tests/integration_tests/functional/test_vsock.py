# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the virtio-vsock device.

In order to test the vsock device connection state machine, these tests will:
- Generate a 20MiB random data blob;
- Use `socat` to start a listening echo server inside the guest VM;
- Run 50, concurrent, host-initiated connections, each transfering the random
  blob to and from the guest echo server;
- For every connection, check that the data received back from the echo server
  hashes to the same value as the data sent;
- Start a host echo server, and repeat the process for the same number of
  guest-initiated connections.
"""

import os.path
from socket import timeout as SocketTimeout

from framework.utils_vsock import (
    ECHO_SERVER_PORT,
    VSOCK_UDS_PATH,
    HostEchoWorker,
    _copy_vsock_data_to_guest,
    check_guest_connections,
    check_host_connections,
    check_vsock_device,
    make_blob,
    make_host_port_path,
    start_guest_echo_server,
)

NEGATIVE_TEST_CONNECTION_COUNT = 100
TEST_WORKER_COUNT = 10


def test_vsock(test_microvm_with_api, bin_vsock_path, test_fc_session_root_path):
    """
    Test guest and host vsock initiated connections.

    Check the module docstring for details on the setup.
    """

    vm = test_microvm_with_api
    vm.spawn()

    vm.basic_config()
    vm.add_net_iface()
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path=f"/{VSOCK_UDS_PATH}")
    vm.start()

    check_vsock_device(vm, bin_vsock_path, test_fc_session_root_path, vm.ssh)


def negative_test_host_connections(vm, blob_path, blob_hash):
    """Negative test for host-initiated connections.

    This will start a daemonized echo server on the guest VM, and then spawn
    `NEGATIVE_TEST_CONNECTION_COUNT` `HostEchoWorker` threads.
    Closes the UDS sockets while data is in flight.
    """

    uds_path = start_guest_echo_server(vm)

    workers = []
    for _ in range(NEGATIVE_TEST_CONNECTION_COUNT):
        worker = HostEchoWorker(uds_path, blob_path)
        workers.append(worker)
        worker.start()

    for wrk in workers:
        wrk.close_uds()
        wrk.join()

    # Validate that Firecracker is still up and running.
    ecode, _, _ = vm.ssh.run("sync")
    # Should fail if Firecracker exited from SIGPIPE handler.
    assert ecode == 0

    metrics = vm.flush_metrics()
    # Validate that at least 1 `SIGPIPE` signal was received.
    # Since we are reusing the existing echo server which triggers
    # reads/writes on the UDS backend connections, these might be closed
    # before a read() or a write() is about to be performed by the emulation.
    # The test uses 100 connections it is enough to close at least one
    # before write().
    #
    # If this ever fails due to 100 closes before read() we must
    # add extra tooling that will trigger only writes().
    assert metrics["signals"]["sigpipe"] > 0

    # Validate vsock emulation still accepts connections and works
    # as expected. Use the default blob size to speed up the test.
    blob_path, blob_hash = make_blob(os.path.dirname(blob_path))
    check_host_connections(uds_path, blob_path, blob_hash)


def test_vsock_epipe(test_microvm_with_api, bin_vsock_path, test_fc_session_root_path):
    """
    Vsock negative test to validate SIGPIPE/EPIPE handling.
    """
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path=f"/{VSOCK_UDS_PATH}")
    vm.start()

    # Generate the random data blob file, 20MB
    blob_path, blob_hash = make_blob(test_fc_session_root_path, 20 * 2**20)
    vm_blob_path = "/tmp/vsock/test.blob"

    # Set up a tmpfs drive on the guest, so we can copy the blob there.
    # Guest-initiated connections (echo workers) will use this blob.
    _copy_vsock_data_to_guest(vm.ssh, blob_path, vm_blob_path, bin_vsock_path)

    # Negative test for host-initiated connections that
    # are closed with in flight data.
    negative_test_host_connections(vm, blob_path, blob_hash)


def test_vsock_transport_reset(
    uvm_nano, microvm_factory, bin_vsock_path, test_fc_session_root_path
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
    test_vm = uvm_nano
    test_vm.add_net_iface()
    test_vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path=f"/{VSOCK_UDS_PATH}")
    test_vm.start()

    # Generate the random data blob file.
    blob_path, blob_hash = make_blob(test_fc_session_root_path)
    vm_blob_path = "/tmp/vsock/test.blob"

    # Set up a tmpfs drive on the guest, so we can copy the blob there.
    # Guest-initiated connections (echo workers) will use this blob.
    _copy_vsock_data_to_guest(test_vm.ssh, blob_path, vm_blob_path, bin_vsock_path)

    # Start guest echo server.
    path = start_guest_echo_server(test_vm)

    # Start host workers that connect to the guest server.
    workers = []
    for _ in range(TEST_WORKER_COUNT):
        worker = HostEchoWorker(path, blob_path)
        workers.append(worker)
        worker.start()

    for wrk in workers:
        wrk.join()

    # Create snapshot.
    snapshot = test_vm.snapshot_full()
    test_vm.resume()

    # Check that sockets are no longer working on workers.
    for worker in workers:
        # Whatever we send to the server, it should return the same
        # value.
        buf = bytearray("TEST\n".encode("utf-8"))
        try:
            worker.sock.send(buf)
            # Arbitrary timeout, we set this so the socket won't block as
            # it shouldn't receive anything.
            worker.sock.settimeout(0.25)
            response = worker.sock.recv(32)
            if response != b"":
                # If we reach here, it means the connection did not close.
                assert False, "Connection not closed: response recieved '{}'".format(
                    response.decode("utf-8")
                )
        except (SocketTimeout, ConnectionResetError, BrokenPipeError):
            assert True

    # Terminate VM.
    test_vm.kill()

    # Load snapshot.

    vm2 = microvm_factory.build()
    vm2.spawn()
    vm2.restore_from_snapshot(snapshot, resume=True)

    # Check that vsock device still works.
    # Test guest-initiated connections.
    path = os.path.join(vm2.path, make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT))
    check_guest_connections(vm2, path, vm_blob_path, blob_hash)

    # Test host-initiated connections.
    path = os.path.join(vm2.jailer.chroot_path(), VSOCK_UDS_PATH)
    check_host_connections(path, blob_path, blob_hash)
