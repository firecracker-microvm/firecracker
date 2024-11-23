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
import subprocess
import time
from pathlib import Path
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
from host_tools.fcmetrics import validate_fc_metrics

NEGATIVE_TEST_CONNECTION_COUNT = 100
TEST_WORKER_COUNT = 10


def test_vsock(uvm_plain_any, bin_vsock_path, test_fc_session_root_path):
    """
    Test guest and host vsock initiated connections.

    Check the module docstring for details on the setup.
    """

    vm = uvm_plain_any
    vm.spawn()

    vm.basic_config()
    vm.add_net_iface()
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path=f"/{VSOCK_UDS_PATH}")
    vm.start()

    check_vsock_device(vm, bin_vsock_path, test_fc_session_root_path, vm.ssh)
    metrics = vm.flush_metrics()
    validate_fc_metrics(metrics)


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

    # Validate that guest is still up and running.
    # Should fail if Firecracker exited from SIGPIPE handler.

    metrics = vm.flush_metrics()
    validate_fc_metrics(metrics)

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
    metrics = vm.flush_metrics()
    validate_fc_metrics(metrics)


def test_vsock_epipe(uvm_plain, bin_vsock_path, test_fc_session_root_path):
    """
    Vsock negative test to validate SIGPIPE/EPIPE handling.
    """
    vm = uvm_plain
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
    metrics = vm.flush_metrics()
    validate_fc_metrics(metrics)


def test_vsock_transport_reset_h2g(
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
            assert (
                response == b""
            ), f"Connection not closed: response received '{response.decode('utf-8')}'"
        except (SocketTimeout, ConnectionResetError, BrokenPipeError):
            pass

    # Terminate VM.
    metrics = test_vm.flush_metrics()
    validate_fc_metrics(metrics)
    test_vm.kill()

    # Load snapshot.
    vm2 = microvm_factory.build_from_snapshot(snapshot)

    # Check that vsock device still works.
    # Test guest-initiated connections.
    path = os.path.join(vm2.path, make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT))
    check_guest_connections(vm2, path, vm_blob_path, blob_hash)

    # Test host-initiated connections.
    path = os.path.join(vm2.jailer.chroot_path(), VSOCK_UDS_PATH)
    check_host_connections(path, blob_path, blob_hash)
    metrics = vm2.flush_metrics()
    validate_fc_metrics(metrics)


def test_vsock_transport_reset_g2h(uvm_nano, microvm_factory):
    """
    Vsock transport reset test.
    """
    test_vm = uvm_nano
    test_vm.add_net_iface()
    test_vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path=f"/{VSOCK_UDS_PATH}")
    test_vm.start()

    # Create snapshot and terminate a VM.
    snapshot = test_vm.snapshot_full()
    test_vm.kill()

    for _ in range(5):
        # Load snapshot.
        new_vm = microvm_factory.build_from_snapshot(snapshot)

        # After snap restore all vsock connections should be
        # dropped. This means guest socat should exit same way
        # as it did after snapshot was taken.
        code, _, _ = new_vm.ssh.run("pidof socat")
        assert code == 1

        host_socket_path = os.path.join(
            new_vm.path, f"{VSOCK_UDS_PATH}_{ECHO_SERVER_PORT}"
        )
        host_socat_commmand = [
            "socat",
            "-dddd",
            f"UNIX-LISTEN:{host_socket_path},fork",
            "STDOUT",
        ]
        host_socat = subprocess.Popen(
            host_socat_commmand, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # Give some time for host socat to create socket
        time.sleep(0.5)
        assert Path(host_socket_path).exists()
        new_vm.create_jailed_resource(host_socket_path)

        # Create a socat process in the guest which will connect to the host socat
        guest_socat_commmand = (
            f"tmux new -d 'socat - vsock-connect:2:{ECHO_SERVER_PORT}'"
        )
        new_vm.ssh.run(guest_socat_commmand)

        # socat should be running in the guest now
        code, _, _ = new_vm.ssh.run("pidof socat")
        assert code == 0

        # Create snapshot.
        snapshot = new_vm.snapshot_full()
        new_vm.resume()

        # After `create_snapshot` + 'restore' calls, connection should be dropped
        code, _, _ = new_vm.ssh.run("pidof socat")
        assert code == 1

        # Kill host socat as it is not useful anymore
        host_socat.kill()
        host_socat.communicate()

        # Terminate VM.
        new_vm.kill()
