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
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from pathlib import Path
from socket import timeout as SocketTimeout

import pytest

from framework.utils_vsock import (
    ECHO_SERVER_PORT,
    VSOCK_UDS_PATH,
    HostEchoWorker,
    _copy_vsock_data_to_guest,
    boot_vsock_vm,
    check_guest_connections,
    check_host_connections,
    check_vsock_device,
    host_echo_server,
    make_blob,
    make_host_port_path,
    start_guest_echo_server,
    vsock_connect_to_guest,
)
from host_tools.fcmetrics import validate_fc_metrics

NEGATIVE_TEST_CONNECTION_COUNT = 100
TEST_WORKER_COUNT = 10


@pytest.fixture
def vsock_uvm(uvm_plain_acpi, request):
    """Fixture to initialize a microVM with vsock device."""
    vcpus = request.param if hasattr(request, "param") else 1

    return boot_vsock_vm(
        uvm_plain_acpi,
        vcpu_count=vcpus,
        mem_size_mib=1024,
        log_level="Info",
        emit_metrics=True,
        pin_threads=True,
    )


@pytest.fixture
def vsock_uvm_any(uvm_plain_any):
    """Fixture to initialize a kernel-parametrized microVM with vsock device."""
    return boot_vsock_vm(uvm_plain_any)


def test_vsock(vsock_uvm_any, bin_vsock_path, test_fc_session_root_path):
    """
    Test guest and host vsock initiated connections.

    Check the module docstring for details on the setup.
    """

    vm = vsock_uvm_any

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

    with ExitStack() as stack:
        workers = [
            stack.enter_context(HostEchoWorker(uds_path, blob_path))
            for _ in range(NEGATIVE_TEST_CONNECTION_COUNT)
        ]
        for wrk in workers:
            wrk.start()

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


def test_vsock_epipe(vsock_uvm_any, bin_vsock_path, test_fc_session_root_path):
    """
    Vsock negative test to validate SIGPIPE/EPIPE handling.
    """
    vm = vsock_uvm_any

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


@pytest.mark.parametrize("vsock_uvm", [1, 2], indirect=True, ids=["1vcpu", "2vcpu"])
def test_vsock_transport_reset_h2g(
    vsock_uvm, microvm_factory, bin_vsock_path, test_fc_session_root_path
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
    test_vm = vsock_uvm

    # Generate the random data blob file.
    blob_path, blob_hash = make_blob(test_fc_session_root_path)
    vm_blob_path = "/tmp/vsock/test.blob"

    # Set up a tmpfs drive on the guest, so we can copy the blob there.
    # Guest-initiated connections (echo workers) will use this blob.
    _copy_vsock_data_to_guest(test_vm.ssh, blob_path, vm_blob_path, bin_vsock_path)

    # Start guest echo server.
    path = start_guest_echo_server(test_vm)

    # Start host workers that connect to the guest server.
    with ExitStack() as stack:
        workers = [
            stack.enter_context(HostEchoWorker(path, blob_path))
            for _ in range(TEST_WORKER_COUNT)
        ]
        for wrk in workers:
            wrk.start()

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


@pytest.mark.parametrize("vsock_uvm", [1, 2], indirect=True, ids=["1vcpu", "2vcpu"])
def test_vsock_transport_reset_g2h(vsock_uvm, microvm_factory):
    """
    Vsock transport reset test.
    """
    test_vm = vsock_uvm

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

        try:
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
        finally:
            # Kill host socat as it is not useful anymore. Done in `finally`
            # so that an assertion failure earlier in the iteration does not
            # leak a `socat` process into the next iteration (or the next
            # test).
            host_socat.kill()
            host_socat.communicate()

            # Terminate VM.
            new_vm.kill()


def test_vsock_after_override(
    uvm_plain_any, microvm_factory, bin_vsock_path, test_fc_session_root_path
):
    """
    Test that the Vsock device works correctly after overriding the host UDS
    path on snapshot restore.
    """
    initial_uds_path = VSOCK_UDS_PATH
    overridden_uds_path = f"{VSOCK_UDS_PATH}2"

    test_vm = uvm_plain_any
    test_vm.spawn()
    test_vm.basic_config(vcpu_count=2, mem_size_mib=256)
    test_vm.add_net_iface()
    test_vm.api.vsock.put(
        vsock_id="vsock0", guest_cid=3, uds_path=f"/{initial_uds_path}"
    )
    test_vm.start()

    # Generate the random data blob file.
    blob_path, blob_hash = make_blob(test_fc_session_root_path)
    vm_blob_path = "/tmp/vsock/test.blob"

    # Set up a tmpfs drive on the guest, so we can copy the blob there.
    # Guest-initiated connections (echo workers) will use this blob.
    _copy_vsock_data_to_guest(test_vm.ssh, blob_path, vm_blob_path, bin_vsock_path)

    # Start guest echo server.
    start_guest_echo_server(test_vm)

    # Create snapshot and terminate a VM.
    snapshot = test_vm.snapshot_full()
    test_vm.kill()

    vm2 = microvm_factory.build()
    vm2.spawn()

    vm2.restore_from_snapshot(snapshot, vsock_override=overridden_uds_path, resume=True)

    # Check that vsock device still works.
    # Test guest-initiated connections.
    path = os.path.join(
        vm2.path, make_host_port_path(overridden_uds_path, ECHO_SERVER_PORT)
    )
    check_guest_connections(vm2, path, vm_blob_path, blob_hash)

    # Test host-initiated connections.
    path = os.path.join(vm2.jailer.chroot_path(), overridden_uds_path)
    check_host_connections(path, blob_path, blob_hash)
    metrics = vm2.flush_metrics()
    validate_fc_metrics(metrics)


def test_vsock_override_fails_without_device(uvm_plain_any, microvm_factory):
    """
    Providing an override should fail if there is no vsock device.
    """

    overridden_uds_path = f"{VSOCK_UDS_PATH}2"

    test_vm = uvm_plain_any
    test_vm.spawn()
    test_vm.basic_config(vcpu_count=2, mem_size_mib=256)
    test_vm.start()

    snapshot = test_vm.snapshot_full()
    test_vm.kill()

    vm2 = microvm_factory.build()
    vm2.spawn()

    # The failed snapshot load causes Firecracker to exit.
    with pytest.raises(RuntimeError, match="Unknown Vsock Device"):
        vm2.restore_from_snapshot(
            snapshot, vsock_override=overridden_uds_path, resume=True
        )

    vm2.mark_killed()


@pytest.mark.nonci
def test_vsock_post_restore_connect_storm(
    microvm_factory,
    guest_kernel,
    rootfs,
    bin_vsock_path,
    test_fc_session_root_path,
):
    """Regression test for the post-snapshot-restore RX/EVQ race.

    Requires PCI MSI-X and >=2 vCPUs. `storm_size` must stay <= guest
    socat backlog (128) to avoid unrelated sk_acceptq_is_full OP_RST.
    """
    blob_path, _blob_hash = make_blob(test_fc_session_root_path)
    vm_blob_path = "/tmp/vsock/test.blob"

    test_vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    test_vm.spawn()
    test_vm.basic_config(vcpu_count=4, mem_size_mib=256)
    test_vm.add_net_iface()
    test_vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path=f"/{VSOCK_UDS_PATH}")
    test_vm.start()

    _copy_vsock_data_to_guest(test_vm.ssh, blob_path, vm_blob_path, bin_vsock_path)
    uds_path_pre = start_guest_echo_server(test_vm)

    with ExitStack() as stack:
        for _ in range(32):
            stack.enter_context(vsock_connect_to_guest(uds_path_pre, ECHO_SERVER_PORT))

        snapshot = test_vm.snapshot_full()
        test_vm.kill()

    storm_size = 64
    iterations = 30
    payload = b"vsock-race-probe-" + b"x" * 4096 + b"\n"

    def worker(sock, ready):
        sock.settimeout(5.0)
        ready.wait()
        try:
            sock.send(f"CONNECT {ECHO_SERVER_PORT}\n".encode("utf-8"))
            ack = sock.recv(32)
            if not ack.startswith(b"OK "):
                return f"bad ack: {ack!r}"
            sock.send(payload)
            received = b""
            while len(received) < len(payload):
                chunk = sock.recv(len(payload) - len(received))
                if not chunk:
                    return f"echo truncated: {received!r}"
                received += chunk
            if received != payload:
                return f"echo mismatch: {received!r}"
            return None
        except (ConnectionResetError, BrokenPipeError, SocketTimeout) as exc:
            return f"socket error: {type(exc).__name__}: {exc}"

    for _ in range(iterations):
        vm = microvm_factory.build()
        try:
            vm.spawn()
            vm.restore_from_snapshot(snapshot, resume=False)

            uds_path = os.path.join(vm.jailer.chroot_path(), VSOCK_UDS_PATH)

            with ExitStack() as stack:
                socks = []
                for _ in range(storm_size):
                    s = stack.enter_context(
                        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    )
                    s.connect(uds_path)
                    socks.append(s)

                ready = threading.Barrier(storm_size + 1)
                with ThreadPoolExecutor(max_workers=storm_size) as pool:
                    futures = [pool.submit(worker, s, ready) for s in socks]
                    vm.resume()
                    ready.wait()
                    errors = [f.result() for f in as_completed(futures)]

                failed = [e for e in errors if e is not None]
                assert not failed, (
                    f"post-restore connect storm hit the RX/EVQ race "
                    f"({len(failed)}/{storm_size} connections broken): {failed[:5]}"
                )

                metrics = vm.flush_metrics()
                validate_fc_metrics(metrics)
        finally:
            vm.kill()


def test_snapshot_restore_with_inflight_vsock_tx(
    vsock_uvm, bin_vsock_path, tmp_path, microvm_factory
):
    """
    Guest-initiated vsock connections must still work after a snapshot taken
    while the guest is actively transmitting.

    If a guest TX descriptor is un-consumed when the snapshot is created, the
    restored TX queue has avail_idx ahead of avail_event; with EVENT_IDX the
    guest then suppresses all TX notifications and guest-initiated connections
    hang. Unlike test_cycled_snapshot_restore (which snapshots after traffic has
    drained, so it only hits this by chance), this test snapshots while a guest
    worker is streaming, making the in-flight condition reliable.
    """
    vm = vsock_uvm

    vm_blob_path = "/tmp/vsock/test.blob"
    blob_path, blob_hash = make_blob(tmp_path)
    _copy_vsock_data_to_guest(vm.ssh, blob_path, vm_blob_path, bin_vsock_path)

    server_port_path = os.path.join(
        vm.path, make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT)
    )
    with host_echo_server(vm, server_port_path):
        # Continuously stream guest->host so the TX queue is non-empty when the
        # snapshot is taken.
        vm.ssh.check_output(
            "nohup sh -c 'while true; do "
            f"cat {vm_blob_path} | /tmp/vsock_helper echo 2 {ECHO_SERVER_PORT} "
            ">/dev/null 2>&1; done' >/dev/null 2>&1 &"
        )
        # Let the stream ramp up so traffic is genuinely in-flight.
        time.sleep(2)
        snapshot = vm.snapshot_full()
    vm.kill()

    # Restore and verify a *fresh* guest-initiated connection works -- this is
    # what hangs when a TX descriptor was in-flight at snapshot time.
    new_vm = microvm_factory.build_from_snapshot(snapshot)
    path = os.path.join(
        new_vm.path, make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT)
    )
    check_guest_connections(new_vm, path, vm_blob_path, blob_hash)
