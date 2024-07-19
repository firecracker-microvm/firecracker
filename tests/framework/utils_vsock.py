# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helper functions for testing vsock device."""

import hashlib
import os.path
import re
import time
from pathlib import Path
from socket import AF_UNIX, SOCK_STREAM, socket
from subprocess import Popen
from threading import Thread

ECHO_SERVER_PORT = 5252
SERVER_ACCEPT_BACKLOG = 128
TEST_CONNECTION_COUNT = 50
BLOB_SIZE = 1 * 1024 * 1024
BUF_SIZE = 64 * 1024
VSOCK_UDS_PATH = "v.sock"


class HostEchoWorker(Thread):
    """A vsock echo worker, connecting to a guest echo server.

    This will initiate a connection to a guest echo server, then start sending
    it the contents of the file at `blob_path`. The echo server should send
    the exact same data back, so a hash is performed on everything received
    from the server. This hash will later be checked against the hashed
    contents of `blob_path`.
    """

    def __init__(self, uds_path, blob_path):
        """."""
        super().__init__()
        self.uds_path = uds_path
        self.blob_path = blob_path
        self.hash = None
        self.error = None
        self.sock = _vsock_connect_to_guest(self.uds_path, ECHO_SERVER_PORT)

    def run(self):
        """Thread code payload.

        Wrap up the real "run" into a catch-all block, because Python cannot
        into threads - if this thread were to raise an unhandled exception,
        the whole process would lock.
        """
        try:
            self._run()
        # pylint: disable=broad-except
        except Exception as err:
            self.error = err

    def close_uds(self):
        """Close vsock UDS connection."""
        self.sock.close()

    def _run(self):
        with open(self.blob_path, "rb") as blob_file:
            hash_obj = hashlib.md5()

            while True:
                buf = blob_file.read(BUF_SIZE)
                if not buf:
                    break

                sent = self.sock.send(buf)
                while sent < len(buf):
                    sent += self.sock.send(buf[sent:])

                buf = self.sock.recv(sent)
                while len(buf) < sent:
                    buf += self.sock.recv(sent - len(buf))

                hash_obj.update(buf)

            self.hash = hash_obj.hexdigest()


def make_blob(dst_dir, size=BLOB_SIZE):
    """Generate a random data file."""
    blob_path = os.path.join(dst_dir, "vsock-test.blob")

    with open(blob_path, "wb") as blob_file:
        left = size
        blob_hash = hashlib.md5()
        while left > 0:
            count = min(left, 4096)
            buf = os.urandom(count)
            blob_hash.update(buf)
            blob_file.write(buf)
            left -= count

    return blob_path, blob_hash.hexdigest()


def start_guest_echo_server(vm):
    """Start a vsock echo server in the microVM.

    Returns a UDS path to connect to the server.
    """
    cmd = f"nohup socat VSOCK-LISTEN:{ECHO_SERVER_PORT},backlog=128,reuseaddr,fork EXEC:'/bin/cat' > /dev/null 2>&1 &"
    vm.ssh.check_output(cmd)

    # Give the server time to initialise
    time.sleep(1)

    return os.path.join(vm.jailer.chroot_path(), VSOCK_UDS_PATH)


def check_host_connections(uds_path, blob_path, blob_hash):
    """Test host-initiated connections.

    This will spawn `TEST_CONNECTION_COUNT` `HostEchoWorker` threads.
    After the workers are done transferring the data read from `blob_path`,
    the hashes they computed for the data echoed back by the server are
    checked against `blob_hash`.
    """

    workers = []
    for _ in range(TEST_CONNECTION_COUNT):
        worker = HostEchoWorker(uds_path, blob_path)
        workers.append(worker)
        worker.start()

    for wrk in workers:
        wrk.join()

    for wrk in workers:
        assert wrk.hash == blob_hash


def check_guest_connections(vm, server_port_path, blob_path, blob_hash):
    """Test guest-initiated connections.

    This will start an echo server on the host (in its own thread), then
    start `TEST_CONNECTION_COUNT` workers inside the guest VM, all
    communicating with the echo server.
    """

    echo_server = Popen(
        ["socat", f"UNIX-LISTEN:{server_port_path},fork,backlog=5", "exec:'/bin/cat'"]
    )

    # Link the listening Unix socket into the VM's jail, so that
    # Firecracker can connect to it.
    attempt = 0
    # But 1st, give socat a bit of time to create the socket
    while not Path(server_port_path).exists() and attempt < 3:
        time.sleep(0.2)
        attempt += 1
    vm.create_jailed_resource(server_port_path)

    # Increase maximum process count for the ssh service.
    # Avoids: "bash: fork: retry: Resource temporarily unavailable"
    # Needed to execute the bash script that tests for concurrent
    # vsock guest initiated connections.
    pids_max_file = "/sys/fs/cgroup/system.slice/ssh.service/pids.max"
    ecode, _, _ = vm.ssh.run(f"echo 1024 > {pids_max_file}")
    assert ecode == 0, "Unable to set max process count for guest ssh service."

    # Build the guest worker sub-command.
    # `vsock_helper` will read the blob file from STDIN and send the echo
    # server response to STDOUT. This response is then hashed, and the
    # hash is compared against `blob_hash` (computed on the host). This
    # comparison sets the exit status of the worker command.
    worker_cmd = "hash=$("
    worker_cmd += "cat {}".format(blob_path)
    worker_cmd += " | /tmp/vsock_helper echo 2 {}".format(ECHO_SERVER_PORT)
    worker_cmd += " | md5sum | cut -f1 -d\\ "
    worker_cmd += ")"
    worker_cmd += ' && [[ "$hash" = "{}" ]]'.format(blob_hash)

    # Run `TEST_CONNECTION_COUNT` concurrent workers, using the above
    # worker sub-command.
    # If any worker fails, this command will fail. If all worker sub-commands
    # succeed, this will also succeed.
    cmd = 'workers="";'
    cmd += "for i in $(seq 1 {}); do".format(TEST_CONNECTION_COUNT)
    cmd += "  ({})& ".format(worker_cmd)
    cmd += '  workers="$workers $!";'
    cmd += "done;"
    cmd += "for w in $workers; do wait $w || exit -1; done"

    ecode, _, stderr = vm.ssh.run(cmd)
    echo_server.terminate()
    rc = echo_server.wait()
    # socat exits with 128 + 15 (SIGTERM)
    assert rc == 143

    assert ecode == 0, stderr


def make_host_port_path(uds_path, port):
    """Build the path for a Unix socket, mapped to host vsock port `port`."""
    return "{}_{}".format(uds_path, port)


def _vsock_connect_to_guest(uds_path, port):
    """Return a Unix socket, connected to the guest vsock port `port`."""
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(uds_path)

    buf = bytearray("CONNECT {}\n".format(port).encode("utf-8"))
    sock.send(buf)

    ack_buf = sock.recv(32)
    assert re.match("^OK [0-9]+\n$", ack_buf.decode("utf-8")) is not None

    return sock


def _copy_vsock_data_to_guest(ssh_connection, blob_path, vm_blob_path, vsock_helper):
    # Copy the data file and a vsock helper to the guest.

    cmd = "mkdir -p /tmp/vsock"
    ecode, _, _ = ssh_connection.run(cmd)
    assert ecode == 0, "Failed to set up tmpfs drive on the guest."

    ssh_connection.scp_put(vsock_helper, "/tmp/vsock_helper")
    ssh_connection.scp_put(blob_path, vm_blob_path)


def check_vsock_device(vm, bin_vsock_path, test_fc_session_root_path, ssh_connection):
    """Create a blob and test guest and host initiated connections on vsock."""
    vm_blob_path = "/tmp/vsock/test.blob"

    # Generate a random data file for vsock.
    blob_path, blob_hash = make_blob(test_fc_session_root_path)

    # Copy the data file and a vsock helper to the guest.
    _copy_vsock_data_to_guest(ssh_connection, blob_path, vm_blob_path, bin_vsock_path)

    # Test vsock guest-initiated connections.
    path = os.path.join(vm.path, make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT))
    check_guest_connections(vm, path, vm_blob_path, blob_hash)

    # Test vsock host-initiated connections.
    path = start_guest_echo_server(vm)
    check_host_connections(path, blob_path, blob_hash)
