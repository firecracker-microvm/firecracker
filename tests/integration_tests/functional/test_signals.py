# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for Firecracker signal handling."""

import json
import os
import resource as res
import subprocess
import urllib.parse
from signal import SIGBUS, SIGHUP, SIGILL, SIGPIPE, SIGSEGV, SIGSYS, SIGXCPU, SIGXFSZ
from time import sleep

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel, pin_rootfs_mode
from framework.http_api import Session

signum_str = {
    SIGBUS: "sigbus",
    SIGSEGV: "sigsegv",
    SIGXFSZ: "sigxfsz",
    SIGXCPU: "sigxcpu",
    SIGPIPE: "sigpipe",
    SIGHUP: "sighup",
    SIGILL: "sigill",
    SIGSYS: "sigsys",
}


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
@pytest.mark.parametrize(
    "signum", [SIGBUS, SIGSEGV, SIGXFSZ, SIGXCPU, SIGPIPE, SIGHUP, SIGILL, SIGSYS]
)
def test_generic_signal_handler(uvm, signum):
    """
    Test signal handling for all handled signals.
    """
    microvm = uvm
    microvm.spawn()

    # We don't need to monitor the memory for this test.
    microvm.memory_monitor = None

    microvm.basic_config()
    microvm.start()
    sleep(0.5)

    metrics_jail_path = microvm.metrics_file
    metrics_fd = open(metrics_jail_path, encoding="utf-8")
    line_metrics = metrics_fd.readlines()
    assert len(line_metrics) == 1

    os.kill(microvm.firecracker_pid, signum)
    # Firecracker gracefully handles SIGPIPE (doesn't terminate) and logs nothing.
    if signum == int(SIGPIPE):
        # Flush metrics to file, so we can see the SIGPIPE at bottom assert.
        # This is going to fail if process has exited.
        microvm.api.actions.put(action_type="FlushMetrics")
    else:
        msg = "Shutting down VM after intercepting signal {}".format(signum)

        microvm.mark_killed()

        microvm.check_log_message(msg)

    if signum != SIGSYS:
        metric_line = json.loads(metrics_fd.readlines()[0])
        assert metric_line["signals"][signum_str[signum]] == 1


def test_sigpipe_from_log_write(microvm_factory, tmp_path):
    """
    Test that a SIGPIPE raised by Firecracker's own log write is survivable.

    With no log path configured the log target is stdout, so putting stdout on a
    pipe and dropping the read end makes the next request log, and so raise
    SIGPIPE on the thread that is already inside the log write.
    """
    sock = tmp_path / "fc.sock"
    url = f"http+unix://{urllib.parse.quote(str(sock), safe='')}/"
    read_fd, write_fd = os.pipe()
    proc = subprocess.Popen(
        [str(microvm_factory.fc_binary_path), "--api-sock", str(sock)],
        stdout=write_fd,
        stderr=write_fd,
    )
    os.close(write_fd)
    try:
        for _ in range(100):
            if sock.exists():
                break
            sleep(0.05)

        session = Session()
        assert session.get(url, timeout=5).status_code == 200

        # Drop the read end, so the log write of the next request gets EPIPE.
        os.close(read_fd)
        read_fd = None

        assert session.get(url, timeout=5).status_code == 200
        assert proc.poll() is None, f"Firecracker exited with {proc.poll()}"
    finally:
        if read_fd is not None:
            os.close(read_fd)
        proc.kill()
        proc.wait()


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
@pin_rootfs_mode("rw")
def test_sigxfsz_handler(uvm):
    """
    Test intercepting and handling SIGXFSZ.
    """
    microvm = uvm
    microvm.spawn()

    # We don't need to monitor the memory for this test.
    microvm.memory_monitor = None

    # We need to use the Sync file engine type. If we use io_uring we will not
    # get a SIGXFSZ. We'll instead get an errno 27 File too large as the
    # completed entry status code.
    microvm.basic_config(rootfs_io_engine="Sync")
    microvm.start()

    metrics_jail_path = microvm.metrics_file
    metrics_fd = open(metrics_jail_path, encoding="utf-8")
    line_metrics = metrics_fd.readlines()
    assert len(line_metrics) == 1

    firecracker_pid = microvm.firecracker_pid
    size = os.path.getsize(metrics_jail_path)
    # The SIGXFSZ is triggered because the size of rootfs is bigger than
    # the size of metrics file times 3. Since the metrics file is flushed
    # twice we have to make sure that the limit is bigger than that
    # in order to make sure the SIGXFSZ metric is logged
    res.prlimit(firecracker_pid, res.RLIMIT_FSIZE, (size * 3, res.RLIM_INFINITY))

    microvm.mark_killed()

    msg = "Shutting down VM after intercepting signal 25, code 0"
    microvm.check_log_message(msg)
    metric_line = json.loads(metrics_fd.readlines()[0])
    assert metric_line["signals"]["sigxfsz"] == 1


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_handled_signals(uvm):
    """
    Test that handled signals don't kill the microVM.
    """
    microvm = uvm
    microvm.spawn()

    # We don't need to monitor the memory for this test.
    microvm.memory_monitor = None

    microvm.basic_config(vcpu_count=2)
    microvm.add_net_iface()
    microvm.start()

    # Open a SSH connection to validate the microVM stays alive.
    # Just validate a simple command: `nproc`
    cmd = "nproc"
    _, stdout, stderr = microvm.ssh.run(cmd)
    assert stderr == ""
    assert int(stdout) == 2

    # We have a handler installed for this signal.
    # The 35 is the SIGRTMIN for musl libc.
    # We hardcode this value since the SIGRTMIN python reports
    # is 34, which is likely the one for glibc.
    os.kill(microvm.firecracker_pid, 35)

    # Validate the microVM is still up and running.
    _, stdout, stderr = microvm.ssh.run(cmd)
    assert stderr == ""
    assert int(stdout) == 2
