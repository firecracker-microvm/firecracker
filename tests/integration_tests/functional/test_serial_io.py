# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for the Firecracker serial console."""

import fcntl
import os
import platform
import signal
import termios
import time
from pathlib import Path

from framework import utils
from framework.microvm import Serial

PLATFORM = platform.machine()


def test_serial_after_snapshot(uvm_plain, microvm_factory):
    """
    Serial I/O after restoring from a snapshot.
    """
    microvm = uvm_plain
    microvm.help.enable_console()
    microvm.spawn(serial_out_path=None)
    microvm.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
    )
    serial = Serial(microvm)
    serial.open()
    microvm.start()

    # looking for the # prompt at the end
    serial.rx("ubuntu-fc-uvm:~#")

    # Create snapshot.
    snapshot = microvm.snapshot_full()
    # Kill base microVM.
    microvm.kill()

    # Load microVM clone from snapshot.
    vm = microvm_factory.build()
    vm.help.enable_console()
    vm.spawn(serial_out_path=None)
    vm.restore_from_snapshot(snapshot, resume=True)
    serial = Serial(vm)
    serial.open()
    # We need to send a newline to signal the serial to flush
    # the login content.
    serial.tx("")

    # looking for the # prompt at the end
    serial.rx("ubuntu-fc-uvm:~#")
    serial.tx("pwd")
    res = serial.rx("#")
    assert "/root" in res


def test_serial_active_tx_snapshot(uvm_plain, microvm_factory):
    """
    Snapshot a guest that is actively transmitting on the serial console and
    test that the transmission continues after snapshot restore.
    """
    microvm = uvm_plain
    microvm.help.enable_console()
    microvm.spawn(serial_out_path=None)
    microvm.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
    )
    serial = Serial(microvm)
    serial.open()
    microvm.start()

    # looking for the # prompt at the end
    serial.rx("ubuntu-fc-uvm:~#")

    # Start an unbounded serial transmission from inside the guest such that
    # there will be an active transmission at the point of pausing the VM to
    # take the snapshot. This will saturate the TX buffer of the UART and it
    # might make the guest driver enable TX interrupts.
    serial.tx("cat /dev/zero")
    # Give the guest time to start the transmission
    time.sleep(1)

    # Create snapshot.
    snapshot = microvm.snapshot_full()
    # Kill base microVM.
    microvm.kill()

    # Load microVM clone from snapshot.
    vm = microvm_factory.build()
    vm.help.enable_console()
    vm.spawn(serial_out_path=None)
    vm.restore_from_snapshot(snapshot, resume=True)
    serial = Serial(vm)
    serial.open()

    # Send Ctrl-C to the guest to stop the ongoing transmission and regain the shell
    serial.tx("\x03", end="")
    # looking for the # prompt at the end
    serial.rx("ubuntu-fc-uvm:~#")
    serial.tx("pwd")
    res = serial.rx("#")
    assert "/root" in res


def test_serial_console_login(uvm_plain_any):
    """
    Test serial console login.
    """
    microvm = uvm_plain_any
    microvm.help.enable_console()
    microvm.spawn(serial_out_path=None)

    # We don't need to monitor the memory for this test because we are
    # just rebooting and the process dies before pmap gets the RSS.
    microvm.memory_monitor = None

    # Set up the microVM with 1 vCPU and a serial console.
    microvm.basic_config(vcpu_count=1)

    microvm.start()

    serial = Serial(microvm)
    serial.open()
    serial.rx("ubuntu-fc-uvm:")
    serial.tx("id")
    serial.rx("uid=0(root) gid=0(root) groups=0(root)")


def get_total_mem_size(pid):
    """Get total memory usage for a process."""
    cmd = f"pmap {pid} | tail -n 1 | sed 's/^ //' | tr -s ' ' | cut -d' ' -f2"
    _, stdout, stderr = utils.check_output(cmd)
    assert stderr == ""

    # This assumes that the pmap returns something in the form of
    # 123456789K (which is typically the case for us)
    return float(stdout.strip()[:-1] * 1000)


def send_bytes(tty, bytes_count, timeout=60):
    """Send data to the terminal."""
    start = time.time()
    for _ in range(bytes_count):
        fcntl.ioctl(tty, termios.TIOCSTI, "\n")
        current = time.time()
        if current - start > timeout:
            break


def test_serial_dos(uvm_plain_any):
    """
    Test serial console behavior under DoS.
    """
    microvm = uvm_plain_any
    microvm.help.enable_console()
    microvm.spawn()

    # Set up the microVM with 1 vCPU and a serial console.
    microvm.basic_config(
        vcpu_count=1,
    )
    microvm.add_net_iface()
    microvm.start()

    # Open an fd for firecracker process terminal.
    tty_path = f"/proc/{microvm.firecracker_pid}/fd/0"
    tty_fd = os.open(tty_path, os.O_RDWR)

    # Check if the total memory size changed.
    before_size = get_total_mem_size(microvm.firecracker_pid)
    send_bytes(tty_fd, 100000000, timeout=1)
    after_size = get_total_mem_size(microvm.firecracker_pid)
    # Give the check a bit of tolerance (1%) since sometimes random unrelated
    # allocations break it.
    assert after_size <= (before_size * 1.01), (
        "The memory size of the "
        "Firecracker process "
        "changed from {} to {}.".format(before_size, after_size)
    )


def test_serial_block(uvm_plain_any):
    """
    Test that writing to stdout never blocks the vCPU thread.
    """
    test_microvm = uvm_plain_any
    test_microvm.help.enable_console()
    test_microvm.spawn(serial_out_path=None)
    # Set up the microVM with 1 vCPU so we make sure the vCPU thread
    # responsible for the SSH connection will also run the serial.
    test_microvm.basic_config(
        vcpu_count=1,
        mem_size_mib=512,
    )
    test_microvm.add_net_iface()
    test_microvm.start()

    # Get an initial reading of missed writes to the serial.
    fc_metrics = test_microvm.flush_metrics()
    init_count = fc_metrics["uart"]["missed_write_count"]

    # Stop `screen` process which captures stdout so we stop consuming stdout.
    os.kill(test_microvm.screen_pid, signal.SIGSTOP)

    # Generate a random text file.
    test_microvm.ssh.check_output(
        "base64 /dev/urandom | head -c 100000 > /tmp/file.txt"
    )

    # Dump output to terminal
    test_microvm.ssh.check_output("cat /tmp/file.txt > /dev/ttyS0")

    # Check that the vCPU isn't blocked.
    test_microvm.ssh.check_output("cd /")

    # Check the metrics to see if the serial missed bytes.
    fc_metrics = test_microvm.flush_metrics()
    last_count = fc_metrics["uart"]["missed_write_count"]

    # Should be significantly more than before the `cat` command.
    assert last_count - init_count > 10000


REGISTER_FAILED_WARNING = "Failed to register serial input fd: event_manager: failed to manage epoll file descriptor: Operation not permitted (os error 1)"


def test_no_serial_fd_error_when_daemonized(uvm_plain):
    """
    Tests that when running firecracker daemonized, the serial device
    does not try to register stdin to epoll (which would fail due to stdin no
    longer being pointed at a terminal).

    Regression test for #4037.
    """

    test_microvm = uvm_plain
    test_microvm.spawn()
    test_microvm.add_net_iface()
    test_microvm.basic_config(
        vcpu_count=1,
        mem_size_mib=512,
    )
    test_microvm.start()

    assert REGISTER_FAILED_WARNING not in test_microvm.log_data


def test_serial_file_output(uvm_any):
    """Test that redirecting serial console output to a file works for booted and restored VMs"""
    uvm_any.ssh.check_output("echo 'hello' > /dev/ttyS0")

    assert b"hello" in uvm_any.serial_out_path.read_bytes()


def test_serial_rate_limiting(uvm_plain):
    """Test that serial output is rate-limited when a rate limiter is configured."""
    microvm = uvm_plain
    microvm.spawn()
    microvm.add_net_iface()
    microvm.basic_config(vcpu_count=1, mem_size_mib=256)

    # Configure serial output to a file with a rate limiter:
    # 1 KiB/sec sustained, 64 KiB one-time burst.
    serial_path = Path(microvm.path) / "serial.log"
    serial_path.touch()
    microvm.create_jailed_resource(serial_path)
    microvm.api.serial.put(
        serial_out_path="serial.log",
        rate_limiter={"size": 1024, "one_time_burst": 65536, "refill_time": 1000},
    )
    microvm.start()

    size_before = serial_path.stat().st_size

    # Write a large payload (~1MB) from the guest to the serial port.
    microvm.ssh.check_output("base64 /dev/urandom | head -c 1000000 > /dev/ttyS0")

    # Wait for any in-flight writes to settle.
    time.sleep(2)

    # With 64 KiB burst + ~2s at 1 KiB/sec, output should be well under 80 KB.
    new_bytes = serial_path.stat().st_size - size_before
    assert new_bytes < 80000, (
        f"Serial output is {new_bytes} bytes, "
        "expected under 80000 due to rate limiting"
    )

    # Verify the rate_limiter_dropped_bytes metric was incremented.
    fc_metrics = microvm.flush_metrics()
    assert fc_metrics["uart"]["rate_limiter_dropped_bytes"] > 0
