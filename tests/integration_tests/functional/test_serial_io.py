# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for the Firecracker serial console."""

import fcntl
import os
import platform
import signal
import termios
import time

from framework import utils
from framework.microvm import Serial
from framework.state_machine import TestState

PLATFORM = platform.machine()


class WaitTerminal(TestState):  # pylint: disable=too-few-public-methods
    """Initial state when we wait for the login prompt."""

    def handle_input(self, serial, input_char) -> TestState:
        """Handle input and return next state."""
        if self.match(input_char):
            serial.tx("id")
            return WaitIDResult("uid=0(root) gid=0(root) groups=0(root)")
        return self


class WaitIDResult(TestState):  # pylint: disable=too-few-public-methods
    """Wait for the console to show the result of the 'id' shell command."""

    def handle_input(self, unused_serial, input_char) -> TestState:
        """Handle input and return next state."""
        if self.match(input_char):
            return TestFinished()
        return self


class TestFinished(TestState):  # pylint: disable=too-few-public-methods
    """Test complete and successful."""

    def handle_input(self, unused_serial, _) -> TestState:
        """Return self since the test is about to end."""
        return self


def test_serial_after_snapshot(uvm_plain, microvm_factory):
    """
    Serial I/O after restoring from a snapshot.
    """
    microvm = uvm_plain
    microvm.help.enable_console()
    microvm.spawn()
    microvm.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
        boot_args="console=ttyS0 reboot=k panic=1 pci=off",
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
    vm.spawn()
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


def test_serial_console_login(uvm_plain_any):
    """
    Test serial console login.
    """
    microvm = uvm_plain_any
    microvm.help.enable_console()
    microvm.spawn()

    # We don't need to monitor the memory for this test because we are
    # just rebooting and the process dies before pmap gets the RSS.
    microvm.memory_monitor = None

    # Set up the microVM with 1 vCPU and a serial console.
    microvm.basic_config(
        vcpu_count=1, boot_args="console=ttyS0 reboot=k panic=1 pci=off"
    )

    microvm.start()

    serial = Serial(microvm)
    serial.open()
    current_state = WaitTerminal("ubuntu-fc-uvm:")

    while not isinstance(current_state, TestFinished):
        output_char = serial.rx_char()
        current_state = current_state.handle_input(serial, output_char)


def get_total_mem_size(pid):
    """Get total memory usage for a process."""
    cmd = f"pmap {pid} | tail -n 1 | sed 's/^ //' | tr -s ' ' | cut -d' ' -f2"
    _, stdout, stderr = utils.check_output(cmd)
    assert stderr == ""

    return stdout


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
        boot_args="console=ttyS0 reboot=k panic=1 pci=off",
    )
    microvm.start()

    # Open an fd for firecracker process terminal.
    tty_path = f"/proc/{microvm.firecracker_pid}/fd/0"
    tty_fd = os.open(tty_path, os.O_RDWR)

    # Check if the total memory size changed.
    before_size = get_total_mem_size(microvm.firecracker_pid)
    send_bytes(tty_fd, 100000000, timeout=1)
    after_size = get_total_mem_size(microvm.firecracker_pid)
    assert before_size == after_size, (
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
    test_microvm.spawn()
    # Set up the microVM with 1 vCPU so we make sure the vCPU thread
    # responsible for the SSH connection will also run the serial.
    test_microvm.basic_config(
        vcpu_count=1,
        mem_size_mib=512,
        boot_args="console=ttyS0 reboot=k panic=1 pci=off",
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
    test_microvm.wait_for_up()

    assert REGISTER_FAILED_WARNING not in test_microvm.log_data
