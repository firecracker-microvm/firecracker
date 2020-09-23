# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for the Firecracker serial console."""

import fcntl
import os
import termios
import time
from subprocess import run, PIPE

from framework.microvm import Serial
from framework.state_machine import TestState


class WaitLogin(TestState):  # pylint: disable=too-few-public-methods
    """Initial state when we wait for the login prompt."""

    def handle_input(self, serial, input_char) -> TestState:
        """Handle input and return next state."""
        if self.match(input_char):
            time.sleep(2)
            # Send login username.
            serial.tx("root")
            time.sleep(2)
            return WaitPasswordPrompt("Password:")
        return self


class WaitPasswordPrompt(TestState):  # pylint: disable=too-few-public-methods
    """Wait for the password prompt to be shown."""

    def handle_input(self, serial, input_char) -> TestState:
        """Handle input and return next state."""
        if self.match(input_char):
            serial.tx("root")
            time.sleep(2)
            serial.tx("id")
            time.sleep(2)
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


def test_serial_console_login(test_microvm_with_ssh):
    """Test serial console login."""
    microvm = test_microvm_with_ssh
    microvm.jailer.daemonize = False
    microvm.spawn()

    # We don't need to monitor the memory for this test because we are
    # just rebooting and the process dies before pmap gets the RSS.
    microvm.memory_events_queue = None

    # Set up the microVM with 1 vCPU and a serial console.
    microvm.basic_config(vcpu_count=1,
                         boot_args='console=ttyS0 reboot=k panic=1 pci=off')
    microvm.start()

    serial = Serial(microvm)
    serial.open()

    # Set initial state - wait for 'login:' prompt
    current_state = WaitLogin("login:")
    while not isinstance(current_state, TestFinished):
        output_char = serial.rx_char()
        current_state = current_state.handle_input(
            serial, output_char)


def get_total_mem_size(pid):
    """Get total memory usage for a process."""
    cmd = f"pmap {pid} | tail -n 1 | sed 's/^ //' | tr -s ' ' | cut -d' ' -f2"
    proc = run(cmd, check=True, shell=True, stdout=PIPE)
    return proc.stdout.decode()


def send_bytes(tty, bytes_count, timeout=60):
    """Send data to the terminal."""
    start = time.time()
    for _ in range(bytes_count):
        fcntl.ioctl(tty, termios.TIOCSTI, 'a')
        current = time.time()
        if current - start > timeout:
            break


def test_serial_dos(test_microvm_with_ssh):
    """Test serial console behavior when it is under DoS."""
    microvm = test_microvm_with_ssh
    microvm.jailer.daemonize = False
    microvm.spawn()
    microvm.memory_events_queue = None

    # Set up the microVM with 1 vCPU and a serial console.
    microvm.basic_config(vcpu_count=1,
                         boot_args='console=ttyS0 reboot=k panic=1 pci=off')
    microvm.start()

    # Get Firecracker process TTY.
    tty_path = f"/proc/{microvm.jailer_clone_pid}/fd/0"
    tty_fd = os.open(tty_path, os.O_RDWR)

    # Check if the total memory size changed.
    before_size = get_total_mem_size(microvm.jailer_clone_pid)
    # Send 100MB at maximum to the terminal backed by our serial device.
    # In practice, we send bytes in a burst for only 1 seconds. This is
    # sufficient for exercising serial device buffer capacity.
    send_bytes(tty_fd, bytes_count=100000000, timeout=1)
    after_size = get_total_mem_size(microvm.jailer_clone_pid)
    assert before_size == after_size, "The memory size of the " \
                                      "Firecracker process " \
                                      "changed from {} to {}." \
        .format(before_size,
                after_size)
