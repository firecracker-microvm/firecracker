# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for the Firecracker serial console."""
import time
from framework.microvm import Serial
from framework.state_machine import TestState


class WaitLogin(TestState):  # pylint: disable=too-few-public-methods
    """Initial state when we wait for the login prompt."""

    def handle_input(self, serial, input_char) -> TestState:
        """Handle input and return next state."""
        if self.match(input_char):
            # Send login username.
            serial.tx("root")
            return WaitPasswordPrompt("Password:")
        return self


class WaitPasswordPrompt(TestState):  # pylint: disable=too-few-public-methods
    """Wait for the password prompt to be shown."""

    def handle_input(self, serial, input_char) -> TestState:
        """Handle input and return next state."""
        if self.match(input_char):
            serial.tx("root")
            # Wait 1 second for shell
            time.sleep(1)
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
