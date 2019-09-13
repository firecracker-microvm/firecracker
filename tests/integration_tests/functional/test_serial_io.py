# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario for the Firecracker serial console."""
import os
import time
import select


# Too few public methods (1/2) (too-few-public-methods)
# pylint: disable=R0903
class MatchStaticString:
    """Match a static string versus input."""

    # Prevent state objects from being collected by pytest.
    __test__ = False

    def __init__(self, match_string):
        """Initialize using specified match string."""
        self._string = match_string
        self._input = ""

    def match(self, input_char) -> bool:
        """
        Check if `_input` matches the match `_string`.

        Process one char at a time and build `_input` string.
        Preserve built `_input` if partially matches `_string`.
        Return True when `_input` is the same as `_string`.
        """
        self._input += str(input_char)
        if self._input == self._string[:len(self._input)]:
            if len(self._input) == len(self._string):
                self._input = ""
                return True
            return False

        self._input = self._input[1:]
        return False


class TestState(MatchStaticString):
    """Generic test state object."""

    # Prevent state objects from being collected by pytest.
    __test__ = False

    def __init__(self, match_string=''):
        """Initialize state fields."""
        MatchStaticString.__init__(self, match_string)
        print('\n*** Current test state: ', str(self), end='')

    def handle_input(self, microvm, input_char):
        """Handle input event and return next state."""

    def __repr__(self):
        """Leverages the __str__ method to describe the TestState."""
        return self.__str__()

    def __str__(self):
        """Return state name."""
        return self.__class__.__name__


class WaitLogin(TestState):
    """Initial state when we wait for the login prompt."""

    def handle_input(self, microvm, input_char) -> TestState:
        """Handle input and return next state."""
        if self.match(input_char):
            # Send login username.
            microvm.serial_input("root")
            return WaitPasswordPrompt("Password:")
        return self


class WaitPasswordPrompt(TestState):
    """Wait for the password prompt to be shown."""

    def handle_input(self, microvm, input_char) -> TestState:
        """Handle input and return next state."""
        if self.match(input_char):
            microvm.serial_input("root")
            # Wait 1 second for shell
            time.sleep(1)
            microvm.serial_input("id")
            return WaitIDResult("uid=0(root) gid=0(root) groups=0(root)")
        return self


class WaitIDResult(TestState):
    """Wait for the console to show the result of the 'id' shell command."""

    def handle_input(self, microvm, input_char) -> TestState:
        """Handle input and return next state."""
        if self.match(input_char):
            return TestFinished()
        return self


class TestFinished(TestState):
    """Test complete and successful."""

    def handle_input(self, microvm, input_char) -> TestState:
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

    # Screen stdout log
    screen_log = "/tmp/screen.log"

    # Open the screen log file.
    screen_log_fd = os.open(screen_log, os.O_RDONLY)
    poller = select.poll()

    # Set initial state - wait for 'login:' prompt
    current_state = WaitLogin("login:")

    poller.register(screen_log_fd, select.POLLIN | select.POLLHUP)

    while not isinstance(current_state, TestFinished):
        result = poller.poll(0.1)
        for fd, flag in result:
            if flag & select.POLLIN:
                output_char = str(os.read(fd, 1),
                                  encoding='utf-8',
                                  errors='ignore')
                # [DEBUG] Uncomment to see the serial console output.
                # print(output_char, end='')
                current_state = current_state.handle_input(
                                microvm, output_char)
            elif flag & select.POLLHUP:
                assert False, "Oh! The console vanished before test completed."
    os.close(screen_log_fd)
