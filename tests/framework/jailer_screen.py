# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run the jailer under a screen session"""

import os
import re
import select
import signal
import time
from pathlib import Path

import psutil
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_fixed

from framework import utils

from .jailer import JailerContext

FLUSH_CMD = 'screen -S {session} -X colon "logfile flush 0^M"'


def start_screen_process(screen_log, session_name, binary_path, binary_params):
    """Start binary process into a screen session."""
    start_cmd = "screen -L -Logfile {logfile} -dmS {session} {binary} {params}"
    start_cmd = start_cmd.format(
        logfile=screen_log,
        session=session_name,
        binary=binary_path,
        params=" ".join(binary_params),
    )

    utils.check_output(start_cmd)

    # Build a regex object to match (number).session_name
    regex_object = re.compile(r"([0-9]+)\.{}".format(session_name))

    # Run 'screen -ls' in a retry loop, 30 times with a 1s delay between calls.
    # If the output of 'screen -ls' matches the regex object, it will return the
    # PID. Otherwise, a RuntimeError will be raised.
    for attempt in Retrying(
        retry=retry_if_exception_type(RuntimeError),
        stop=stop_after_attempt(30),
        wait=wait_fixed(1),
        reraise=True,
    ):
        with attempt:
            screen_pid = utils.search_output_from_cmd(
                cmd="screen -ls", find_regex=regex_object
            ).group(1)

    screen_pid = int(screen_pid)
    # Make sure the screen process launched successfully
    # As the parent process for the binary.
    screen_ps = psutil.Process(screen_pid)

    for attempt in Retrying(
        stop=stop_after_attempt(5),
        wait=wait_fixed(0.5),
        reraise=True,
    ):
        with attempt:
            assert screen_ps.is_running()

    # Configure screen to flush stdout to file.
    utils.check_output(FLUSH_CMD.format(session=session_name))

    return screen_pid


class JailerScreen(JailerContext):
    """Spawn Firecracker under screen"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemonize = False
        self.screen_pid = None
        self.expect_kill_by_signal = False

    def spawn(self, pre_cmd):
        """Spawn Firecracker under screen"""
        self.screen_pid = None
        cmd = pre_cmd or []
        cmd += self.construct_param_list()
        # Run Firecracker under screen. This is used when we want to access
        # the serial console. The file will collect the output from
        # 'screen'ed Firecracker.
        self.screen_pid = start_screen_process(
            self.screen_log,
            self.screen_session,
            cmd[0],
            cmd[1:],
        )

        # If `--new-pid-ns` is used, the Firecracker process will detach from
        # the screen and the screen process will exit. We do not want to
        # attempt to kill it in that case to avoid a race condition.
        if self.new_pid_ns:
            self.screen_pid = None

    def kill(self):
        """Kill the Firecracker process"""
        if not self.screen_pid:
            raise RuntimeError("screen process not started")
        # Killing screen will send SIGHUP to underlying Firecracker.
        # Needed to avoid false positives in case kill() is called again.
        self.expect_kill_by_signal = True
        os.kill(self.screen_pid, signal.SIGKILL)
        os.kill(self.pid, signal.SIGKILL)

    @property
    def console_data(self):
        """Return the output of microVM's console"""
        if self.screen_log is None:
            return None
        file = Path(self.screen_log)
        if not file.exists():
            return None
        return file.read_text(encoding="utf-8")

    @property
    def screen_session(self):
        """The screen session name

        The id of this microVM, which should be unique.
        """
        return self.jailer_id

    @property
    def screen_log(self):
        """Get the screen log file."""
        return f"/tmp/screen-{self.screen_session}.log"

    def serial_input(self, input_string):
        """Send a string to the Firecracker serial console via screen."""
        input_cmd = f'screen -S {self.screen_session} -p 0 -X stuff "{input_string}"'
        return utils.check_output(input_cmd)

    def serial(self):
        """Get a Serial object for this jailer/microvm"""
        return Serial(self)


class Serial:
    """Class for serial console communication with a Microvm."""

    RX_TIMEOUT_S = 60

    def __init__(self, screen_jailer):
        """Initialize a new Serial object."""
        self._poller = None
        self._screen_jailer = screen_jailer

    def open(self):
        """Open a serial connection."""
        # Open the screen log file.
        if self._poller is not None:
            # serial already opened
            return

        attempt = 0
        while not Path(self._screen_jailer.screen_log).exists() and attempt < 5:
            time.sleep(0.2)
            attempt += 1

        screen_log_fd = os.open(self._screen_jailer.screen_log, os.O_RDONLY)
        self._poller = select.poll()
        self._poller.register(screen_log_fd, select.POLLIN | select.POLLHUP)

    def tx(self, input_string, end="\n"):
        # pylint: disable=invalid-name
        # No need to have a snake_case naming style for a single word.
        r"""Send a string terminated by an end token (defaulting to "\n")."""
        self._screen_jailer.serial_input(input_string + end)

    def rx_char(self):
        """Read a single character."""
        result = self._poller.poll(0.1)

        for fd, flag in result:
            if flag & select.POLLHUP:
                assert False, "Oh! The console vanished before test completed."

            if flag & select.POLLIN:
                output_char = str(os.read(fd, 1), encoding="utf-8", errors="ignore")
                return output_char

        return ""

    def rx(self, token="\n"):
        # pylint: disable=invalid-name
        # No need to have a snake_case naming style for a single word.
        r"""Read a string delimited by an end token (defaults to "\n")."""
        rx_str = ""
        start = time.time()
        while True:
            rx_str += self.rx_char()
            if rx_str.endswith(token):
                break
            if (time.time() - start) >= self.RX_TIMEOUT_S:
                self._screen_jailer.kill()
                assert False

        return rx_str
