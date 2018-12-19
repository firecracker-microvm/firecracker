# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for testing the logging system (metrics, common logs)."""

import fcntl
import os
import sys

from queue import Queue
from subprocess import run
from threading import Thread


class Fifo:
    """Facility for creating and working with named pipes (FIFOs)."""

    path = None

    def __init__(self, path):
        """Create a new named pipe."""
        if os.path.exists(path):
            raise FileExistsError("Named pipe {} already exists.".format(path))
        cmd = 'mkfifo ' + path
        run(cmd, shell=True, check=True)
        self.path = path

    def sequential_reader(self, max_lines):
        """Returns up to `max_lines` lines from fifo `fifo_index`.

        :return: A list containing the read lines.
        """
        fifo = self._open_nonblocking()
        return fifo.readlines()[:max_lines]

    def threaded_reader(self, check_func, *args):
        """Start a thread to read fifo.

        The thread that runs the `check_func` on each line
         in the FIFO and enqueues any exceptions in the `exceptions_queue`.
        """
        exceptions_queue = Queue()
        metric_reader_thread = Thread(
            target=self._do_thread_reader, args=(
                exceptions_queue,
                check_func,
                *args
            )
        )
        metric_reader_thread.start()
        return exceptions_queue

    def _open_nonblocking(self):
        """Open a FIFO as read-only and non-blocking."""
        fifo = open(self.path, "r")
        fd = fifo.fileno()
        flag = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flag | os.O_NONBLOCK)
        return fifo

    def _do_thread_reader(self, exceptions_queue, check_func, *args):
        """Read from a FIFO opened as read-only.

        This applies a function for checking output on each
        line of the logs received.
        Failures and exceptions are propagated to the main thread
        through the `exceptions_queue`.
        """
        fifo = self._open_nonblocking()
        max_iter = 20
        while max_iter > 0:
            data = fifo.readline()
            if not data:
                break
            try:
                check_func(
                    "{0}".format(data), *args
                )
            # pylint: disable=broad-except
            # We need to propagate all type of exceptions to the main thread.
            except Exception:
                exceptions_queue.put(sys.exc_info())
            max_iter = max_iter-1
        exceptions_queue.put("Done")

    def __del__(self):
        """Destructor cleaning up the FIFO from where it was created."""
        if self.path:
            try:
                os.remove(self.path)
            except OSError:
                pass
