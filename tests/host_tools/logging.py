# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for testing the logging system (metrics, common logs)."""

import fcntl
import os


class Fifo:
    """Facility for creating and working with named pipes (FIFOs)."""

    path = None
    fifo = None

    def __init__(self, path, blocking=False):
        """Create a new named pipe."""
        if os.path.exists(path):
            raise FileExistsError("Named pipe {} already exists.".format(path))

        os.mkfifo(path)
        if not blocking:
            fd = os.open(path, os.O_NONBLOCK)
            self.fifo = os.fdopen(fd, "r")
        else:
            self.fifo = open(path, "r", encoding="utf-8")

        self.path = path

    def sequential_reader(self, max_lines):
        """Return up to `max_lines` lines from a non blocking fifo.

        :return: A list containing the read lines.
        """
        return self.fifo.readlines()[:max_lines]

    @property
    def flags(self):
        """Return flags of the opened fifo.

        :return An integer with flags of the opened file.
        """
        fd = self.fifo.fileno()
        return fcntl.fcntl(fd, fcntl.F_GETFL)

    @flags.setter
    def flags(self, flags):
        """Set new flags for the opened fifo."""
        fd = self.fifo.fileno()
        fcntl.fcntl(fd, fcntl.F_SETFL, flags)

    def __del__(self):
        """Destructor cleaning up the FIFO from where it was created."""
        if self.path:
            try:
                os.remove(self.path)
            except OSError:
                pass
