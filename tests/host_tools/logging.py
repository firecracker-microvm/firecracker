"""Utilities for testing the logging system (metrics, common logs)."""

import fcntl
import os
import sys


def fifo_reader(
        test_microvm,
        queue,
        fifo_index,
        check_func,
        *args
):
    """Read from a FIFO opened as read-only.

    This applies a function for checking output on each
    line of the logs received.
    """
    with open(test_microvm.slot.fifos[fifo_index], "r") as fifo:
        fd = fifo.fileno()
        flag = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flag | os.O_NONBLOCK)
        max_iter = 20
        while max_iter > 0:
            data = fifo.readline()
            if not data:
                break
            try:
                check_func(
                    "{0}".format(data), *args
                )
            except Exception:
                queue.put(sys.exc_info())
            max_iter = max_iter-1
    queue.put("Done")
