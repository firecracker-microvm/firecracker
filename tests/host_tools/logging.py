"""Utilities for testing the logging system (metrics, common logs)."""

import fcntl
import os
import sys
from threading import Thread
from queue import Queue


def open_microvm_fifo_nonblocking(
        test_microvm,
        fifo_index
):
    """Open a FIFO as read-only and non-blocking."""
    fifo = open(test_microvm.slot.fifos[fifo_index], "r")
    fd = fifo.fileno()
    flag = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flag | os.O_NONBLOCK)
    return fifo


def threaded_fifo_reader(
        test_microvm,
        fifo_index,
        check_func,
        *args
):
    """Start a thread to read fifo.

    The thread that runs the `check_func` on each line
     in the FIFO and enqueues any exceptions in the `exceptions_queue`.
    """
    exceptions_queue = Queue()
    metric_reader_thread = Thread(
        target=do_thread_fifo_reader, args=(
            exceptions_queue,
            test_microvm,
            fifo_index,
            check_func,
            *args
        )
    )
    metric_reader_thread.start()
    return exceptions_queue


def do_thread_fifo_reader(
        exceptions_queue,
        test_microvm,
        fifo_index,
        check_func,
        *args
):
    """Read from a FIFO opened as read-only.

    This applies a function for checking output on each
    line of the logs received.
    Failures and exceptions are propagated to the main thread
    through the `exceptions_queue`.
    """
    fifo = open_microvm_fifo_nonblocking(test_microvm, fifo_index)
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
            exceptions_queue.put(sys.exc_info())
        max_iter = max_iter-1
    exceptions_queue.put("Done")
