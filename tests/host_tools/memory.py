# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for measuring memory utilization for a process."""
import time

from threading import Thread

import framework.utils as utils


MAX_MEMORY = 5 * 1024
MEMORY_COP_TIMEOUT = 1


class MemoryUsageExceededException(Exception):
    """A custom exception containing details on excessive memory usage."""

    def __init__(self, usage):
        """Compose the error message containing the memory consumption."""
        super(MemoryUsageExceededException, self).__init__(
            'Memory usage ({} KiB) exceeded maximum threshold ({} KiB).\n'
            .format(usage, MAX_MEMORY)
        )


def threaded_memory_monitor(mem_size_mib, pid, exceeded_queue):
    """Spawns a thread that monitors memory consumption of a process.

    If at some point the memory used exceeds mem_size_mib, the calling thread
    will trigger error.
    """
    memory_cop_thread = Thread(target=_memory_cop, args=(
        mem_size_mib,
        pid,
        exceeded_queue
    ))
    memory_cop_thread.start()


def _memory_cop(mem_size_mib, pid, exceeded_queue):
    """Thread for monitoring memory consumption of some pid.

    `pmap` is used to compute the memory overhead. If it exceeds
    the maximum value, it is pushed in a thread safe queue and memory
    monitoring ceases. It is up to the caller to check the queue.
    """
    pmap_cmd = 'pmap -xq {}'.format(pid)
    while True:
        mem_total = 0
        try:
            _, stdout, _ = utils.run_cmd(pmap_cmd)
            pmap_out = stdout.split("\n")
        except ChildProcessError:
            break
        for line in pmap_out:
            tokens = line.split()
            if not tokens:
                break
            try:
                total_size = int(tokens[1])
                rss = int(tokens[2])
            except ValueError:
                # This line doesn't contain memory related information.
                continue
            if total_size == mem_size_mib * 1024:
                # This is the guest's memory region.
                # TODO Check for the address of the guest's memory instead.
                continue
            mem_total += rss

        if mem_total > MAX_MEMORY:
            exceeded_queue.put(mem_total)
            return

        if not mem_total:
            return

        time.sleep(MEMORY_COP_TIMEOUT)
