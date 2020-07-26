# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for measuring memory utilization for a process."""
from queue import Queue
import time
from threading import Thread

import framework.utils as utils


class MemoryUsageExceededException(Exception):
    """A custom exception containing details on excessive memory usage."""

    def __init__(self, usage, threshold):
        """Compose the error message containing the memory consumption."""
        super(MemoryUsageExceededException, self).__init__(
            'Memory usage ({} KiB) exceeded maximum threshold ({} KiB).\n'
            .format(usage, threshold)
        )


class MemoryMonitor(Thread):
    """Class to represent a RSS memory monitor for a Firecracker process.

    The guest's memory region is skipped, as the main interest is the
    VMM memory usage.
    """

    MEMORY_THRESHOLD = 5 * 1024
    MEMORY_SAMPLE_TIMEOUT_S = 1

    def __init__(self):
        """Initialize monitor attributes."""
        Thread.__init__(self)
        self._pid = None
        self._guest_mem_mib = None
        self._exceeded_queue = Queue()
        self._threshold = self.MEMORY_THRESHOLD
        self._should_stop = False

    @property
    def pid(self):
        """Get the pid."""
        return self._pid

    @property
    def guest_mem_mib(self):
        """Get the guest memory in MiB."""
        return self._guest_mem_mib

    @property
    def threshold(self):
        """Get the memory threshold."""
        return self._threshold

    @property
    def exceeded_queue(self):
        """Get the exceeded queue."""
        return self._exceeded_queue

    @guest_mem_mib.setter
    def guest_mem_mib(self, guest_mem_mib):
        """Set the guest memory MiB."""
        self._guest_mem_mib = guest_mem_mib

    @pid.setter
    def pid(self, pid):
        """Set the pid."""
        self._pid = pid

    @threshold.setter
    def threshold(self, threshold):
        """Set the threshold."""
        self._threshold = threshold

    def signal_stop(self):
        """Signal that the thread should stop."""
        self._should_stop = True

    def run(self):
        """Thread for monitoring the RSS memory usage of a Firecracker process.

        `pmap` is used to compute the memory overhead. If it exceeds
        the maximum value, it is pushed in a thread safe queue and memory
        monitoring ceases. It is up to the caller to check the queue.
        """
        pmap_cmd = 'pmap -xq {}'.format(self.pid)

        while not self._should_stop:
            mem_total = 0
            try:
                _, stdout, _ = utils.run_cmd(pmap_cmd)
                pmap_out = stdout.split("\n")
            except ChildProcessError:
                return
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
                if total_size == self.guest_mem_mib * 1024:
                    # This is the guest's memory region.
                    # TODO Check for the address of the guest's memory instead.
                    continue
                mem_total += rss

            if mem_total > self.threshold:
                self.exceeded_queue.put(mem_total)
                return

            if not mem_total:
                return

            time.sleep(self.MEMORY_SAMPLE_TIMEOUT_S)

    def check_samples(self):
        """Check that there are no samples over the threshold."""
        if not self.exceeded_queue.empty():
            raise MemoryUsageExceededException(
                self.exceeded_queue.get(), self.threshold)
