# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for measuring memory utilization for a process."""
from queue import Queue
import time
from threading import Thread, Lock

from framework import utils


class MemoryUsageExceededException(Exception):
    """A custom exception containing details on excessive memory usage."""

    def __init__(self, usage, threshold, out):
        """Compose the error message containing the memory consumption."""
        super().__init__(
            f"Memory usage ({usage} KiB) exceeded maximum threshold "
            f"({threshold} KiB).\n {out} \n"
        )


class MemoryMonitor(Thread):
    """Class to represent an RSS memory monitor for a Firecracker process.

    The guest's memory region is skipped, as the main interest is the
    VMM memory usage.
    """

    MEMORY_THRESHOLD = 5 * 1024
    MEMORY_SAMPLE_TIMEOUT_S = 0.05
    X86_MEMORY_GAP_START = 3407872

    def __init__(self):
        """Initialize monitor attributes."""
        Thread.__init__(self)
        self._pid = None
        self._guest_mem_mib = None
        self._guest_mem_start_1 = None
        self._guest_mem_end_1 = None
        self._guest_mem_start_2 = None
        self._guest_mem_end_2 = None
        self._exceeded_queue = Queue()
        self._pmap_out = None
        self._threshold = self.MEMORY_THRESHOLD
        self._should_stop = False
        self._current_rss = 0
        self._lock = Lock()
        self.daemon = True

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
        pmap_cmd = "pmap -xq {}".format(self.pid)

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
                    address = int(tokens[0].lstrip("0"), 16)
                    total_size = int(tokens[1])
                    rss = int(tokens[2])
                except ValueError:
                    # This line doesn't contain memory related information.
                    continue
                if self.update_guest_mem_regions(address, total_size):
                    continue
                if self.is_in_guest_mem_regions(address):
                    continue
                mem_total += rss
            with self._lock:
                self._current_rss = mem_total
            if mem_total > self.threshold:
                self.exceeded_queue.put(mem_total)
                self._pmap_out = stdout
                return

            time.sleep(self.MEMORY_SAMPLE_TIMEOUT_S)

    def update_guest_mem_regions(self, address, size_kib):
        """
        If the address is recognised as a guest memory region,
        cache it and return True, otherwise return False.
        """

        # If x86_64 guest memory exceeds 3328M, it will be split
        # in 2 regions: 3328M and the rest. We have 3 cases here
        # to recognise a guest memory region:
        #  - its size matches the guest memory exactly
        #  - its size is 3328M
        #  - its size is guest memory minus 3328M.
        if size_kib in (
            self.guest_mem_mib * 1024,
            self.X86_MEMORY_GAP_START,
            self.guest_mem_mib * 1024 - self.X86_MEMORY_GAP_START,
        ):
            if not self._guest_mem_start_1:
                self._guest_mem_start_1 = address
                self._guest_mem_end_1 = address + size_kib * 1024
                return True
            if not self._guest_mem_start_2:
                self._guest_mem_start_2 = address
                self._guest_mem_end_2 = address + size_kib * 1024
                return True
        return False

    def is_in_guest_mem_regions(self, address):
        """Check if the address is inside a guest memory region."""
        for guest_mem_start, guest_mem_end in [
            (self._guest_mem_start_1, self._guest_mem_end_1),
            (self._guest_mem_start_2, self._guest_mem_end_2),
        ]:
            if (
                guest_mem_start is not None
                and guest_mem_start <= address < guest_mem_end
            ):
                return True
        return False

    def check_samples(self):
        """Check that there are no samples over the threshold."""
        if not self.exceeded_queue.empty():
            raise MemoryUsageExceededException(
                self.exceeded_queue.get(), self.threshold, self._pmap_out
            )

    @property
    def current_rss(self):
        """Obtain current RSS for Firecracker's overhead."""
        # This is to ensure that the monitor has updated itself.
        time.sleep(self.MEMORY_SAMPLE_TIMEOUT_S + 0.5)
        with self._lock:
            return self._current_rss
