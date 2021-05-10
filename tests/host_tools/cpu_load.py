# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for measuring cpu utilisation for a process."""
import time
from threading import Thread
import framework.utils as utils

# /proc/<pid>/stat output taken from
# https://www.man7.org/linux/man-pages/man5/proc.5.html
STAT_UTIME_IDX = 13
STAT_STIME_IDX = 14
STAT_STARTTIME_IDX = 21


class CpuLoadExceededException(Exception):
    """A custom exception containing details on excessive cpu load."""

    def __init__(self, cpu_load_samples, threshold):
        """Compose the error message containing the cpu load details."""
        super().__init__(
            'Cpu load samples {} exceeded maximum threshold {}.\n'
            .format(cpu_load_samples, threshold)
        )


class CpuLoadMonitor(Thread):
    """Class to represent a cpu load monitor for a thread."""

    CPU_LOAD_SAMPLES_TIMEOUT_S = 1

    def __init__(
        self,
        process_pid,
        thread_pid,
        threshold
    ):
        """Set up monitor attributes."""
        Thread.__init__(self)
        self._process_pid = process_pid
        self._thread_pid = thread_pid
        self._cpu_load_samples = []
        self._threshold = threshold
        self._should_stop = False

    @property
    def process_pid(self):
        """Get the process pid."""
        return self._process_pid

    @property
    def thread_pid(self):
        """Get the thread pid."""
        return self._thread_pid

    @property
    def threshold(self):
        """Get the cpu load threshold."""
        return self._threshold

    @property
    def cpu_load_samples(self):
        """Get the cpu load samples."""
        return self._cpu_load_samples

    def signal_stop(self):
        """Signal that the thread should stop."""
        self._should_stop = True

    def run(self):
        """Thread for monitoring cpu load of some pid.

        It is up to the caller to check the queue.
        """
        while not self._should_stop:
            cpu_load = utils.ProcessManager.get_cpu_percent(
                self._process_pid)["real"]
            if cpu_load > self.threshold:
                self.cpu_load_samples.append(cpu_load)
            time.sleep(1)  # 1 second granularity.

    def check_samples(self):
        """Check that there are no samples above the threshold."""
        if len(self.cpu_load_samples) > 0:
            raise CpuLoadExceededException(
                self._cpu_load_samples, self._threshold)
