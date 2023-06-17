# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for measuring cpu utilisation for a process."""
import time
from threading import Thread

from framework import utils


class CpuLoadExceededException(Exception):
    """A custom exception containing details on excessive cpu load."""

    def __init__(self, cpu_load_samples, threshold):
        """Compose the error message containing the cpu load details."""
        super().__init__(
            f"Cpu load samples {cpu_load_samples} exceeded maximum"
            f"threshold {threshold}.\n"
        )


class CpuLoadMonitor(Thread):
    """Class to represent a cpu load monitor for a thread."""

    CPU_LOAD_SAMPLES_TIMEOUT_S = 1

    def __init__(self, process_pid, thread_pid, threshold):
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
            cpus = utils.ProcessManager.get_cpu_percent(self._process_pid)

            try:
                fc_threads = cpus["firecracker"]

                # There can be multiple "firecracker" threads sometimes, see #3429
                assert len(fc_threads) > 0

                for _, cpu_load in fc_threads.items():
                    if cpu_load > self._threshold:
                        self._cpu_load_samples.append(cpu_load)
            except KeyError:
                pass  # no firecracker process

            time.sleep(0.05)  # 50 milliseconds granularity.

    def check_samples(self):
        """Check that there are no samples above the threshold."""
        if len(self.cpu_load_samples) > 0:
            raise CpuLoadExceededException(self._cpu_load_samples, self._threshold)

    def __enter__(self):
        """Functions to use this CPU Load class as a Context Manager

        >>> clm = CpuLoadMonitor(1000, 1000, 45)
        >>> with clm:
        >>>    # do stuff
        """
        self.start()

    def __exit__(self, _type, _value, _traceback):
        """Exit context"""
        self.check_samples()
        self.signal_stop()
        self.join()
