# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for interacting with the kernel's ftrace subsystem"""
import contextlib

from framework.utils import run_cmd


@contextlib.contextmanager
def ftrace_events(events: str = "*:*"):
    """Temporarily enables the kernel's tracing functionality for the specified events

    Assumes that the caller is the only test executing on the host"""

    # We have to do system-wide tracing because inside docker we live in a pidns, but trace-cmd does not know about
    # this. We don't know how to translate the pidns PID to one ftrace would understand, so we use the fact that only
    # one vm is running at the same time, and thus we can attribute all KVM events to this one VM
    run_cmd("mount -t tracefs nodev /sys/kernel/tracing")
    run_cmd("echo > /sys/kernel/tracing/trace")  # clear the trace buffers
    run_cmd(f"echo {events} > /sys/kernel/tracing/set_event")
    run_cmd("echo nop > /sys/kernel/tracing/current_tracer")
    run_cmd("echo 1 > /sys/kernel/tracing/tracing_on")

    try:
        yield
    finally:
        run_cmd("echo 0 > /sys/kernel/tracing/tracing_on")
        run_cmd("umount /sys/kernel/tracing")
