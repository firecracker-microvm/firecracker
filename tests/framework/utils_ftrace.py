# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for interacting with the kernel's ftrace subsystem"""
import contextlib

from framework.utils import check_output


@contextlib.contextmanager
def ftrace_events(events: str = "*:*"):
    """Temporarily enables the kernel's tracing functionality for the specified events

    Assumes that the caller is the only test executing on the host"""

    # We have to do system-wide tracing because inside docker we live in a pidns, but trace-cmd does not know about
    # this. We don't know how to translate the pidns PID to one ftrace would understand, so we use the fact that only
    # one vm is running at the same time, and thus we can attribute all KVM events to this one VM
    check_output("mount -t tracefs nodev /sys/kernel/tracing")
    check_output("echo > /sys/kernel/tracing/trace")  # clear the trace buffers
    check_output(f"echo {events} > /sys/kernel/tracing/set_event")
    check_output("echo nop > /sys/kernel/tracing/current_tracer")
    check_output("echo 1 > /sys/kernel/tracing/tracing_on")

    try:
        yield
    finally:
        check_output("echo 0 > /sys/kernel/tracing/tracing_on")
        check_output("umount /sys/kernel/tracing")
