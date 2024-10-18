# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the boot time to init process is within spec."""

import datetime
import re
import time

import pytest

from framework.properties import global_props

# Regex for obtaining boot time from some string.
TIMESTAMP_LOG_REGEX = r"Guest-boot-time\s+\=\s+(\d+)\s+us"

DEFAULT_BOOT_ARGS = (
    "reboot=k panic=1 pci=off nomodule 8250.nr_uarts=0"
    " i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd"
)


DIMENSIONS = {
    "instance": global_props.instance,
    "cpu_model": global_props.cpu_model,
    "host_os": global_props.host_os,
    "host_kernel": "linux-" + global_props.host_linux_version,
}


def _get_microvm_boottime(vm):
    """Auxiliary function for asserting the expected boot time."""
    boot_time_us = None
    timestamps = []

    iterations = 50
    sleep_time_s = 0.1
    for _ in range(iterations):
        timestamps = re.findall(TIMESTAMP_LOG_REGEX, vm.log_data)
        if timestamps:
            break
        time.sleep(sleep_time_s)
    if timestamps:
        boot_time_us = int(timestamps[0])

    assert boot_time_us, (
        f"MicroVM did not boot within {sleep_time_s * iterations}s\n"
        f"Firecracker logs:\n{vm.log_data}\n"
        f"Thread backtraces:\n{vm.thread_backtraces}"
    )
    return boot_time_us


def find_events(log_data):
    """
    Parse events in the Firecracker logs

    Events have this format:

        TIMESTAMP [LOGLEVEL] event_(start|end): EVENT
    """
    ts_fmt = "%Y-%m-%dT%H:%M:%S.%f"
    matches = re.findall(r"(.+) \[.+\] event_(start|end): (.*)", log_data)
    timestamps = {}
    for ts, when, what in matches:
        evt1 = timestamps.setdefault(what, {})
        evt1[when] = datetime.datetime.strptime(ts[:-3], ts_fmt)
    for _, val in timestamps.items():
        val["duration"] = val["end"] - val["start"]
    return timestamps


@pytest.mark.parametrize(
    "vcpu_count,mem_size_mib",
    [(1, 128), (1, 1024), (2, 2048), (4, 4096)],
)
@pytest.mark.nonci
def test_boottime(
    microvm_factory, guest_kernel_acpi, rootfs_rw, vcpu_count, mem_size_mib, metrics
):
    """Test boot time with different guest configurations"""

    metrics.set_dimensions(
        {
            **DIMENSIONS,
            "performance_test": "test_boottime",
            "guest_kernel": guest_kernel_acpi.name,
            "vcpus": str(vcpu_count),
            "mem_size_mib": str(mem_size_mib),
        }
    )

    for _ in range(10):
        vm = microvm_factory.build(guest_kernel_acpi, rootfs_rw)
        vm.jailer.extra_args.update({"boot-timer": None})
        vm.spawn()
        vm.basic_config(
            vcpu_count=vcpu_count,
            mem_size_mib=mem_size_mib,
            boot_args=DEFAULT_BOOT_ARGS + " init=/usr/local/bin/init",
            enable_entropy_device=True,
        )
        vm.add_net_iface()
        vm.start()
        vm.pin_threads(0)
        boottime_us = _get_microvm_boottime(vm)
        metrics.put_metric("boot_time", boottime_us, unit="Microseconds")
        timestamps = find_events(vm.log_data)
        build_time = timestamps["build microvm for boot"]["duration"]
        metrics.put_metric("build_time", build_time.microseconds, unit="Microseconds")
        metrics.put_metric(
            "guest_boot_time",
            boottime_us - build_time.microseconds,
            unit="Microseconds",
        )
        vm.kill()
