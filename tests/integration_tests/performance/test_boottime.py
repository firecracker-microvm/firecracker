# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the boot time to init process is within spec."""

import datetime
import re
import time

import pytest

# Regex for obtaining boot time from some string.

DEFAULT_BOOT_ARGS = (
    "reboot=k panic=1 pci=off nomodule 8250.nr_uarts=0"
    " i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd"
)


def get_boottime_device_info(vm):
    """Auxiliary function for asserting the expected boot time."""
    boot_time_us = None
    boot_time_cpu_us = None
    timestamps = []

    timestamp_log_regex = (
        r"Guest-boot-time =\s+(\d+) us\s+(\d+) ms,\s+(\d+) CPU us\s+(\d+) CPU ms"
    )

    iterations = 50
    sleep_time_s = 0.1
    for _ in range(iterations):
        timestamps = re.findall(timestamp_log_regex, vm.log_data)
        if timestamps:
            break
        time.sleep(sleep_time_s)
    if timestamps:
        boot_time_us, _, boot_time_cpu_us, _ = timestamps[0]

    assert boot_time_us and boot_time_cpu_us, (
        f"MicroVM did not boot within {sleep_time_s * iterations}s\n"
        f"Firecracker logs:\n{vm.log_data}\n"
        f"Thread backtraces:\n{vm.thread_backtraces}"
    )
    return int(boot_time_us), int(boot_time_cpu_us)


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


def get_systemd_analyze_times(microvm):
    """
    Parse systemd-analyze output
    """
    rc, stdout, stderr = microvm.ssh.run("systemd-analyze")
    assert rc == 0, stderr
    assert stderr == ""

    boot_line = stdout.splitlines()[0]
    # The line will look like this:
    # Startup finished in 79ms (kernel) + 231ms (userspace) = 310ms
    # In the regex we capture the time and the unit for kernel, userspace and total values
    pattern = r"Startup finished in (\d*)(ms|s)\s+\(kernel\) \+ (\d*)(ms|s)\s+\(userspace\) = ([\d.]*)(ms|s)\s*"
    kernel, kernel_unit, userspace, userspace_unit, total, total_unit = re.findall(
        pattern, boot_line
    )[0]

    def to_ms(v, unit):
        match unit:
            case "ms":
                return float(v)
            case "s":
                return float(v) * 1000

    kernel = to_ms(kernel, kernel_unit)
    userspace = to_ms(userspace, userspace_unit)
    total = to_ms(total, total_unit)

    return kernel, userspace, total


@pytest.mark.parametrize(
    "vcpu_count,mem_size_mib",
    [(1, 128), (1, 1024), (2, 2048), (4, 4096)],
)
@pytest.mark.nonci
def test_boottime(
    microvm_factory, guest_kernel_acpi, rootfs_rw, vcpu_count, mem_size_mib, metrics
):
    """Test boot time with different guest configurations"""

    for i in range(10):
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

        boot_time_us, cpu_boot_time_us = get_boottime_device_info(vm)

        if i == 0:
            metrics.set_dimensions(
                {
                    "performance_test": "test_boottime",
                    **vm.dimensions,
                }
            )

        metrics.put_metric(
            "guest_boot_time",
            boot_time_us,
            unit="Microseconds",
        )
        metrics.put_metric(
            "guest_cpu_boot_time",
            cpu_boot_time_us,
            unit="Microseconds",
        )

        events = find_events(vm.log_data)
        build_time = events["build microvm for boot"]["duration"]
        metrics.put_metric("build_time", build_time.microseconds, unit="Microseconds")
        resume_time = events["boot microvm"]["duration"]
        metrics.put_metric("resume_time", resume_time.microseconds, unit="Microseconds")

        kernel, userspace, total = get_systemd_analyze_times(vm)
        metrics.put_metric("systemd_kernel", kernel, unit="Milliseconds")
        metrics.put_metric("systemd_userspace", userspace, unit="Milliseconds")
        metrics.put_metric("systemd_total", total, unit="Milliseconds")

        vm.kill()
