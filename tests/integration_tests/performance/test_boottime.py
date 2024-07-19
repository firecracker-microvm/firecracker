# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the boot time to init process is within spec."""

import datetime
import re
import time

import pytest

from framework.properties import global_props

# The maximum acceptable boot time in us.
MAX_BOOT_TIME_US = 150000

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


@pytest.fixture
def fast_microvm(microvm_factory, guest_kernel_linux_4_14, rootfs_rw):
    """The microvm defined for the boottime SLA

    Guest kernel 4.14
    Rootfs: Ubuntu 22.04 ext4

    Using ext4 seems to result in a faster boot than with squashfs. Probably
    because we have to spend CPU time decompressing and extracting into memory.
    """
    return microvm_factory.build(kernel=guest_kernel_linux_4_14, rootfs=rootfs_rw)


def test_no_boottime(uvm_plain):
    """
    Check that boot timer device is not present by default.
    """
    vm = uvm_plain
    _configure_and_run_vm(vm)
    # microvm.start() ensures that the vm is in Running mode,
    # so there is no need to sleep and wait for log message.
    timestamps = re.findall(TIMESTAMP_LOG_REGEX, uvm_plain.log_data)
    assert not timestamps


def test_boottime_no_network(fast_microvm, record_property, metrics):
    """
    Check boot time of microVM without a network device.
    """

    vm = fast_microvm
    vm.jailer.extra_args.update({"boot-timer": None})
    _configure_and_run_vm(vm)
    boottime_us = _get_microvm_boottime(vm)
    print(f"Boot time with no network is: {boottime_us} us")
    record_property("boottime_no_network", f"{boottime_us} us < {MAX_BOOT_TIME_US} us")
    metrics.set_dimensions(DIMENSIONS)
    metrics.put_metric("boot_time", boottime_us, unit="Microseconds")
    assert (
        boottime_us < MAX_BOOT_TIME_US
    ), f"boot time {boottime_us} cannot be greater than: {MAX_BOOT_TIME_US} us"


def test_boottime_with_network(fast_microvm, record_property, metrics):
    """Check boot time of microVM with a network device."""
    vm = fast_microvm
    vm.jailer.extra_args.update({"boot-timer": None})
    _configure_and_run_vm(vm, network=True)
    boottime_us = _get_microvm_boottime(vm)
    print(f"Boot time with network configured is: {boottime_us} us")
    record_property(
        "boottime_with_network", f"{boottime_us} us < {MAX_BOOT_TIME_US} us"
    )
    metrics.set_dimensions(DIMENSIONS)
    metrics.put_metric("boot_time_with_net", boottime_us, unit="Microseconds")
    assert (
        boottime_us < MAX_BOOT_TIME_US
    ), f"boot time {boottime_us} cannot be greater than: {MAX_BOOT_TIME_US} us"


def test_initrd_boottime(uvm_with_initrd, record_property, metrics):
    """
    Check boot time of microVM when using an initrd.
    """
    vm = uvm_with_initrd
    vm.jailer.extra_args.update({"boot-timer": None})
    _configure_and_run_vm(vm, initrd=True)
    boottime_us = _get_microvm_boottime(vm)
    print(f"Boot time with initrd is: {boottime_us} us")
    record_property("boottime_initrd", f"{boottime_us} us")
    metrics.set_dimensions(DIMENSIONS)
    metrics.put_metric("boot_time_with_initrd", boottime_us, unit="Microseconds")


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


def _configure_and_run_vm(microvm, network=False, initrd=False):
    """Auxiliary function for preparing microvm before measuring boottime."""
    microvm.spawn()

    # Machine configuration specified in the SLA.
    config = {
        "vcpu_count": 1,
        "mem_size_mib": 128,
        "boot_args": DEFAULT_BOOT_ARGS + " init=/usr/local/bin/init",
        "enable_entropy_device": True,
    }
    if initrd:
        config["add_root_device"] = False
        config["use_initrd"] = True

    microvm.basic_config(**config)
    if network:
        microvm.add_net_iface()
    microvm.start()
    microvm.pin_threads(0)


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
def test_boottime(
    microvm_factory, guest_kernel, rootfs_rw, vcpu_count, mem_size_mib, metrics
):
    """Test boot time with different guest configurations"""

    metrics.set_dimensions(
        {
            **DIMENSIONS,
            "performance_test": "test_boottime",
            "guest_kernel": guest_kernel.name,
            "vcpus": str(vcpu_count),
            "mem_size_mib": str(mem_size_mib),
        }
    )

    for _ in range(10):
        vm = microvm_factory.build(guest_kernel, rootfs_rw)
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
