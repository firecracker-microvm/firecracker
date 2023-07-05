# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the boot time to init process is within spec."""

import re
import time

import pytest

from framework.properties import global_props

# The maximum acceptable boot time in us.
MAX_BOOT_TIME_US = 150000

# Regex for obtaining boot time from some string.
TIMESTAMP_LOG_REGEX = r"Guest-boot-time\s+\=\s+(\d+)\s+us"

DIMENSIONS = {
    "instance": global_props.instance,
    "cpu_model": global_props.cpu_model,
    "host_kernel": "linux-" + global_props.host_linux_version,
}


def test_no_boottime(test_microvm_with_api):
    """
    Check that boot timer device is not present by default.
    """
    vm = test_microvm_with_api
    _ = _configure_and_run_vm(vm)
    # microvm.start() ensures that the vm is in Running mode,
    # so there is no need to sleep and wait for log message.
    timestamps = re.findall(TIMESTAMP_LOG_REGEX, test_microvm_with_api.log_data)
    assert not timestamps


# temporarily disable this test in 6.1
@pytest.mark.xfail(
    global_props.host_linux_version == "6.1",
    reason="perf regression under investigation",
)
def test_boottime_no_network(test_microvm_with_api, record_property, metrics):
    """
    Check boot time of microVM without a network device.
    """
    vm = test_microvm_with_api
    vm.jailer.extra_args.update({"boot-timer": None})
    _ = _configure_and_run_vm(vm)
    boottime_us = _get_microvm_boottime(vm)
    print(f"Boot time with no network is: {boottime_us} us")
    record_property("boottime_no_network", f"{boottime_us} us < {MAX_BOOT_TIME_US} us")
    metrics.set_dimensions(DIMENSIONS)
    metrics.put_metric("boot_time", boottime_us, unit="Microseconds")
    assert (
        boottime_us < MAX_BOOT_TIME_US
    ), f"boot time {boottime_us} cannot be greater than: {MAX_BOOT_TIME_US} us"


# temporarily disable this test in 6.1
@pytest.mark.xfail(
    global_props.host_linux_version == "6.1",
    reason="perf regression under investigation",
)
def test_boottime_with_network(
    test_microvm_with_api, network_config, record_property, metrics
):
    """
    Check boot time of microVM with a network device.
    """
    vm = test_microvm_with_api
    vm.jailer.extra_args.update({"boot-timer": None})
    _configure_and_run_vm(vm, {"config": network_config, "iface_id": "1"})
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


def test_initrd_boottime(test_microvm_with_initrd, record_property, metrics):
    """
    Check boot time of microVM when using an initrd.
    """
    vm = test_microvm_with_initrd
    vm.jailer.extra_args.update({"boot-timer": None})
    _configure_and_run_vm(vm, initrd=True)
    boottime_us = _get_microvm_boottime(vm)
    print(f"Boot time with initrd is: {boottime_us} us")
    record_property("boottime_initrd", f"{boottime_us} us")
    metrics.set_dimensions(DIMENSIONS)
    metrics.put_metric("boot_time_with_initrd", boottime_us, unit="Microseconds")


def _get_microvm_boottime(vm):
    """Auxiliary function for asserting the expected boot time."""
    boot_time_us = 0
    timestamps = []
    for _ in range(10):
        timestamps = re.findall(TIMESTAMP_LOG_REGEX, vm.log_data)
        if timestamps:
            break
        time.sleep(0.1)
    if timestamps:
        boot_time_us = int(timestamps[0])

    assert boot_time_us > 0
    return boot_time_us


def _configure_and_run_vm(microvm, network_info=None, initrd=False):
    """Auxiliary function for preparing microvm before measuring boottime."""
    microvm.spawn()

    # Machine configuration specified in the SLA.
    config = {"vcpu_count": 1, "mem_size_mib": 128}

    if initrd:
        config["add_root_device"] = False
        config["use_initrd"] = True

    microvm.basic_config(**config)

    if network_info:
        _tap, _, _ = microvm.ssh_network_config(
            network_info["config"], network_info["iface_id"]
        )

    microvm.start()
    return _tap if network_info else None
