# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the boot time to init process is within spec."""

import re
import platform
from framework.utils_cpuid import get_instance_type, get_cpu_model_name

from framework.properties import global_props

# The maximum acceptable boot time in us.
MAX_BOOT_TIME_US = 150000
# NOTE: For aarch64 most of the boot time is spent by the kernel to unpack the
# initramfs in RAM. This time is influenced by the size and the compression
# method of the used initrd image. The boot time for Skylake is greater than
# other x86-64 CPUs, since L1TF mitigation (unconditional L1D cache flush) is
# enabled.
INITRD_BOOT_TIME_US = {
    "x86_64": {
        "m5d.metal": {
            "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz": 230000,
            "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz": 180000,
        },
        "m6i.metal": {
            "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz": 180000,
        },
        "m6a.metal": {
            "AMD EPYC 7R13 48-Core Processor": 180000,
        },
    },
    "aarch64": {
        "m6g.metal": {
            "ARM_NEOVERSE_N1": 205000,
        }
    },
}
# TODO: Keep a `current` boot time in S3 and validate we don't regress
# Regex for obtaining boot time from some string.
TIMESTAMP_LOG_REGEX = r"Guest-boot-time\s+\=\s+(\d+)\s+us"


DIMENSIONS = {
    "cpu_arch": global_props.cpu_architecture,
    "cpu_model": global_props.cpu_model,
    "host_linux": global_props.host_linux_version,
}


def test_no_boottime(test_microvm_with_api):
    """
    Check that boot timer device is not present by default.

    @type: functional
    """
    vm = test_microvm_with_api
    _ = _configure_and_run_vm(vm)
    # microvm.start() ensures that the vm is in Running mode,
    # so there is no need to sleep and wait for log message.
    timestamps = re.findall(TIMESTAMP_LOG_REGEX, test_microvm_with_api.log_data)
    assert not timestamps


def test_boottime_no_network(test_microvm_with_api, record_property, metrics):
    """
    Check boot time of microVM without a network device.

    @type: performance
    """
    vm = test_microvm_with_api
    vm.jailer.extra_args.update({"boot-timer": None})
    _ = _configure_and_run_vm(vm)
    boottime_us = _test_microvm_boottime(vm)
    print(f"Boot time with no network is: {boottime_us} us")
    record_property("boottime_no_network", f"{boottime_us} us < {MAX_BOOT_TIME_US} us")
    metrics.set_dimensions(DIMENSIONS)
    metrics.put_metric("boot_time", boottime_us, unit="Microseconds")


def test_boottime_with_network(
    test_microvm_with_api, network_config, record_property, metrics
):
    """
    Check boot time of microVM with a network device.

    @type: performance
    """
    vm = test_microvm_with_api
    vm.jailer.extra_args.update({"boot-timer": None})
    _tap = _configure_and_run_vm(vm, {"config": network_config, "iface_id": "1"})
    boottime_us = _test_microvm_boottime(vm)
    print(f"Boot time with network configured is: {boottime_us} us")
    record_property(
        "boottime_with_network", f"{boottime_us} us < {MAX_BOOT_TIME_US} us"
    )
    metrics.set_dimensions(DIMENSIONS)
    metrics.put_metric("boot_time_with_net", boottime_us, unit="Microseconds")


def test_initrd_boottime(test_microvm_with_initrd, record_property, metrics):
    """
    Check boot time of microVM when using an initrd.

    @type: performance
    """
    vm = test_microvm_with_initrd
    vm.jailer.extra_args.update({"boot-timer": None})
    _tap = _configure_and_run_vm(vm, initrd=True)
    max_time_us = INITRD_BOOT_TIME_US[platform.machine()][get_instance_type()][
        get_cpu_model_name()
    ]
    boottime_us = _test_microvm_boottime(vm, max_time_us=max_time_us)
    print(f"Boot time with initrd is: {boottime_us} us")
    record_property("boottime_initrd", f"{boottime_us} us < {max_time_us} us")
    metrics.set_dimensions(DIMENSIONS)
    metrics.put_metric("boot_time_with_initrd", boottime_us, unit="Microseconds")


def _test_microvm_boottime(vm, max_time_us=MAX_BOOT_TIME_US):
    """Auxiliary function for asserting the expected boot time."""
    boot_time_us = 0
    timestamps = vm.find_log_message(TIMESTAMP_LOG_REGEX)
    if timestamps:
        boot_time_us = int(timestamps[0])

    assert boot_time_us > 0
    assert (
        boot_time_us < max_time_us
    ), f"boot time {boot_time_us} cannot be greater than: {max_time_us} us"
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
