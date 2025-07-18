# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the performance of memory hotplugging."""

import time

import pytest

import framework.utils as utils
from framework.properties import global_props


def hp_microvm(microvm_factory, guest_kernel_linux_6_1, rootfs, hp_size):
    """Creates a microvm with the networking setup used by the performance tests in this file.
    This fixture receives its vcpu count via indirect parameterization"""
    vcpu_count = 2
    mem_size_mib = 1024
    # with just online, we're not guaranteed to get the pages back!
    boot_args = f"memhp_default_state=online_movable"

    vm = microvm_factory.build(guest_kernel_linux_6_1, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(
        vcpu_count=vcpu_count, mem_size_mib=mem_size_mib, boot_args=boot_args
    )
    vm.add_net_iface()
    vm.api.memory_hp.put(total_size_mib=hp_size)
    vm.start()
    vm.pin_threads(0)

    return vm


def timed_memory_hotplug(uvm, size, metrics, metric_prefix, fc_metric_name, timeout=10):
    """Wait for all memory hotplug events to be processed"""

    uvm.flush_metrics()

    start_api = time.time()
    uvm.api.memory_hp.patch(requested_size_mib=size)
    end_api = time.time()

    deadline = time.time() + timeout
    while time.time() < deadline:
        if uvm.api.memory_hp.get().json()["plugged_size_mib"] == size:
            break
        time.sleep(0.001)
    else:
        raise RuntimeError("Hotplug timeout")
    end_plug = time.time()
    fc_metrics = uvm.flush_metrics()

    metrics.put_metric(
        f"{metric_prefix}_api_time",
        (end_api - start_api),
        unit="Seconds",
    )
    metrics.put_metric(
        f"{metric_prefix}_total_time",
        (end_plug - start_api),
        unit="Seconds",
    )
    metrics.put_metric(
        f"{metric_prefix}_fc_time",
        fc_metrics["virtio_mem"][fc_metric_name]["sum_us"],
        unit="Microseconds",
    )


def get_rss_from_pmap(uvm):
    _, output, _ = utils.check_output("pmap -X {}".format(uvm.firecracker_pid))
    return int(output.split("\n")[-2].split()[1], 10)


@pytest.mark.nonci
@pytest.mark.parametrize(
    "hp_size",
    [
        1024,
        2048,
        4096,
        8192,
        16384,
    ],
)
def test_hotplug_latency(
    microvm_factory, guest_kernel_linux_6_1, rootfs, hp_size, metrics
):
    """Test the latency of hotplugging memory"""

    for i in range(100):
        uvm = hp_microvm(microvm_factory, guest_kernel_linux_6_1, rootfs, hp_size)

        if i == 0:
            metrics.set_dimensions(
                {
                    "instance": global_props.instance,
                    "cpu_model": global_props.cpu_model,
                    "host_kernel": f"linux-{global_props.host_linux_version}",
                    "performance_test": "test_hotplug_latency",
                    "hp_size": str(hp_size),
                    **uvm.dimensions,
                }
            )

        timed_memory_hotplug(uvm, hp_size, metrics, "hotplug", "plug_agg")
        timed_memory_hotplug(uvm, 0, metrics, "hotunplug", "unplug_agg")
        timed_memory_hotplug(uvm, hp_size, metrics, "hotplug_2nd", "plug_agg")
