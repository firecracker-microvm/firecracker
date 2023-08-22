# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test that the process startup time up to socket bind is within spec."""

# pylint: disable=redefined-outer-name

import os
import time

import pytest

from framework.properties import global_props
from host_tools.cargo_build import run_seccompiler_bin


@pytest.fixture
def startup_time(metrics, record_property):
    """Fixture to capture the startup time"""
    metrics.set_dimensions(
        {
            "instance": global_props.instance,
            "cpu_model": global_props.cpu_model,
            "host_kernel": "linux-" + global_props.host_linux_version,
        }
    )

    def record_startup_time(startup_time):
        metrics.put_metric("startup_time", startup_time, unit="Microseconds")
        record_property("startup_time_μs", startup_time)

    return record_startup_time


def test_startup_time_new_pid_ns(test_microvm_with_api, startup_time):
    """
    Check startup time when jailer is spawned in a new PID namespace.
    """
    microvm = test_microvm_with_api
    microvm.bin_cloner_path = None
    microvm.jailer.new_pid_ns = True
    startup_time(_test_startup_time(microvm))


def test_startup_time_daemonize(test_microvm_with_api, startup_time):
    """
    Check startup time when jailer detaches Firecracker from the controlling terminal.
    """
    microvm = test_microvm_with_api
    startup_time(_test_startup_time(microvm))


def test_startup_time_custom_seccomp(test_microvm_with_api, startup_time):
    """
    Check the startup time when using custom seccomp filters.
    """
    microvm = test_microvm_with_api
    _custom_filter_setup(microvm)
    startup_time(_test_startup_time(microvm))


def _test_startup_time(microvm):
    microvm.spawn()
    microvm.basic_config(vcpu_count=2, mem_size_mib=1024)
    microvm.start()
    time.sleep(0.4)

    # The metrics should be at index 1.
    # Since metrics are flushed at InstanceStart, the first line will suffice.
    datapoints = microvm.get_all_metrics()
    metrics = datapoints[0]
    startup_time_us = metrics["api_server"]["process_startup_time_us"]
    cpu_startup_time_us = metrics["api_server"]["process_startup_time_cpu_us"]

    print(
        "Process startup time is: {} us ({} CPU us)".format(
            startup_time_us, cpu_startup_time_us
        )
    )

    assert cpu_startup_time_us > 0
    return cpu_startup_time_us


def _custom_filter_setup(test_microvm):
    bpf_path = os.path.join(test_microvm.path, "bpf.out")

    run_seccompiler_bin(bpf_path)

    test_microvm.create_jailed_resource(bpf_path)
    test_microvm.jailer.extra_args.update({"seccomp-filter": "bpf.out"})
