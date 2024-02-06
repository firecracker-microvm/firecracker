# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test that the process startup time up to socket bind is within spec."""

import os
import time

from host_tools.cargo_build import run_seccompiler_bin


def test_startup_time_new_pid_ns(
    microvm_factory, guest_kernel_linux_5_10, rootfs, metrics
):
    """
    Check startup time when jailer is spawned in a new PID namespace.
    """
    for _ in range(10):
        microvm = microvm_factory.build(guest_kernel_linux_5_10, rootfs)
        microvm.jailer.new_pid_ns = True
        _test_startup_time(microvm, metrics, "new_pid_ns")


def test_startup_time_daemonize(
    microvm_factory, guest_kernel_linux_5_10, rootfs, metrics
):
    """
    Check startup time when jailer detaches Firecracker from the controlling terminal.
    """
    for _ in range(10):
        microvm = microvm_factory.build(guest_kernel_linux_5_10, rootfs)
        _test_startup_time(microvm, metrics, "daemonize")


def test_startup_time_custom_seccomp(
    microvm_factory, guest_kernel_linux_5_10, rootfs, metrics
):
    """
    Check the startup time when using custom seccomp filters.
    """
    for _ in range(10):
        microvm = microvm_factory.build(guest_kernel_linux_5_10, rootfs)
        _custom_filter_setup(microvm)
        _test_startup_time(microvm, metrics, "custom_seccomp")


def _test_startup_time(microvm, metrics, test_suffix: str):
    microvm.spawn()
    microvm.basic_config(vcpu_count=2, mem_size_mib=1024)
    metrics.set_dimensions(
        {**microvm.dimensions, "performance_test": f"test_startup_time_{test_suffix}"}
    )
    test_start_time = time.time()
    microvm.start()
    time.sleep(0.4)

    # The metrics should be at index 1.
    # Since metrics are flushed at InstanceStart, the first line will suffice.
    datapoints = microvm.get_all_metrics()
    test_end_time = time.time()
    fc_metrics = datapoints[0]
    startup_time_us = fc_metrics["api_server"]["process_startup_time_us"]
    cpu_startup_time_us = fc_metrics["api_server"]["process_startup_time_cpu_us"]

    print(
        "Process startup time is: {} us ({} CPU us)".format(
            startup_time_us, cpu_startup_time_us
        )
    )

    assert cpu_startup_time_us > 0
    # Check that startup time is not a huge value
    # This is to catch issues like the ones introduced in PR
    # https://github.com/firecracker-microvm/firecracker/pull/4305
    test_time_delta_us = (test_end_time - test_start_time) * 1000 * 1000
    assert startup_time_us < test_time_delta_us
    assert cpu_startup_time_us < test_time_delta_us

    metrics.put_metric("startup_time", cpu_startup_time_us, unit="Microseconds")


def _custom_filter_setup(test_microvm):
    bpf_path = os.path.join(test_microvm.path, "bpf.out")

    run_seccompiler_bin(bpf_path)

    test_microvm.create_jailed_resource(bpf_path)
    test_microvm.jailer.extra_args.update({"seccomp-filter": "bpf.out"})
