# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the correctness of the command line parameters."""

import platform
from pathlib import Path

import pytest

from framework.utils import run_cmd
from host_tools.cargo_build import get_firecracker_binaries


def test_describe_snapshot_all_versions(
    microvm_factory, guest_kernel, rootfs, firecracker_release
):
    """
    Test `--describe-snapshot` correctness for all snapshot versions.

    For each release create a snapshot and verify the data version of the
    snapshot state file.
    """
    target_version = firecracker_release.snapshot_version
    vm = microvm_factory.build(
        guest_kernel,
        rootfs,
        fc_binary_path=firecracker_release.path,
        jailer_binary_path=firecracker_release.jailer,
    )
    vm.spawn()
    vm.basic_config(track_dirty_pages=True)
    vm.start()
    snapshot = vm.snapshot_diff()
    print("========== Firecracker create snapshot log ==========")
    print(vm.log_data)
    vm.kill()

    # Fetch Firecracker binary for the latest version
    fc_binary, _ = get_firecracker_binaries()
    # Verify the output of `--describe-snapshot` command line parameter
    cmd = [fc_binary] + ["--describe-snapshot", snapshot.vmstate]
    code, stdout, stderr = run_cmd(cmd)
    assert code == 0, stderr
    assert stderr == ""
    assert target_version in stdout


def test_cli_metrics_path(uvm_plain):
    """
    Test --metrics-path parameter
    """
    microvm = uvm_plain
    metrics_path = Path(microvm.path) / "my_metrics.ndjson"
    microvm.spawn(metrics_path=metrics_path)
    microvm.basic_config()
    microvm.start()
    metrics = microvm.flush_metrics()

    exp_keys = [
        "utc_timestamp_ms",
        "api_server",
        "balloon",
        "block",
        "deprecated_api",
        "get_api_requests",
        "i8042",
        "latencies_us",
        "logger",
        "mmds",
        "net",
        "patch_api_requests",
        "put_api_requests",
        "seccomp",
        "vcpu",
        "vmm",
        "uart",
        "signals",
        "vsock",
        "entropy",
    ]

    if platform.machine() == "aarch64":
        exp_keys.append("rtc")

    assert set(metrics.keys()) == set(exp_keys)


def test_cli_metrics_path_if_metrics_initialized_twice_fail(test_microvm_with_api):
    """
    Given: a running firecracker with metrics configured with the CLI option
    When: Configure metrics via API
    Then: API returns an error
    """
    microvm = test_microvm_with_api

    # First configure the µvm metrics with --metrics-path
    metrics_path = Path(microvm.path) / "metrics.ndjson"
    metrics_path.touch()
    microvm.spawn(metrics_path=metrics_path)

    # Then try to configure it with PUT /metrics
    metrics2_path = Path(microvm.path) / "metrics2.ndjson"
    metrics2_path.touch()

    # It should fail with because it's already configured
    with pytest.raises(RuntimeError, match="Reinitialization of metrics not allowed."):
        microvm.api.metrics.put(
            metrics_path=microvm.create_jailed_resource(metrics2_path)
        )


def test_cli_metrics_if_resume_no_metrics(uvm_plain, microvm_factory):
    """
    Check that metrics configuration is not part of the snapshot
    """
    # Given: a snapshot of a FC with metrics configured with the CLI option
    uvm1 = uvm_plain
    metrics_path = Path(uvm1.path) / "metrics.ndjson"
    metrics_path.touch()
    uvm1.spawn(metrics_path=metrics_path)
    uvm1.basic_config()
    uvm1.start()
    snapshot = uvm1.snapshot_full()

    # When: restoring from the snapshot
    uvm2 = microvm_factory.build()
    uvm2.spawn()
    uvm2.restore_from_snapshot(snapshot)

    # Then: the old metrics configuration does not exist
    metrics2 = Path(uvm2.jailer.chroot_path()) / metrics_path.name
    assert not metrics2.exists()
