# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the correctness of the command line parameters."""

import logging
import platform
from pathlib import Path

import host_tools.logging as log_tools
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.utils import run_cmd
from host_tools.cargo_build import get_firecracker_binaries


def test_describe_snapshot_all_versions(bin_cloner_path, firecracker_release):
    """
    Test `--describe-snapshot` correctness for all snapshot versions.

    For each release create a snapshot and verify the data version of the
    snapshot state file.
    """
    logger = logging.getLogger("describe_snapshot")
    builder = MicrovmBuilder(bin_cloner_path)
    jailer = firecracker_release.jailer()
    target_version = firecracker_release.snapshot_version

    logger.info(
        "Creating snapshot with Firecracker: %s", firecracker_release.local_path()
    )
    logger.info("Using Jailer: %s", jailer.local_path())
    logger.info("Using target version: %s", target_version)

    vm_instance = builder.build_vm_nano(
        fc_binary=firecracker_release.local_path(),
        jailer_binary=jailer.local_path(),
        diff_snapshots=True,
    )
    vm = vm_instance.vm
    vm.start()

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(vm)
    disks = [vm_instance.disks[0].local_path()]

    # Version 0.24 and greater have Diff support.
    snap_type = SnapshotType.DIFF

    snapshot = snapshot_builder.create(
        disks,
        vm_instance.ssh_key,
        snapshot_type=snap_type,
    )
    logger.debug("========== Firecracker create snapshot log ==========")
    logger.debug(vm.log_data)
    vm.kill()

    # Fetch Firecracker binary for the latest version
    fc_binary, _ = get_firecracker_binaries()
    # Verify the output of `--describe-snapshot` command line parameter
    cmd = [fc_binary] + ["--describe-snapshot", snapshot.vmstate]

    code, stdout, stderr = run_cmd(cmd)
    assert code == 0, stderr
    assert stderr == ""
    assert target_version in stdout


def test_cli_metrics_path(test_microvm_with_api):
    """
    Test --metrics-path parameter
    """
    microvm = test_microvm_with_api
    metrics_fifo_path = Path(microvm.path) / "metrics_ndjson.fifo"
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    microvm.spawn(metrics_path=metrics_fifo_path)
    microvm.basic_config()
    microvm.start()

    metrics = microvm.flush_metrics(metrics_fifo)

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
    response = microvm.metrics.put(
        metrics_path=microvm.create_jailed_resource(metrics2_path)
    )

    # It should fail with HTTP 400 because it's already configured
    assert response.status_code == 400
    assert response.json() == {
        "fault_message": "Failed to handle pre-boot request: Failed to intiailize metrics: Reinitialization of metrics not allowed."
    }


def test_cli_metrics_if_resume_no_metrics(test_microvm_with_api, microvm_factory):
    """
    Check that metrics configuration is not part of the snapshot
    """
    # Given: a snapshot of a FC with metrics configured with the CLI option
    uvm1 = test_microvm_with_api
    metrics_path = Path(uvm1.path) / "metrics.ndjson"
    metrics_path.touch()
    uvm1.spawn(metrics_path=metrics_path)
    uvm1.basic_config()
    uvm1.start()

    mem_path = Path(uvm1.jailer.chroot_path()) / "test.mem"
    snapshot_path = Path(uvm1.jailer.chroot_path()) / "test.snap"
    uvm1.pause_to_snapshot(
        mem_file_path=mem_path.name,
        snapshot_path=snapshot_path.name,
    )
    assert mem_path.exists()

    # When: restoring from the snapshot
    uvm2 = microvm_factory.build()
    uvm2.spawn()
    uvm2.restore_from_snapshot(
        snapshot_vmstate=snapshot_path,
        snapshot_mem=mem_path,
        snapshot_disks=[uvm1.rootfs_file],
    )

    # Then: the old metrics configuration does not exist
    metrics2 = Path(uvm2.jailer.chroot_path()) / metrics_path.name
    assert not metrics2.exists()
