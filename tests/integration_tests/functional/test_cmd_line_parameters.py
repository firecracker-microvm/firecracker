# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the correctness of the command line parameters."""

import subprocess
from pathlib import Path

import packaging.version
import pytest

from framework.utils import check_output
from host_tools.fcmetrics import validate_fc_metrics


def test_describe_snapshot_all_versions(
    microvm_factory, guest_kernel, rootfs, firecracker_release
):
    """
    Test `--describe-snapshot` correctness for all snapshot versions.

    For each release create a snapshot and verify the data version of the
    snapshot state file.
    """

    # TODO: remove this check once all versions prior to 1.6.0 go out of support.
    if packaging.version.parse(firecracker_release.version) < packaging.version.parse(
        "1.7.0"
    ):
        pytest.skip(
            "We can't parse snapshot files created from Firecracker with version < 1.7.0."
        )

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

    # Fetch Firecracker binary
    fc_binary = microvm_factory.fc_binary_path
    # Verify the output of `--describe-snapshot` command line parameter
    cmd = [fc_binary] + ["--describe-snapshot", snapshot.vmstate]
    _, stdout, stderr = check_output(cmd)
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
    validate_fc_metrics(metrics)


def test_cli_metrics_path_if_metrics_initialized_twice_fail(uvm_plain):
    """
    Given: a running firecracker with metrics configured with the CLI option
    When: Configure metrics via API
    Then: API returns an error
    """
    microvm = uvm_plain

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


def test_cli_no_params(microvm_factory):
    """
    Test running firecracker with no parameters should work
    """

    fc_binary = microvm_factory.fc_binary_path
    process = subprocess.Popen(fc_binary)
    try:
        process.communicate(timeout=3)
        assert process.returncode is None
    except subprocess.TimeoutExpired:
        # The good case
        process.kill()
