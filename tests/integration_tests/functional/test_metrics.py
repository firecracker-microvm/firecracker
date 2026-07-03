# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the metrics system."""

import os
from pathlib import Path

import host_tools.drive as drive_tools
from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from host_tools.fcmetrics import FcDeviceMetrics, validate_fc_metrics


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_flush_metrics(uvm):
    """
    Check the `FlushMetrics` vmm action.
    """
    microvm = uvm
    microvm.spawn()
    microvm.basic_config()
    microvm.start()

    metrics = microvm.flush_metrics()
    validate_fc_metrics(metrics)


def _configure_metrics_via_api(microvm, **kwargs):
    """Configure metrics through the API rather than the `--metrics-path` CLI
    option (the two ways of initializing metrics are mutually exclusive), and
    wire up the host-side metrics file so the line can be read back."""
    microvm.spawn(metrics_path=None)
    microvm.basic_config()

    metrics_path = Path(microvm.path) / "metrics.ndjson"
    metrics_path.touch()
    microvm.metrics_file = metrics_path

    microvm.api.metrics.put(
        metrics_path=microvm.create_jailed_resource(metrics_path), **kwargs
    )
    microvm.start()


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_metrics_default_shape(uvm):
    """
    Check that no `id` or `properties` field is emitted by default.
    """
    microvm = uvm
    microvm.spawn()
    microvm.basic_config()
    microvm.start()

    metrics = microvm.flush_metrics()
    validate_fc_metrics(metrics)
    assert "id" not in metrics
    assert "properties" not in metrics


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_metrics_emit_id(uvm):
    """
    Check that `emit_id` emits the instance id, independently of `properties`.
    """
    microvm = uvm
    _configure_metrics_via_api(microvm, emit_id=True)

    metrics = microvm.flush_metrics()
    validate_fc_metrics(metrics)
    assert metrics["id"] == microvm.id
    assert "properties" not in metrics


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_metrics_with_properties(uvm):
    """
    Check that `properties` is emitted, independently of `emit_id`.
    """
    microvm = uvm
    properties = {"customer_id": "1234", "bundle_id": "fn-abc"}
    _configure_metrics_via_api(microvm, properties=properties)

    metrics = microvm.flush_metrics()
    validate_fc_metrics(metrics)
    assert metrics["properties"] == properties
    assert "id" not in metrics


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_metrics_emit_id_and_properties(uvm):
    """
    Check that `emit_id` and `properties` can be enabled together.
    """
    microvm = uvm
    properties = {"customer_id": "1234", "bundle_id": "fn-abc"}
    _configure_metrics_via_api(microvm, emit_id=True, properties=properties)

    metrics = microvm.flush_metrics()
    validate_fc_metrics(metrics)
    assert metrics["id"] == microvm.id
    assert metrics["properties"] == properties


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_net_metrics(uvm):
    """
    Validate that NetDeviceMetrics doesn't have a breaking change
    and "net" is aggregate of all "net_*" in the json object.
    """
    test_microvm = uvm
    test_microvm.spawn()

    # Set up a basic microVM.
    test_microvm.basic_config()

    # randomly selected 10 as the number of net devices to test
    num_net_devices = 10

    net_metrics = FcDeviceMetrics("net", num_net_devices)

    # create more than 1 net devices to test aggregation
    for _ in range(num_net_devices):
        test_microvm.add_net_iface()
    test_microvm.start()

    # check that the started microvm has "net" and "NUM_NET_DEVICES" number of "net_" metrics
    net_metrics.validate(test_microvm)

    for i in range(num_net_devices):
        # Test that network devices attached are operational.
        # Verify if guest can run commands.
        exit_code, _, _ = test_microvm.ssh_iface(i).run("sync")
        # test that we get metrics while interacting with different interfaces
        net_metrics.validate(test_microvm)
        assert exit_code == 0


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_block_metrics(uvm):
    """
    Validate that BlockDeviceMetrics doesn't have a breaking change
    and "block" is aggregate of all "block_*" in the json object.
    """
    test_microvm = uvm
    test_microvm.spawn()

    # Add first scratch block device.
    fs1 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch1"), size=128
    )
    test_microvm.add_drive("scratch1", fs1.path)

    # Set up a basic microVM.
    # (this is the second block device added).
    test_microvm.basic_config()

    # Add the third block device.
    fs2 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch2"), size=512
    )
    test_microvm.add_drive("scratch2", fs2.path)

    num_block_devices = 3
    block_metrics = FcDeviceMetrics("block", num_block_devices)

    test_microvm.start()

    # check that the started microvm has "block" and "num_block_devices" number of "block_" metrics
    block_metrics.validate(test_microvm)
