# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests to collect Firecracker metrics for vhost-user devices."""

import time

import pytest

import host_tools.drive as drive_tools


@pytest.mark.parametrize("vcpu_count", [1, 2], ids=["1vcpu", "2vcpu"])
def test_vhost_user_block_metrics(
    microvm_factory, guest_kernel_acpi, rootfs, vcpu_count, metrics
):
    """
    This test tries to boot a VM with vhost-user-block
    as a scratch device, resize the vhost-user scratch drive to have
    config change notifications, collects and then uploads the related
    vhost-user FirecrackerMetrics to Cloudwatch.
    Having vhost-user as root device vs a scratch should not impact metrics, however,
    we choose to have it as a scratch device because we are interested in config change
    metrics which we cannot extract when vhost-user is root device
    (read only rootfs won't have a config change).
    """
    orig_size = 10  # MB
    # Picked from test_config_change assuming that the intention is to change size from
    # low->high->low->high and so the numbers are not in monotonic sequence.
    new_sizes = [20, 10, 30]  # MB

    vm = microvm_factory.build(guest_kernel_acpi, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.basic_config(vcpu_count=vcpu_count)
    vm.add_net_iface()

    # Add a block device to test resizing.
    fs = drive_tools.FilesystemFile(size=orig_size)
    vm.add_vhost_user_drive("scratch", fs.path)
    vm.start()

    # vhost-user-block is activated during boot but it takes a while so we wait.
    # 300msec picked by the limited number of experiments tried to see how long
    # it takes to get the activate_time_us metrics.
    time.sleep(0.3)

    metrics.set_dimensions(
        {
            "performance_test": "vhost_user_block_metrics",
            "io_engine": "vhost-user",
            **vm.dimensions,
        }
    )
    fc_metrics = vm.flush_metrics()
    assert 0 == fc_metrics["vhost_user_block_scratch"]["activate_fails"]
    assert fc_metrics["vhost_user_block_scratch"]["init_time_us"]
    assert fc_metrics["vhost_user_block_scratch"]["activate_time_us"]

    metrics.put_metric(
        "init_time_us",
        fc_metrics["vhost_user_block_scratch"]["init_time_us"],
        unit="Microseconds",
    )
    metrics.put_metric(
        "activate_time_us",
        fc_metrics["vhost_user_block_scratch"]["activate_time_us"],
        unit="Microseconds",
    )

    for new_size in new_sizes:
        # Instruct the backend to resize the device.
        # It will both resize the file and update its device config.
        vm.disks_vhost_user["scratch"].resize(new_size)

        # Instruct Firecracker to reread device config and notify
        # the guest of a config change.
        vm.patch_drive("scratch")

        fc_metrics = vm.flush_metrics()
        assert 0 == fc_metrics["vhost_user_block_scratch"]["cfg_fails"]
        assert fc_metrics["vhost_user_block_scratch"]["config_change_time_us"]
        metrics.put_metric(
            "config_change_time_us",
            fc_metrics["vhost_user_block_scratch"]["config_change_time_us"],
            unit="Microseconds",
        )
