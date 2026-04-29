# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test to restore snapshots across kernel versions."""

import json
import logging
from pathlib import Path

import pytest

from framework.defs import FC_WORKSPACE_DIR
from framework.utils import (
    check_entropy,
    check_network_data_integrity,
    generate_mmds_get_request,
    generate_mmds_session_token,
    guest_run_fio_iteration,
    populate_data_store,
)
from framework.utils_cpu_templates import get_supported_cpu_templates
from framework.utils_vsock import check_vsock_device
from integration_tests.functional.test_balloon import (
    get_stable_rss_mem,
    make_guest_dirty_memory,
)

pytestmark = pytest.mark.nonci


def _check_guest_monotonic_did_not_jump(ssh_connection, max_delta_sec=10):
    # Phase1 recorded CLOCK_MONOTONIC to /tmp/monotonic-before just before
    # snapshotting. Firecracker is supposed to resume MONOTONIC from capture
    # time, so the delta here should be near zero regardless of how long
    # phase1 and restore are apart in the pipeline. A large delta indicates
    # MONOTONIC jumped forward across the snapshot - a kvm-clock regression
    # that could surface only on some host-kernel combinations.
    _, before_str, _ = ssh_connection.check_output("cat /tmp/monotonic-before")
    _, after_str, _ = ssh_connection.check_output(
        "python3 -c 'import time; print(time.monotonic())'"
    )
    delta = float(after_str.strip()) - float(before_str.strip())
    assert (
        0 <= delta <= max_delta_sec
    ), f"Guest MONOTONIC jumped {delta:.3f}s across snapshot (max {max_delta_sec}s)"


def _test_balloon(microvm):
    # Check memory usage.
    first_reading = get_stable_rss_mem(microvm)
    # Dirty 300MB of pages.
    make_guest_dirty_memory(microvm.ssh, amount_mib=300)
    # Check memory usage again.
    second_reading = get_stable_rss_mem(microvm)
    assert second_reading > first_reading

    # Inflate the balloon. Get back 200MB.
    microvm.api.balloon.patch(amount_mib=200)

    third_reading = get_stable_rss_mem(microvm)
    # Ensure that there is a reduction in RSS.
    assert second_reading > third_reading


def _test_mmds(vm, mmds_net_iface):
    # Populate MMDS.
    data_store = {"latest": {"meta-data": {"ami-id": "ami-12345678"}}}
    populate_data_store(vm, data_store)

    mmds_ipv4_address = "169.254.169.254"
    vm.guest_ip = mmds_net_iface.guest_ip

    # Insert new rule into the routing table of the guest.
    cmd = "ip route add {} dev {}".format(
        mmds_net_iface.guest_ip, mmds_net_iface.dev_name
    )
    vm.ssh.check_output(cmd)

    # The base microVM had MMDS version 2 configured, which was persisted
    # across the snapshot-restore.
    token = generate_mmds_session_token(vm.ssh, mmds_ipv4_address, token_ttl=60)

    cmd = generate_mmds_get_request(mmds_ipv4_address, token=token)
    _, stdout, _ = vm.ssh.run(cmd)
    assert json.loads(stdout) == data_store


def get_snapshot_dirs():
    """Get all the snapshot directories"""
    snapshot_root_name = "snapshot_artifacts"
    snapshot_root_dir = Path(FC_WORKSPACE_DIR) / snapshot_root_name
    cpu_templates = ["None"] + get_supported_cpu_templates()
    for cpu_template in cpu_templates:
        for snapshot_dir in snapshot_root_dir.glob(
            f"**/*_{cpu_template}_guest_snapshot"
        ):
            assert snapshot_dir.is_dir()
            yield pytest.param(snapshot_dir, id=snapshot_dir.name)


@pytest.mark.timeout(600)
@pytest.mark.parametrize("snapshot_dir", get_snapshot_dirs())
def test_snap_restore_from_artifacts(
    microvm_factory, bin_vsock_path, test_fc_session_root_path, snapshot_dir
):
    """
    Restore from snapshots obtained with all supported guest kernel versions.

    The snapshot artifacts have been generated through the
    `create_snapshot_artifacts` devtool command. The base microVM snapshotted
    has been built from the config file at
    ~/firecracker/tools/create_snapshot_artifact/complex_vm_config.json.
    """
    logger = logging.getLogger("cross_kernel_snapshot_restore")

    # Iterate through all subdirectories based on CPU template
    # in the snapshot root dir.
    logger.info("Working with snapshot artifacts in %s.", snapshot_dir)

    # Skip memory monitor: the balloon inflation below fragments the guest
    # VMA via discard_range's MAP_FIXED anonymous mmap workaround (used only
    # for private file-backed mappings from snapshot restore), defeating
    # MemoryMonitor.is_guest_mem. Cross-kernel test, not overhead.
    vm = microvm_factory.build(monitor_memory=False)
    vm.time_api_requests = False
    vm.spawn()
    logger.info("Loading microVM from snapshot...")
    vm.restore_from_path(snapshot_dir)
    vm.resume()

    # Ensure microVM is running.
    assert vm.state == "Running"

    # Test that net devices have connectivity after restore.
    for idx, iface in enumerate(vm.iface.values()):
        logger.info("Testing net device %s...", iface["iface"].dev_name)
        vm.ssh_iface(idx).check_output("true")

    # Check MONOTONIC before any other post-restore activity, so the delta
    # is bounded by the few seconds of post-resume setup rather than the
    # full test runtime.
    logger.info("Testing guest MONOTONIC did not jump across snapshot...")
    _check_guest_monotonic_did_not_jump(vm.ssh)

    logger.info("Testing network data integrity...")
    check_network_data_integrity(vm.ssh)

    logger.info("Testing data store behavior...")
    _test_mmds(vm, vm.iface["eth3"]["iface"])

    logger.info("Testing balloon device...")
    _test_balloon(vm)

    logger.info("Testing vsock device...")
    check_vsock_device(vm, bin_vsock_path, test_fc_session_root_path, vm.ssh)

    logger.info("Testing block device via fio...")
    guest_run_fio_iteration(vm.ssh, 0)

    logger.info("Testing entropy...")
    check_entropy(vm.ssh)

    vm.kill()
