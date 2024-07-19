# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test to restore snapshots across kernel versions."""

import json
import logging
import platform
from pathlib import Path

import pytest

from framework.defs import FC_WORKSPACE_DIR
from framework.utils import (
    generate_mmds_get_request,
    generate_mmds_session_token,
    guest_run_fio_iteration,
    populate_data_store,
)
from framework.utils_cpu_templates import get_supported_cpu_templates
from framework.utils_vsock import check_vsock_device
from integration_tests.functional.test_balloon import (
    get_stable_rss_mem_by_pid,
    make_guest_dirty_memory,
)

pytestmark = pytest.mark.nonci


def _test_balloon(microvm):
    # Get the firecracker pid.
    firecracker_pid = microvm.firecracker_pid

    # Check memory usage.
    first_reading = get_stable_rss_mem_by_pid(firecracker_pid)
    # Dirty 300MB of pages.
    make_guest_dirty_memory(microvm.ssh, amount_mib=300)
    # Check memory usage again.
    second_reading = get_stable_rss_mem_by_pid(firecracker_pid)
    assert second_reading > first_reading

    # Inflate the balloon. Get back 200MB.
    microvm.api.balloon.patch(amount_mib=200)

    third_reading = get_stable_rss_mem_by_pid(firecracker_pid)
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
    cpu_templates = []
    if platform.machine() == "x86_64":
        cpu_templates = ["None"]
    cpu_templates += get_supported_cpu_templates()
    for cpu_template in cpu_templates:
        for snapshot_dir in snapshot_root_dir.glob(f"*_{cpu_template}_guest_snapshot"):
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

    vm = microvm_factory.build()
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

    logger.info("Testing data store behavior...")
    _test_mmds(vm, vm.iface["eth3"]["iface"])

    logger.info("Testing balloon device...")
    _test_balloon(vm)

    logger.info("Testing vsock device...")
    check_vsock_device(vm, bin_vsock_path, test_fc_session_root_path, vm.ssh)

    # Run fio on the guest.
    # TODO: check the result of FIO or use fsck to check that the root device is
    # not corrupted. No obvious errors will be returned here.
    guest_run_fio_iteration(vm.ssh, 0)

    vm.kill()
