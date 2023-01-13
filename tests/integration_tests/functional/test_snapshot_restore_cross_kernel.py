# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test to restore snapshots across kernel versions."""
import json
import logging
import os
import re
import pathlib
import shutil
import pytest

from framework.artifacts import (
    Snapshot,
    Artifact,
    ArtifactType,
    create_net_devices_configuration,
)
from framework.builder import MicrovmBuilder
from framework.defs import FC_WORKSPACE_DIR, DEFAULT_TEST_SESSION_ROOT_PATH
from framework.utils_vsock import check_vsock_device
from framework.utils import (
    generate_mmds_session_token,
    generate_mmds_get_request,
    guest_run_fio_iteration,
)
from framework.utils_cpuid import CpuVendor, get_cpu_vendor
from integration_tests.functional.test_mmds import _populate_data_store
from integration_tests.functional.test_balloon import (
    get_stable_rss_mem_by_pid,
    make_guest_dirty_memory,
    MB_TO_PAGES,
)


# Define 4 net device configurations.
net_ifaces = create_net_devices_configuration(4)


def _test_balloon(microvm):
    # Get the firecracker pid.
    firecracker_pid = microvm.jailer_clone_pid

    # Check memory usage.
    first_reading = get_stable_rss_mem_by_pid(firecracker_pid)
    # Dirty 300MB of pages.
    make_guest_dirty_memory(microvm.ssh, amount=(300 * MB_TO_PAGES))
    # Check memory usage again.
    second_reading = get_stable_rss_mem_by_pid(firecracker_pid)
    assert second_reading > first_reading

    # Inflate the balloon. Get back 200MB.
    response = microvm.balloon.patch(amount_mib=200)
    assert microvm.api_session.is_status_no_content(response.status_code)

    third_reading = get_stable_rss_mem_by_pid(firecracker_pid)
    # Ensure that there is a reduction in RSS.
    assert second_reading > third_reading


def _get_snapshot_files_paths(snapshot_dir):
    mem = vmstate = ssh_key = disk = None

    for file in os.listdir(snapshot_dir):
        file_path = os.path.join(Artifact.LOCAL_ARTIFACT_DIR, file)

        if file.endswith(".mem"):
            mem = file_path
        elif file.endswith(".vmstate"):
            vmstate = file_path
        elif file.endswith(".id_rsa"):
            ssh_key = Artifact(
                None,
                os.path.basename(file),
                ArtifactType.SSH_KEY,
                DEFAULT_TEST_SESSION_ROOT_PATH,
            )
            file_path = ssh_key.local_path()
            pathlib.Path(os.path.dirname(file_path)).mkdir(parents=True, exist_ok=True)
        elif file.endswith(".ext4"):
            disk = file_path

        # Copy to default root session.
        shutil.copy(os.path.join(snapshot_dir, file), file_path)
        assert os.path.isfile(file_path)

    # Ensure all required snapshot files are present inside the dir.
    assert mem and vmstate and disk and ssh_key

    # Change ssh key permissions.
    os.chmod(ssh_key.local_path(), 0o400)

    return mem, vmstate, disk, ssh_key


def _test_mmds(vm, mmds_net_iface):
    # Populate MMDS.
    data_store = {"latest": {"meta-data": {"ami-id": "ami-12345678"}}}
    _populate_data_store(vm, data_store)

    mmds_ipv4_address = "169.254.169.254"
    vm.ssh_config["hostname"] = mmds_net_iface.guest_ip

    # Insert new rule into the routing table of the guest.
    cmd = "ip route add {} dev {}".format(
        mmds_net_iface.guest_ip, mmds_net_iface.dev_name
    )
    code, _, _ = vm.ssh.execute_command(cmd)
    assert code == 0

    # The base microVM had MMDS version 2 configured, which was persisted
    # across the snapshot-restore.
    token = generate_mmds_session_token(vm.ssh, mmds_ipv4_address, token_ttl=60)

    cmd = generate_mmds_get_request(mmds_ipv4_address, token=token)
    _, stdout, _ = vm.ssh.execute_command(cmd)
    assert json.load(stdout) == data_store


@pytest.mark.nonci
@pytest.mark.parametrize(
    "cpu_template",
    ["C3", "T2", "T2S", "None"] if get_cpu_vendor() == CpuVendor.INTEL else ["None"],
)
def test_snap_restore_from_artifacts(
    bin_cloner_path, bin_vsock_path, test_fc_session_root_path, cpu_template
):
    """
    Restore from snapshots obtained with all supported guest kernel versions.

    The snapshot artifacts have been generated through the
    `create_snapshot_artifacts` devtool command. The base microVM snapshotted
    has been built from the config file at
    ~/firecracker/tools/create_snapshot_artifact/complex_vm_config.json.

    @type: functional
    """
    logger = logging.getLogger("cross_kernel_snapshot_restore")
    builder = MicrovmBuilder(bin_cloner_path)

    snapshot_root_name = "snapshot_artifacts"
    snapshot_root_dir = os.path.join(FC_WORKSPACE_DIR, snapshot_root_name)
    pathlib.Path(Artifact.LOCAL_ARTIFACT_DIR).mkdir(parents=True, exist_ok=True)

    # Iterate through all subdirectories based on CPU template
    # in the snapshot root dir.
    subdir_filter = r".*_" + re.escape(cpu_template) + r"_guest_snapshot"
    snap_subdirs = [
        d for d in os.listdir(snapshot_root_dir) if re.match(subdir_filter, d)
    ]
    for subdir_name in snap_subdirs:
        snapshot_dir = os.path.join(snapshot_root_dir, subdir_name)
        assert os.path.isdir(snapshot_dir)

        logger.info("Working with snapshot artifacts in %s.", snapshot_dir)
        mem, vmstate, disk, ssh_key = _get_snapshot_files_paths(snapshot_dir)

        logger.info("Creating snapshot from artifacts...")
        snapshot = Snapshot(mem, vmstate, [disk], net_ifaces, ssh_key)

        logger.info("Loading microVM from snapshot...")
        vm, _ = builder.build_from_snapshot(snapshot, resume=True, diff_snapshots=False)

        # Ensure microVM is running.
        response = vm.machine_cfg.get()
        assert vm.api_session.is_status_ok(response.status_code)
        assert vm.state == "Running"

        # Test that net devices have connectivity after restore.
        for iface in snapshot.net_ifaces:
            logger.info("Testing net device %s...", iface.dev_name)
            vm.ssh_config["hostname"] = iface.guest_ip
            exit_code, _, _ = vm.ssh.execute_command("sync")
            assert exit_code == 0

        logger.info("Testing data store behavior...")
        _test_mmds(vm, snapshot.net_ifaces[3])

        logger.info("Testing balloon device...")
        _test_balloon(vm)

        logger.info("Testing vsock device...")
        check_vsock_device(vm, bin_vsock_path, test_fc_session_root_path, vm.ssh)

        # Run fio on the guest.
        # TODO: check the result of FIO or use fsck to check that the root device is
        # not corrupted. No obvious errors will be returned here.
        guest_run_fio_iteration(vm.ssh, 0)

        vm.kill()
