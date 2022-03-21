# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test UFFD related functionality when resuming from snapshot."""
import logging
import os

from framework.artifacts import SnapshotMemBackendType
from framework.builder import MicrovmBuilder, SnapshotBuilder
from framework.utils import run_cmd

import host_tools.network as net_tools


def create_snapshot(bin_cloner_path):
    """Create a snapshot of a microVM."""
    vm_builder = MicrovmBuilder(bin_cloner_path)
    vm_instance = vm_builder.build_vm_nano()
    basevm = vm_instance.vm
    root_disk = vm_instance.disks[0]
    ssh_key = vm_instance.ssh_key

    basevm.start()
    ssh_connection = net_tools.SSHConnection(basevm.ssh_config)

    # Verify if guest can run commands.
    exit_code, _, _ = ssh_connection.execute_command("sync")
    assert exit_code == 0

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    # Create base snapshot.
    snapshot = snapshot_builder.create([root_disk.local_path()],
                                       ssh_key)

    basevm.kill()

    return snapshot


def test_bad_socket_path(bin_cloner_path, test_microvm_with_api):
    """
    Test error scenario when socket path does not exist.

    @type: negative
    """
    logger = logging.getLogger("uffd_bad_socket_path")

    logger.info("Create snapshot")
    snapshot = create_snapshot(bin_cloner_path)

    logger.info("Load snapshot, mem %s", snapshot.mem)
    vm = test_microvm_with_api
    vm.spawn()
    jailed_vmstate = vm.create_jailed_resource(snapshot.vmstate)

    response = vm.snapshot.load(
        mem_backend={
            'type': SnapshotMemBackendType.UFFD,
            'path': 'inexsistent'
        },
        snapshot_path=jailed_vmstate
    )

    assert vm.api_session.is_status_bad_request(response.status_code)
    assert "Load microVM snapshot error: Cannot connect to UDS in order to " \
           "send information on handling guest memory page-faults due to: " \
           "No such file or directory (os error 2)" in response.text


def test_unbinded_socket(bin_cloner_path, test_microvm_with_api):
    """
    Test error scenario when PF handler has not yet called bind on socket.

    @type: negative
    """
    logger = logging.getLogger("uffd_unbinded_socket")

    logger.info("Create snapshot")
    snapshot = create_snapshot(bin_cloner_path)

    logger.info("Load snapshot, mem %s", snapshot.mem)
    vm = test_microvm_with_api
    vm.spawn()
    jailed_vmstate = vm.create_jailed_resource(snapshot.vmstate)

    socket_path = os.path.join(vm.path, "firecracker-uffd.sock")
    run_cmd("touch {}".format(socket_path))
    jailed_sock_path = vm.create_jailed_resource(socket_path)

    response = vm.snapshot.load(
        mem_backend={
            'type': SnapshotMemBackendType.UFFD,
            'path': jailed_sock_path
        },
        snapshot_path=jailed_vmstate
    )

    assert vm.api_session.is_status_bad_request(response.status_code)
    assert "Load microVM snapshot error: Cannot connect to UDS in order to" \
           " send information on handling guest memory page-faults due to: " \
           "Connection refused (os error 111)" in response.text
