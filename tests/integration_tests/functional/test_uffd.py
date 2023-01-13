# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test UFFD related functionality when resuming from snapshot."""

import logging
import os
import socket
from subprocess import TimeoutExpired

import stat

import requests
import urllib3

from framework.artifacts import SnapshotMemBackendType
from framework.builder import MicrovmBuilder, SnapshotBuilder
from framework.utils import run_cmd, UffdHandler

SOCKET_PATH = "/firecracker-uffd.sock"


def create_snapshot(bin_cloner_path):
    """Create a snapshot of a microVM."""
    vm_builder = MicrovmBuilder(bin_cloner_path)
    vm_instance = vm_builder.build_vm_nano()
    basevm = vm_instance.vm
    root_disk = vm_instance.disks[0]
    ssh_key = vm_instance.ssh_key

    # Add a memory balloon.
    response = basevm.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )
    assert basevm.api_session.is_status_no_content(response.status_code)

    basevm.start()

    # Verify if guest can run commands.
    exit_code, _, _ = basevm.ssh.execute_command("sync")
    assert exit_code == 0

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    # Create base snapshot.
    snapshot = snapshot_builder.create([root_disk.local_path()], ssh_key)

    basevm.kill()

    return snapshot


def spawn_pf_handler(vm, handler_path, mem_path):
    """Spawn page fault handler process."""
    # Copy snapshot memory file into chroot of microVM.
    jailed_mem = vm.create_jailed_resource(mem_path)
    # Copy the valid page fault binary into chroot of microVM.
    jailed_handler = vm.create_jailed_resource(handler_path)

    handler_name = os.path.basename(jailed_handler)
    args = [SOCKET_PATH, jailed_mem]

    uffd_handler = UffdHandler(handler_name, args)
    real_root = os.open("/", os.O_RDONLY)
    working_dir = os.getcwd()

    os.chroot(vm.chroot())
    os.chdir("/")
    st = os.stat(handler_name)
    os.chmod(handler_name, st.st_mode | stat.S_IEXEC)

    uffd_handler.spawn()
    try:
        outs, errs = uffd_handler.proc().communicate(timeout=1)
        print(outs)
        print(errs)
        assert False, "Could not start PF handler!"
    except TimeoutExpired:
        print("This is the good case!")

    # The page fault handler will create the socket path with root rights.
    # Change rights to the jailer's.
    os.chown(SOCKET_PATH, vm.jailer.uid, vm.jailer.gid)

    os.fchdir(real_root)
    os.chroot(".")
    os.chdir(working_dir)

    return uffd_handler


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
        mem_backend={"type": SnapshotMemBackendType.UFFD, "path": "inexsistent"},
        snapshot_path=jailed_vmstate,
    )

    assert vm.api_session.is_status_bad_request(response.status_code)
    assert (
        "Load microVM snapshot error: Failed to restore from snapshot: Failed to load guest "
        "memory: Error creating guest memory from uffd: Failed to connect to UDS Unix stream: No "
        "such file or directory (os error 2)"
    ) in response.text


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
        mem_backend={"type": SnapshotMemBackendType.UFFD, "path": jailed_sock_path},
        snapshot_path=jailed_vmstate,
    )

    assert vm.api_session.is_status_bad_request(response.status_code)
    assert (
        "Load microVM snapshot error: Failed to restore from snapshot: Failed to load guest "
        "memory: Error creating guest memory from uffd: Failed to connect to UDS Unix stream: "
        "Connection refused (os error 111)"
    ) in response.text


def test_valid_handler(bin_cloner_path, test_microvm_with_api, uffd_handler_paths):
    """
    Test valid uffd handler scenario.

    @type: functional
    """
    logger = logging.getLogger("uffd_valid_handler")

    logger.info("Create snapshot")
    snapshot = create_snapshot(bin_cloner_path)

    logger.info("Load snapshot, mem %s", snapshot.mem)
    vm_builder = MicrovmBuilder(bin_cloner_path)
    vm = test_microvm_with_api
    vm.spawn()

    # Spawn page fault handler process.
    _pf_handler = spawn_pf_handler(
        vm, uffd_handler_paths["valid_handler"], snapshot.mem
    )

    vm, _ = vm_builder.build_from_snapshot(
        snapshot, vm=vm, resume=True, uffd_path=SOCKET_PATH
    )

    # Inflate balloon.
    response = vm.balloon.patch(amount_mib=200)
    assert vm.api_session.is_status_no_content(response.status_code)

    # Deflate balloon.
    response = vm.balloon.patch(amount_mib=0)
    assert vm.api_session.is_status_no_content(response.status_code)

    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.execute_command("sync")
    assert exit_code == 0


def test_malicious_handler(bin_cloner_path, test_microvm_with_api, uffd_handler_paths):
    """
    Test malicious uffd handler scenario.

    The page fault handler panics when receiving a page fault,
    so no events are handled and snapshot memory regions cannot be
    loaded into memory. In this case, Firecracker is designed to freeze,
    instead of silently switching to having the kernel handle page
    faults, so that it becomes obvious that something went wrong.

    @type: negative
    """
    logger = logging.getLogger("uffd_malicious_handler")

    logger.info("Create snapshot")
    snapshot = create_snapshot(bin_cloner_path)

    logger.info("Load snapshot, mem %s", snapshot.mem)
    vm_builder = MicrovmBuilder(bin_cloner_path)
    vm = test_microvm_with_api
    vm.spawn()

    # Spawn page fault handler process.
    _pf_handler = spawn_pf_handler(
        vm, uffd_handler_paths["malicious_handler"], snapshot.mem
    )

    # We expect Firecracker to freeze while resuming from a snapshot
    # due to the malicious handler's unavailability.
    try:
        vm_builder.build_from_snapshot(
            snapshot, vm=vm, resume=True, uffd_path=SOCKET_PATH, timeout=30
        )
        assert False
    except (
        socket.timeout,
        urllib3.exceptions.ReadTimeoutError,
        requests.exceptions.ReadTimeout,
    ) as _err:
        assert True, _err
