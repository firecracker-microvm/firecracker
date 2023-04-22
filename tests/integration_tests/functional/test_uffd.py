# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test UFFD related functionality when resuming from snapshot."""

import os
import stat
from subprocess import TimeoutExpired

import pytest
import requests

from framework.utils import Timeout, UffdHandler, run_cmd

SOCKET_PATH = "/firecracker-uffd.sock"


@pytest.fixture(scope="function", name="snapshot")
def snapshot_fxt(microvm_factory, guest_kernel_linux_5_10, rootfs_ubuntu_22):
    """Create a snapshot of a microVM."""

    basevm = microvm_factory.build(guest_kernel_linux_5_10, rootfs_ubuntu_22)
    basevm.spawn()
    basevm.basic_config(vcpu_count=2, mem_size_mib=256)
    basevm.add_net_iface()

    # Add a memory balloon.
    response = basevm.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )
    assert basevm.api_session.is_status_no_content(response.status_code)

    basevm.start()

    # Verify if guest can run commands.
    exit_code, _, _ = basevm.ssh.execute_command("sync")
    assert exit_code == 0

    # Create base snapshot.
    snapshot = basevm.snapshot_full()
    basevm.kill()

    yield snapshot


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


def test_bad_socket_path(uvm_plain, snapshot):
    """
    Test error scenario when socket path does not exist.
    """
    vm = uvm_plain
    vm.spawn()
    jailed_vmstate = vm.create_jailed_resource(snapshot.vmstate)
    response = vm.snapshot.load(
        mem_backend={"type": "Uffd", "path": "inexistent"},
        snapshot_path=jailed_vmstate,
    )

    assert vm.api_session.is_status_bad_request(response.status_code)
    assert (
        "Load microVM snapshot error: Failed to restore from snapshot: Failed to load guest "
        "memory: Error creating guest memory from uffd: Failed to connect to UDS Unix stream: No "
        "such file or directory (os error 2)"
    ) in response.text


def test_unbinded_socket(uvm_plain, snapshot):
    """
    Test error scenario when PF handler has not yet called bind on socket.
    """
    vm = uvm_plain
    vm.spawn()

    jailed_vmstate = vm.create_jailed_resource(snapshot.vmstate)
    socket_path = os.path.join(vm.path, "firecracker-uffd.sock")
    run_cmd("touch {}".format(socket_path))
    jailed_sock_path = vm.create_jailed_resource(socket_path)

    response = vm.snapshot.load(
        mem_backend={"type": "Uffd", "path": jailed_sock_path},
        snapshot_path=jailed_vmstate,
    )

    assert vm.api_session.is_status_bad_request(response.status_code)
    assert (
        "Load microVM snapshot error: Failed to restore from snapshot: Failed to load guest "
        "memory: Error creating guest memory from uffd: Failed to connect to UDS Unix stream: "
        "Connection refused (os error 111)"
    ) in response.text


def test_valid_handler(uvm_plain, snapshot, uffd_handler_paths):
    """
    Test valid uffd handler scenario.
    """
    vm = uvm_plain
    vm.memory_monitor = None
    vm.spawn()

    # Spawn page fault handler process.
    _pf_handler = spawn_pf_handler(
        vm, uffd_handler_paths["valid_handler"], snapshot.mem
    )

    vm.restore_from_snapshot(snapshot, resume=True, uffd_path=SOCKET_PATH)

    # Inflate balloon.
    response = vm.balloon.patch(amount_mib=200)
    assert vm.api_session.is_status_no_content(response.status_code)

    # Deflate balloon.
    response = vm.balloon.patch(amount_mib=0)
    assert vm.api_session.is_status_no_content(response.status_code)

    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.execute_command("sync")
    assert exit_code == 0


def test_malicious_handler(uvm_plain, snapshot, uffd_handler_paths):
    """
    Test malicious uffd handler scenario.

    The page fault handler panics when receiving a page fault,
    so no events are handled and snapshot memory regions cannot be
    loaded into memory. In this case, Firecracker is designed to freeze,
    instead of silently switching to having the kernel handle page
    faults, so that it becomes obvious that something went wrong.
    """

    vm = uvm_plain
    vm.memory_monitor = None
    vm.spawn()

    # Spawn page fault handler process.
    _pf_handler = spawn_pf_handler(
        vm, uffd_handler_paths["malicious_handler"], snapshot.mem
    )

    # We expect Firecracker to freeze while resuming from a snapshot
    # due to the malicious handler's unavailability.
    try:
        with Timeout(seconds=30):
            vm.restore_from_snapshot(snapshot, resume=True, uffd_path=SOCKET_PATH)
            assert False, "Firecracker should freeze"
    except (TimeoutError, requests.exceptions.ReadTimeout):
        pass
