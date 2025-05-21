# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test UFFD related functionality when resuming from snapshot."""

import os
import re

import pytest
import requests

from framework.utils import Timeout, check_output


@pytest.fixture(scope="function", name="snapshot")
def snapshot_fxt(microvm_factory, guest_kernel_linux_5_10, rootfs):
    """Create a snapshot of a microVM."""

    basevm = microvm_factory.build(guest_kernel_linux_5_10, rootfs)
    basevm.spawn()
    basevm.basic_config(vcpu_count=2, mem_size_mib=256)
    basevm.add_net_iface()

    # Add a memory balloon.
    basevm.api.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )

    basevm.start()

    # Create base snapshot.
    snapshot = basevm.snapshot_full()
    basevm.kill()

    yield snapshot


def test_bad_socket_path(uvm_plain, snapshot):
    """
    Test error scenario when socket path does not exist.
    """
    vm = uvm_plain
    vm.spawn()
    jailed_vmstate = vm.create_jailed_resource(snapshot.vmstate)

    expected_msg = re.escape(
        "Load snapshot error: Failed to restore from snapshot: Failed to load guest "
        "memory: Error creating guest memory from uffd: Failed to connect to UDS Unix stream: No "
        "such file or directory (os error 2)"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.snapshot_load.put(
            mem_backend={"backend_type": "Uffd", "backend_path": "inexistent"},
            snapshot_path=jailed_vmstate,
        )

    vm.mark_killed()


def test_unbinded_socket(uvm_plain, snapshot):
    """
    Test error scenario when PF handler has not yet called bind on socket.
    """
    vm = uvm_plain
    vm.spawn()

    jailed_vmstate = vm.create_jailed_resource(snapshot.vmstate)
    socket_path = os.path.join(vm.path, "firecracker-uffd.sock")
    check_output("touch {}".format(socket_path))
    jailed_sock_path = vm.create_jailed_resource(socket_path)

    expected_msg = re.escape(
        "Load snapshot error: Failed to restore from snapshot: Failed to load guest "
        "memory: Error creating guest memory from uffd: Failed to connect to UDS Unix stream: "
        "Connection refused (os error 111)"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.snapshot_load.put(
            mem_backend={"backend_type": "Uffd", "backend_path": jailed_sock_path},
            snapshot_path=jailed_vmstate,
        )

    vm.mark_killed()


def test_valid_handler(uvm_plain, snapshot):
    """
    Test valid uffd handler scenario.
    """
    vm = uvm_plain
    vm.memory_monitor = None
    vm.spawn()
    vm.restore_from_snapshot(snapshot, resume=True, uffd_handler_name="on_demand")

    # Inflate balloon.
    vm.api.balloon.patch(amount_mib=200)

    # Verify if the restored guest works.
    vm.ssh.check_output("true")

    # Deflate balloon.
    vm.api.balloon.patch(amount_mib=0)

    # Verify if the restored guest works.
    vm.ssh.check_output("true")


def test_malicious_handler(uvm_plain, snapshot):
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

    # We expect Firecracker to freeze while resuming from a snapshot
    # due to the malicious handler's unavailability.
    try:
        with Timeout(seconds=30):
            vm.restore_from_snapshot(
                snapshot, resume=True, uffd_handler_name="malicious"
            )
            assert False, "Firecracker should freeze"
    except (TimeoutError, requests.exceptions.ReadTimeout):
        vm.uffd_handler.mark_killed()
