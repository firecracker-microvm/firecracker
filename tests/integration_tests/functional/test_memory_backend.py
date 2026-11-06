# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the `SharedMemfd` memory backend: guest memory shared with an
external process through a memfd, at boot (`machine-config.mem_backend`) and
on restore (`backend_type: SharedMemfd`)."""

import json
import os
import re
import time
from pathlib import Path

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.utils import make_guest_dirty_memory
from framework.utils_hugepages import HugePagesConfig

pytestmark = pin_guest_kernel(GUEST_KERNEL_DEFAULT)

MEM_SIZE_MIB = 256
MEM_SIZE_BYTES = MEM_SIZE_MIB * 2**20
PAGE_CONFIGS = [HugePagesConfig.NONE, HugePagesConfig.HUGETLBFS_2MB]
# The name given to the memfd in src/vmm/src/vstate/memory.rs.
MEMFD_NAME = "memfd:guest_mem"


def boot_with_mem_backend(vm, huge_pages=HugePagesConfig.NONE, handler="on_demand"):
    """Boot `vm` with an example handler attached as memory backend."""
    vm.spawn()
    if huge_pages != HugePagesConfig.NONE:
        # Huge page mappings are not accounted the way the monitor expects.
        vm.memory_monitor = None
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=MEM_SIZE_MIB,
        huge_pages=huge_pages,
        mem_backend=handler,
    )
    vm.add_net_iface()
    vm.start()
    assert vm.uffd_handler.is_running(), vm.uffd_handler.log_data
    return vm


def check_handshake(handler, timeout_s=5):
    """The handler received the guest memory memfd, as large as guest memory.

    The handler logs it right after the handshake, which may still be in flight
    when the API call that triggered it returns.
    """
    expected = f"Received guest memory memfd of {MEM_SIZE_BYTES} bytes"
    deadline = time.monotonic() + timeout_s
    while expected not in handler.log_data:
        assert time.monotonic() < deadline, handler.log_data
        time.sleep(0.1)


def handler_memfd(handler):
    """The guest memory memfd as held by the handler process, found through
    `/proc`, so that the test reads guest memory through the backend's own
    descriptor rather than Firecracker's."""
    fd_dir = Path(f"/proc/{handler.proc.pid}/fd")
    memfds = [fd for fd in fd_dir.iterdir() if MEMFD_NAME in os.readlink(fd)]
    assert len(memfds) == 1, f"expected one memfd in the handler, found {memfds}"
    return memfds[0]


def check_firecracker_maps_memfd(vm):
    """Firecracker maps guest memory `MAP_SHARED` from the memfd."""
    maps = Path(f"/proc/{vm.firecracker_pid}/maps").read_text(encoding="utf-8")
    shared = [
        line
        for line in maps.splitlines()
        if MEMFD_NAME in line and re.match(r"\S+ rw-s ", line)
    ]
    assert shared, f"no shared memfd mapping in Firecracker:\n{maps}"
    mapped = sum(
        int(end, 16) - int(start, 16)
        for start, end in (line.split()[0].split("-") for line in shared)
    )
    assert mapped == MEM_SIZE_BYTES


def assert_same_content(path_a, path_b, chunk_size=16 * 2**20):
    """Byte-for-byte comparison of two files, chunk by chunk."""
    with open(path_a, "rb") as a, open(path_b, "rb") as b:
        offset = 0
        while True:
            chunk_a, chunk_b = a.read(chunk_size), b.read(chunk_size)
            assert (
                chunk_a == chunk_b
            ), f"content differs within {offset:#x}+{chunk_size:#x}"
            if not chunk_a:
                break
            offset += len(chunk_a)


@pytest.mark.parametrize("huge_pages", PAGE_CONFIGS)
def test_boot_with_mem_backend(uvm, microvm_factory, huge_pages):
    """
    Booting with `machine-config.mem_backend` hands the backend a memfd holding
    all of guest memory; what the backend reads from it is what Firecracker
    writes to a full snapshot. Firecracker does not depend on the backend
    staying alive, and the snapshot restores like any other.
    """
    vm = boot_with_mem_backend(uvm, huge_pages)
    handler = vm.uffd_handler
    check_handshake(handler)
    check_firecracker_maps_memfd(vm)
    assert vm.api.machine_config.get().json()["mem_backend"] == {
        "backend_type": "SharedMemfd",
        "backend_path": str(handler.socket_path),
    }

    vm.ssh.check_output("echo hello > /tmp/marker")
    make_guest_dirty_memory(vm.ssh, amount_mib=32)
    snapshot = vm.snapshot_full()
    assert_same_content(handler_memfd(handler), snapshot.mem)

    # Firecracker does not monitor the backend: the guest keeps running without it.
    handler.kill()
    vm.resume()
    vm.ssh.check_output("true")
    vm.kill()

    restore_kwargs = {}
    if huge_pages == HugePagesConfig.HUGETLBFS_2MB:
        # Explicit 2M pages cannot be populated by the `File` backend.
        restore_kwargs["uffd_handler_name"] = "on_demand"
    restored = microvm_factory.build_from_snapshot(snapshot, **restore_kwargs)
    restored.memory_monitor = None
    assert restored.ssh.check_output("cat /tmp/marker").stdout.strip() == "hello"


@pytest.mark.parametrize("huge_pages", PAGE_CONFIGS)
def test_restore_with_mem_backend(uvm, microvm_factory, huge_pages):
    """
    Restoring with `backend_type: SharedMemfd` hands the handler the uffd and
    the memfd; it serves page faults like a plain UFFD handler, including
    balloon `remove` events, and the memfd ends up holding what the guest sees.
    """
    vm = uvm
    vm.spawn()
    vm.memory_monitor = None
    vm.basic_config(vcpu_count=2, mem_size_mib=MEM_SIZE_MIB, huge_pages=huge_pages)
    vm.add_net_iface()
    vm.api.balloon.put(amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0)
    vm.start()
    vm.ssh.check_output("echo hello > /tmp/marker")
    make_guest_dirty_memory(vm.ssh, amount_mib=32)
    snapshot = vm.snapshot_full()
    vm.kill()

    restored = microvm_factory.build_from_snapshot(
        snapshot, uffd_handler_name="on_demand", mem_backend=True
    )
    restored.memory_monitor = None
    handler = restored.uffd_handler
    check_handshake(handler)
    check_firecracker_maps_memfd(restored)
    assert restored.ssh.check_output("cat /tmp/marker").stdout.strip() == "hello"

    # Balloon traffic (`remove` events, then faults on the released ranges) works on the
    # shared memory as it does on anonymous memory.
    restored.api.balloon.patch(amount_mib=100)
    restored.ssh.check_output("true")
    restored.api.balloon.patch(amount_mib=0)
    make_guest_dirty_memory(restored.ssh, amount_mib=32)

    # Dumping memory faults every page in through the handler, after which the memfd is a
    # complete copy of guest memory.
    again = restored.snapshot_full(mem_path="mem_again", vmstate_path="vmstate_again")
    assert_same_content(handler_memfd(handler), again.mem)
    restored.resume()
    restored.ssh.check_output("true")


def test_boot_from_config_file_with_mem_backend(uvm):
    """
    `mem_backend` is also accepted in the `machine-config` section of the
    configuration file, so a microVM started with `--config-file` can share its
    memory from the very first instruction.
    """
    vm = uvm
    # The handler must listen before Firecracker starts, since the boot is immediate.
    mem_backend = vm.spawn_mem_backend()
    vm.create_jailed_resource(vm.kernel_file)
    vm.create_jailed_resource(vm.rootfs_file)
    config = {
        "boot-source": {
            "kernel_image_path": vm.kernel_file.name,
            "boot_args": "console=ttyS0 reboot=k panic=1",
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": vm.rootfs_file.name,
                "is_root_device": True,
                "is_read_only": True,
            }
        ],
        "machine-config": {
            "vcpu_count": 2,
            "mem_size_mib": MEM_SIZE_MIB,
            "mem_backend": mem_backend,
        },
    }
    config_file = Path(vm.chroot()) / "vm_config.json"
    config_file.write_text(json.dumps(config), encoding="utf-8")
    vm.jailer.extra_args = {"config-file": config_file.name}
    # The serial output is configured through the API after spawning, which a booted
    # microVM refuses.
    vm.spawn(serial_out_path=None)

    assert vm.state == "Running"
    assert vm.api.machine_config.get().json()["mem_backend"] == mem_backend
    check_handshake(vm.uffd_handler)
    check_firecracker_maps_memfd(vm)


def test_fault_all_handler_as_backend(uvm, microvm_factory):
    """The other example handler takes the memfd too, at boot and on restore."""
    vm = boot_with_mem_backend(uvm, handler="fault_all")
    check_handshake(vm.uffd_handler)
    snapshot = vm.snapshot_full()
    vm.kill()

    restored = microvm_factory.build_from_snapshot(
        snapshot, uffd_handler_name="fault_all", mem_backend=True
    )
    restored.memory_monitor = None
    check_handshake(restored.uffd_handler)
    restored.ssh.check_output("true")


def test_negative_api(uvm):
    """Requests that are invalid with a memory backend."""
    vm = uvm
    vm.spawn()

    # machine-config.mem_backend accepts only `SharedMemfd`.
    for backend_type in ("File", "Uffd"):
        with pytest.raises(RuntimeError, match="SharedMemfd"):
            vm.api.machine_config.put(
                vcpu_count=2,
                mem_size_mib=MEM_SIZE_MIB,
                mem_backend={"backend_type": backend_type, "backend_path": "/x"},
            )
    with pytest.raises(RuntimeError, match="unknown variant `foo`"):
        vm.api.machine_config.put(
            vcpu_count=2,
            mem_size_mib=MEM_SIZE_MIB,
            mem_backend={"backend_type": "foo", "backend_path": "/x"},
        )
    assert "mem_backend" not in vm.api.machine_config.get().json()

    # An unreachable backend fails the boot; Firecracker stays up, not booted.
    vm.basic_config(vcpu_count=2, mem_size_mib=MEM_SIZE_MIB)
    vm.api.machine_config.put(
        vcpu_count=2,
        mem_size_mib=MEM_SIZE_MIB,
        mem_backend={"backend_type": "SharedMemfd", "backend_path": "/missing"},
    )
    expected_msg = re.escape(
        "Cannot hand guest memory to the memory backend: Failed to connect to UDS Unix "
        "stream: No such file or directory (os error 2)"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        vm.api.actions.put(action_type="InstanceStart")
    assert vm.api.describe.get().json()["state"] == "Not started"

    # A `PUT` without the field removes the backend, and the microVM boots without one.
    vm.api.machine_config.put(vcpu_count=2, mem_size_mib=MEM_SIZE_MIB)
    assert "mem_backend" not in vm.api.machine_config.get().json()
    vm.add_net_iface()
    vm.start()
    vm.ssh.check_output("true")
