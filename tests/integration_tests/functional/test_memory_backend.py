# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the `SharedMemfd` memory backend.

Firecracker puts guest memory in a memfd and hands it to another process (the
backend), at boot (`machine-config.mem_backend`) or on restore
(`backend_type: SharedMemfd`). The example UFFD handlers play the backend."""

import base64
import json
import os
import re
import shutil
import time
from pathlib import Path

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.utils import make_guest_dirty_memory
from framework.utils_hugepages import HugePagesConfig
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend

pytestmark = [
    pin_guest_kernel(GUEST_KERNEL_DEFAULT),
    # KVM only: enclave guest memory cannot be handed to a backend.
    pin_vm_backend(VM_BACKEND_KVM),
]

MEM_SIZE_MIB = 256
MEM_SIZE_BYTES = MEM_SIZE_MIB * 2**20
PAGE_CONFIGS = [HugePagesConfig.NONE, HugePagesConfig.HUGETLBFS_2MB]
# How the memfd shows up in /proc; the name comes from src/vmm/src/vstate/memory.rs.
MEMFD_NAME = "memfd:guest_mem"


def boot_with_mem_backend(vm, huge_pages=HugePagesConfig.NONE, handler="on_demand"):
    """Boot `vm` with an example handler as its memory backend."""
    vm.spawn()
    if huge_pages != HugePagesConfig.NONE:
        # The memory monitor does not understand huge page mappings.
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
    """Wait for the handler to log that it received the memfd, and check its size.

    The API call that triggers the handshake can return before the handler has
    read it, so wait a little.
    """
    expected = f"Received guest memory memfd of {MEM_SIZE_BYTES} bytes"
    deadline = time.monotonic() + timeout_s
    while expected not in handler.log_data:
        assert time.monotonic() < deadline, handler.log_data
        time.sleep(0.1)


def handler_memfd(handler):
    """Path to the memfd as the handler holds it (`/proc/<pid>/fd/<n>`).

    Reading guest memory through this path uses the backend's descriptor, not
    Firecracker's."""
    fd_dir = Path(f"/proc/{handler.proc.pid}/fd")
    memfds = [fd for fd in fd_dir.iterdir() if MEMFD_NAME in os.readlink(fd)]
    assert len(memfds) == 1, f"expected one memfd in the handler, found {memfds}"
    return memfds[0]


def check_firecracker_maps_memfd(vm):
    """Check that Firecracker maps all of guest memory `MAP_SHARED` from the memfd."""
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
    """Check that two files have the same bytes. Reads them chunk by chunk."""
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


def write_guest_marker(vm):
    """Put 4 KiB of random bytes in guest RAM and return them.

    The bytes go into a file on tmpfs, which the guest keeps in RAM. Reading the
    file back shows what that page of guest memory holds right now."""
    vm.ssh.check_output("head -c 4096 /dev/urandom > /dev/shm/marker")
    marker = base64.b64decode(vm.ssh.check_output("base64 -w0 /dev/shm/marker").stdout)
    assert len(marker) == 4096
    return marker


def read_guest_marker(vm):
    """Read the marker page back, as the guest sees it now."""
    return base64.b64decode(vm.ssh.check_output("base64 -w0 /dev/shm/marker").stdout)


def find_marker(path, marker):
    """Find every copy of `marker` in `path` (a memfd or a snapshot memory file).

    There is usually more than one: the program that wrote the file left a copy
    in a page it has since freed. Returns the offsets."""
    data = Path(path).read_bytes()
    offsets = [m.start() for m in re.finditer(re.escape(marker), data)]
    assert offsets, "marker not found in guest memory"
    return offsets


def write_at(path, offsets, data):
    """Write `data` into the file at `path`, once at each of `offsets`."""
    with open(path, "r+b") as f:
        for offset in offsets:
            f.seek(offset)
            f.write(data)


@pytest.mark.parametrize("huge_pages", PAGE_CONFIGS)
def test_boot_with_mem_backend(uvm, microvm_factory, huge_pages):
    """
    Boot with `machine-config.mem_backend`. The backend gets a memfd with all of
    guest memory in it, and reading the memfd gives the same bytes as a full
    snapshot. The guest does not need the backend to stay alive, and the
    snapshot restores like any other.
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

    # Firecracker does not watch the backend. The guest keeps running without it.
    handler.kill()
    vm.resume()
    vm.ssh.check_output("true")
    vm.kill()

    restore_kwargs = {}
    if huge_pages == HugePagesConfig.HUGETLBFS_2MB:
        # The `File` backend cannot restore into 2M pages; a UFFD handler can.
        restore_kwargs["uffd_handler_name"] = "on_demand"
    restored = microvm_factory.build_from_snapshot(snapshot, **restore_kwargs)
    restored.memory_monitor = None
    assert restored.ssh.check_output("cat /tmp/marker").stdout.strip() == "hello"


@pytest.mark.parametrize("huge_pages", PAGE_CONFIGS)
def test_restore_with_mem_backend(uvm, microvm_factory, huge_pages):
    """
    Restore with `backend_type: SharedMemfd`. The handler gets the uffd and the
    memfd. It serves page faults as a plain UFFD handler does, balloon `remove`
    events included, and the memfd ends up holding what the guest sees.
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
    # `machine-config.mem_backend` is a boot setting. A restore's backend does not show up
    # there.
    assert "mem_backend" not in restored.api.machine_config.get().json()
    check_firecracker_maps_memfd(restored)
    assert restored.ssh.check_output("cat /tmp/marker").stdout.strip() == "hello"

    # Inflating the balloon sends `remove` events to the handler; deflating it and touching
    # the memory again faults the pages back in. Both work on shared memory.
    restored.api.balloon.patch(amount_mib=100)
    restored.ssh.check_output("true")
    restored.api.balloon.patch(amount_mib=0)
    make_guest_dirty_memory(restored.ssh, amount_mib=32)

    # Taking a snapshot faults every page in through the handler. After that, the memfd is
    # a complete copy of guest memory.
    again = restored.snapshot_full(mem_path="mem_again", vmstate_path="vmstate_again")
    assert_same_content(handler_memfd(handler), again.mem)
    restored.resume()
    restored.ssh.check_output("true")


def test_backend_writes_guest_memory(uvm):
    """
    Writing the memfd changes what the guest sees. At boot there is no
    userfaultfd, so no page fault machinery is involved.
    """
    vm = boot_with_mem_backend(uvm)
    marker = write_guest_marker(vm)
    new_marker = os.urandom(4096)
    memfd = handler_memfd(vm.uffd_handler)
    write_at(memfd, find_marker(memfd, marker), new_marker)
    assert read_guest_marker(vm) == new_marker


def test_restore_populates_by_writing_memfd(uvm, microvm_factory):
    """
    A backend can restore guest memory by writing the snapshot's memory file
    into the memfd. Pages written that way never raise a page fault.

    To prove it, the test kills the handler before the guest resumes.
    Firecracker keeps the userfaultfd registered, so if any page still faulted,
    nobody would serve it and the guest would hang. A guest that runs only
    touched pages the backend wrote.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config(vcpu_count=2, mem_size_mib=MEM_SIZE_MIB)
    vm.add_net_iface()
    vm.start()
    marker = write_guest_marker(vm)
    make_guest_dirty_memory(vm.ssh, amount_mib=32)
    snapshot = vm.snapshot_full()
    vm.kill()

    restored = microvm_factory.build()
    restored.spawn()
    restored.memory_monitor = None
    restored.restore_from_snapshot(
        snapshot, resume=False, uffd_handler_name="on_demand", mem_backend=True
    )
    handler = restored.uffd_handler
    check_handshake(handler)

    # Write all of guest memory, with a new marker page, then take the handler away.
    memfd = handler_memfd(handler)
    with open(snapshot.mem, "rb") as src, open(memfd, "r+b") as dst:
        shutil.copyfileobj(src, dst, 16 * 2**20)
    new_marker = os.urandom(4096)
    write_at(memfd, find_marker(snapshot.mem, marker), new_marker)
    handler.kill()

    restored.resume()
    assert read_guest_marker(restored) == new_marker
    make_guest_dirty_memory(restored.ssh, amount_mib=32)


def test_boot_from_config_file_with_mem_backend(uvm):
    """
    `mem_backend` also works in the `machine-config` section of the config
    file. A microVM started with `--config-file` shares its memory from the
    first instruction.
    """
    vm = uvm
    # With a config file the boot happens at once, so the handler must listen first.
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
    # Serial output is set up through the API after spawning, which fails on a microVM
    # that has already booted.
    vm.spawn(serial_out_path=None)

    assert vm.state == "Running"
    assert vm.api.machine_config.get().json()["mem_backend"] == mem_backend
    check_handshake(vm.uffd_handler)
    check_firecracker_maps_memfd(vm)


def test_fault_all_handler_as_backend(uvm, microvm_factory):
    """The fault_all handler takes the memfd too, at boot and on restore."""
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
    """Requests that are rejected, and what a failed boot leaves behind."""
    vm = uvm
    vm.spawn()

    # Only `SharedMemfd` is allowed in machine-config.mem_backend.
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

    # If the backend cannot be reached, the boot fails. Firecracker stays up, not booted.
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

    # A `PUT` without the field removes the backend. The microVM then boots without one.
    vm.api.machine_config.put(vcpu_count=2, mem_size_mib=MEM_SIZE_MIB)
    assert "mem_backend" not in vm.api.machine_config.get().json()
    vm.add_net_iface()
    vm.start()
    vm.ssh.check_output("true")
