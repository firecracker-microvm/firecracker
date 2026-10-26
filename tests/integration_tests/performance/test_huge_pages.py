# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for Firecracker's huge pages support"""

import signal
import time
from pathlib import Path
from typing import Optional

import pytest

from framework import utils
from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.microvm import SnapshotType
from framework.properties import global_props
from framework.utils_ftrace import ftrace_events
from framework.utils_hugepages import HugePagesConfig

pytestmark = pin_guest_kernel(GUEST_KERNEL_DEFAULT)


def check_hugetlbfs_in_use(pid: int, allocation_name: str):
    """Asserts that the process with the given `pid` is using hugetlbfs pages somewhere.

    `allocation_name` should be the name of the smaps entry for which we want to verify that huge pages are used.
    For memfd-backed guest memory, this would be "memfd:guest_mem" (the `guest_mem` part originating from the name
    we give the memfd in memory.rs), for anonymous memory this would be "/anon_hugepage".
    Note: in our testing, we do not currently configure vhost-user-blk devices, so we only exercise
    the "/anon_hugepage" case.
    """

    # Format of a sample smaps entry:
    #   7fc2bc400000-7fc2cc400000 rw-s 00000000 00:10 25488401                   /anon_hugepage
    #   Size:             262144 kB
    #   KernelPageSize:     2048 kB
    #   MMUPageSize:        2048 kB
    #   Rss:                   0 kB
    #   Pss:                   0 kB
    #   Pss_Dirty:             0 kB
    #   Shared_Clean:          0 kB
    #   Shared_Dirty:          0 kB
    #   Private_Clean:         0 kB
    #   Private_Dirty:         0 kB
    #   Referenced:            0 kB
    #   Anonymous:             0 kB
    #   LazyFree:              0 kB
    #   AnonHugePages:         0 kB
    #   ShmemPmdMapped:        0 kB
    #   FilePmdMapped:         0 kB
    #   Shared_Hugetlb:        0 kB
    #   Private_Hugetlb:   92160 kB
    #   Swap:                  0 kB
    #   SwapPss:               0 kB
    #   Locked:                0 kB
    #   THPeligible:           0
    #   ProtectionKey:         0
    cmd = f"cat /proc/{pid}/smaps | grep {allocation_name} -A 23 | grep KernelPageSize"
    _, stdout, _ = utils.check_output(cmd)

    kernel_page_size_kib = int(stdout.split()[1])
    assert kernel_page_size_kib > 4


def bind_hugetlbfs_into_jail(vm, hugetlbfs_path: Path, name: str = "hugetlbfs") -> Path:
    """Bind an existing hugetlbfs mount into a microVM jail, as `/name`, before it starts."""
    jailed_mount = Path(vm.chroot()) / name
    jailed_mount.mkdir(parents=True, exist_ok=True)
    utils.check_output(
        ["mount", "--bind", str(hugetlbfs_path), str(jailed_mount)],
        shell=False,
    )
    return jailed_mount


def sha256sum(path: Path) -> str:
    """Return a file's SHA-256 digest."""
    _, stdout, _ = utils.check_output(["sha256sum", str(path)], shell=False)
    return stdout.split()[0]


def test_hugetlbfs_boot(uvm):
    """Tests booting a microvm with guest memory backed by 2MB hugetlbfs pages"""

    uvm.spawn()
    uvm.basic_config(huge_pages=HugePagesConfig.HUGETLBFS_2MB, mem_size_mib=128)
    uvm.add_net_iface()
    uvm.start()

    check_hugetlbfs_in_use(
        uvm.firecracker_pid,
        "/anon_hugepage",
    )


def test_hugetlbfs_snapshot(microvm_factory, uvm, snapshot_type):
    """
    Test hugetlbfs snapshot restore via uffd

    Despite guest memory being backed by huge pages, enabling differential snapshots
    causes KVM to set up guest mappings at 4k granularity
    """

    ### Create Snapshot ###
    vm = uvm
    vm.memory_monitor = None
    vm.spawn()
    vm.basic_config(
        huge_pages=HugePagesConfig.HUGETLBFS_2MB,
        mem_size_mib=128,
        track_dirty_pages=snapshot_type.needs_dirty_page_tracking,
    )
    vm.add_net_iface()
    vm.start()

    check_hugetlbfs_in_use(vm.firecracker_pid, "/anon_hugepage")

    snapshot = vm.make_snapshot(snapshot_type)

    vm.kill()

    ### Restore Snapshot ###
    vm = microvm_factory.build()
    vm.spawn()
    vm.restore_from_snapshot(snapshot, resume=True, uffd_handler_name="on_demand")

    check_hugetlbfs_in_use(vm.firecracker_pid, "/anon_hugepage")


@pytest.fixture
def hugetlbfs_mount(uvm, tmp_path):
    """A 2 MiB hugetlbfs mount that jailed microVMs can bind and use."""
    hugetlbfs_path = tmp_path / "hugetlbfs"
    mount_hugetlbfs(uvm, hugetlbfs_path)
    yield hugetlbfs_path
    utils.run_cmd(["umount", str(hugetlbfs_path)], shell=False)


def mount_hugetlbfs(vm, path: Path, size: Optional[str] = None):
    """Mount a 2 MiB hugetlbfs at `path` for the jailed `vm`, limited to `size` if given."""
    options = f"pagesize=2M,uid={vm.jailer.uid},gid={vm.jailer.gid},mode=0770"
    if size is not None:
        options += f",size={size}"
    path.mkdir(exist_ok=True)
    utils.check_output(
        ["mount", "-t", "hugetlbfs", "-o", options, "none", str(path)], shell=False
    )


GUEST_TMPFS = "/mnt/hugetlbfs-test"


def guest_sha256sum(vm, path: str) -> str:
    """Return the SHA-256 digest of a file in the guest."""
    _, stdout, _ = vm.ssh.check_output(f"sha256sum {path}")
    return stdout.split()[0]


def write_guest_memory_file(vm, name: str, size_mib: int = 16) -> str:
    """Write random data to a file in guest memory (tmpfs) and return its SHA-256 digest."""
    path = f"{GUEST_TMPFS}/{name}"
    # tmpfs is limited to half of the guest's memory by default.
    vm.ssh.check_output(
        f"mkdir -p {GUEST_TMPFS} && (mountpoint -q {GUEST_TMPFS}"
        f" || mount -t tmpfs -o size=100% tmpfs {GUEST_TMPFS})"
        f" && dd if=/dev/urandom of={path} bs=1M count={size_mib}"
    )
    return guest_sha256sum(vm, path)


def guest_memory_mappings(pid: int, mem_file: str, mem_size_mib: int):
    """Return the name and KernelPageSize (KiB) of each mapping of guest memory restored from
    `mem_file`. Mappings with another name replaced discarded memory.
    """
    mappings = []
    for line in Path(f"/proc/{pid}/smaps").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if "-" in fields[0] and not fields[0].endswith(":"):
            start, end = (int(address, 16) for address in fields[0].split("-"))
            mappings.append(
                {
                    "start": start,
                    "end": end,
                    "offset": int(fields[2], 16),
                    "name": " ".join(fields[5:]),
                }
            )
        elif fields[0] == "KernelPageSize:":
            mappings[-1]["kernel_page_size_kib"] = int(fields[1])

    base = min(
        m["start"] - m["offset"] for m in mappings if m["name"].endswith(mem_file)
    )
    end = base + mem_size_mib * 2**20
    return [
        (m["name"], m["kernel_page_size_kib"])
        for m in mappings
        if base <= m["start"] and m["end"] <= end
    ]


def restore_from_hugetlbfs(microvm_factory, snapshot, hugetlbfs_mount, jail_mounts):
    """Restore `snapshot` with 2M pages from its memory file at `hugetlbfs/mem`."""
    vm = microvm_factory.build()
    vm.memory_monitor = None
    jail_mounts.append(bind_hugetlbfs_into_jail(vm, hugetlbfs_mount))
    vm.spawn()
    vm.restore_from_snapshot(
        snapshot,
        resume=True,
        huge_pages=HugePagesConfig.HUGETLBFS_2MB,
        mem_backend_path="/hugetlbfs/mem",
    )
    return vm


def test_hugetlbfs_snapshot_file_backend(microvm_factory, uvm, hugetlbfs_mount):
    """Restore a hugetlbfs memory file directly without a UFFD handler."""
    jail_mounts = []
    restored_vm = None
    try:
        vm = uvm
        vm.memory_monitor = None
        jail_mounts.append(bind_hugetlbfs_into_jail(vm, hugetlbfs_mount))
        vm.spawn()
        vm.basic_config(huge_pages=HugePagesConfig.NONE, mem_size_mib=128)
        vm.add_net_iface()
        vm.start()

        snapshot = vm.make_snapshot(SnapshotType.FULL, mem_path="hugetlbfs/mem")
        vm.kill()
        snapshot_digest = sha256sum(snapshot.mem)

        restored_vm = restore_from_hugetlbfs(
            microvm_factory, snapshot, hugetlbfs_mount, jail_mounts
        )

        restored_vm.ssh.check_output(
            "dd if=/dev/zero of=/tmp/hugetlbfs-cow-test bs=1M count=16"
        )
        assert (
            restored_vm.api.machine_config.get().json()["huge_pages"]
            == HugePagesConfig.HUGETLBFS_2MB
        )
        check_hugetlbfs_in_use(restored_vm.firecracker_pid, "/hugetlbfs/mem")
        assert sha256sum(snapshot.mem) == snapshot_digest
    finally:
        uvm.kill(might_be_dead=True)
        if restored_vm is not None:
            restored_vm.kill(might_be_dead=True)
        for mount_path in reversed(jail_mounts):
            utils.run_cmd(["umount", str(mount_path)], shell=False)


def test_hugetlbfs_diff_snapshot_file_backend(microvm_factory, uvm, hugetlbfs_mount):
    """A diff snapshot on hugetlbfs is rejected as a separate layer and merges into the full
    snapshot's memory file, keeping unchanged and changed memory.
    """
    jail_mounts = []
    restored_vm = None
    try:
        vm = uvm
        vm.memory_monitor = None
        jail_mounts.append(bind_hugetlbfs_into_jail(vm, hugetlbfs_mount))
        vm.spawn()
        vm.basic_config(
            huge_pages=HugePagesConfig.HUGETLBFS_2MB,
            mem_size_mib=128,
            track_dirty_pages=True,
        )
        vm.add_net_iface()
        vm.start()

        unchanged_digest = write_guest_memory_file(vm, "unchanged")
        vm.make_snapshot(SnapshotType.FULL, mem_path="hugetlbfs/mem")

        with pytest.raises(
            RuntimeError, match="must be merged into an existing memory file"
        ):
            vm.api.snapshot_create.put(
                mem_file_path="hugetlbfs/diff",
                snapshot_path="vmstate-diff",
                snapshot_type=SnapshotType.DIFF.api_type,
            )

        vm.resume()
        changed_digest = write_guest_memory_file(vm, "changed")
        snapshot = vm.make_snapshot(SnapshotType.DIFF, mem_path="hugetlbfs/mem")
        vm.kill()

        restored_vm = restore_from_hugetlbfs(
            microvm_factory, snapshot, hugetlbfs_mount, jail_mounts
        )

        assert (
            guest_sha256sum(restored_vm, f"{GUEST_TMPFS}/unchanged") == unchanged_digest
        )
        assert guest_sha256sum(restored_vm, f"{GUEST_TMPFS}/changed") == changed_digest
    finally:
        uvm.kill(might_be_dead=True)
        if restored_vm is not None:
            restored_vm.kill(might_be_dead=True)
        for mount_path in reversed(jail_mounts):
            utils.run_cmd(["umount", str(mount_path)], shell=False)


def test_hugetlbfs_sparse_snapshot_mount_capacity(uvm, tmp_path):
    """A full snapshot on hugetlbfs only needs huge pages for the guest's nonzero memory, which
    for a freshly booted guest fits in half of its memory. Running out fails the snapshot without
    killing Firecracker.
    """
    mem_size_mib = 1024
    mounts = {"half": f"{mem_size_mib // 2}M", "tiny": "2M"}
    host_mounts = []
    jail_mounts = []
    try:
        vm = uvm
        vm.memory_monitor = None
        for name, size in mounts.items():
            host_mount = tmp_path / name
            mount_hugetlbfs(vm, host_mount, size)
            host_mounts.append(host_mount)
            jail_mounts.append(bind_hugetlbfs_into_jail(vm, host_mount, name))
        vm.spawn()
        vm.basic_config(huge_pages=HugePagesConfig.NONE, mem_size_mib=mem_size_mib)
        vm.add_net_iface()
        vm.start()

        vm.pause()
        vm.api.snapshot_create.put(
            mem_file_path="half/mem",
            snapshot_path="vmstate",
            snapshot_type=SnapshotType.FULL.api_type,
        )
        allocated = (tmp_path / "half" / "mem").stat().st_blocks * 512
        assert 0 < allocated < mem_size_mib * 2**20 // 2

        with pytest.raises(RuntimeError, match="No space left on device"):
            vm.api.snapshot_create.put(
                mem_file_path="tiny/mem",
                snapshot_path="vmstate-tiny",
                snapshot_type=SnapshotType.FULL.api_type,
            )
        vm.resume()
        vm.ssh.check_output("true")
    finally:
        uvm.kill(might_be_dead=True)
        for mount_path in reversed(jail_mounts + host_mounts):
            utils.run_cmd(["umount", str(mount_path)], shell=False)


def test_hugetlbfs_file_backend_free_page_reporting(
    microvm_factory, uvm, hugetlbfs_mount
):
    """Guest memory freed after a hugetlbfs file restore stays on 2 MiB pages."""
    # The guest only reports free memory while it has 64 MiB (32 blocks of 2 MiB) free above its
    # low watermark, so leave room for that next to the 64 MiB it writes.
    mem_size_mib = 256
    jail_mounts = []
    restored_vm = None
    try:
        vm = uvm
        vm.memory_monitor = None
        jail_mounts.append(bind_hugetlbfs_into_jail(vm, hugetlbfs_mount))
        vm.spawn()
        vm.basic_config(huge_pages=HugePagesConfig.NONE, mem_size_mib=mem_size_mib)
        vm.add_net_iface()
        vm.api.balloon.put(
            amount_mib=0,
            deflate_on_oom=False,
            stats_polling_interval_s=0,
            free_page_reporting=True,
        )
        vm.start()

        snapshot = vm.make_snapshot(SnapshotType.FULL, mem_path="hugetlbfs/mem")
        vm.kill()
        snapshot_digest = sha256sum(snapshot.mem)

        restored_vm = restore_from_hugetlbfs(
            microvm_factory, snapshot, hugetlbfs_mount, jail_mounts
        )
        pid = restored_vm.firecracker_pid

        # Free memory in the guest, so that it reports it and Firecracker discards it.
        write_guest_memory_file(restored_vm, "reported", size_mib=64)
        restored_vm.ssh.check_output(f"rm {GUEST_TMPFS}/reported")
        deadline = time.time() + 30
        while True:
            mappings = guest_memory_mappings(pid, "hugetlbfs/mem", mem_size_mib)
            if any(not name.endswith("hugetlbfs/mem") for name, _ in mappings):
                break
            assert time.time() < deadline, "no guest memory was discarded"
            time.sleep(1)
        assert all(size == 2048 for _, size in mappings), mappings

        # The guest reuses the memory it freed.
        digest = write_guest_memory_file(restored_vm, "reused", size_mib=64)
        assert guest_sha256sum(restored_vm, f"{GUEST_TMPFS}/reused") == digest
        mappings = guest_memory_mappings(pid, "hugetlbfs/mem", mem_size_mib)
        assert all(size == 2048 for _, size in mappings), mappings
        assert sha256sum(snapshot.mem) == snapshot_digest
    finally:
        uvm.kill(might_be_dead=True)
        if restored_vm is not None:
            restored_vm.kill(might_be_dead=True)
        for mount_path in reversed(jail_mounts):
            utils.run_cmd(["umount", str(mount_path)], shell=False)


def test_hugetlbfs_full_snapshot_after_restore_and_discard(
    microvm_factory, uvm, tmp_path
):
    """A full snapshot of a microVM restored from a hugetlbfs memory file, after the guest freed
    memory that Firecracker discarded, does not fault the memory the guest never touched into the
    restored mapping. Such faults would allocate huge pages from the memory file's mount, sized
    here to half of the guest's memory, and kill Firecracker with SIGBUS once it ran out. The
    snapshot keeps the guest's memory.
    """
    # The guest only reports free memory while it has 64 MiB (32 blocks of 2 MiB) free above its
    # low watermark. A freshly booted guest's memory fits in half of it (see
    # `test_hugetlbfs_sparse_snapshot_mount_capacity`), which leaves room for the 64 MiB it writes
    # after the restore, but not for the rest of its memory.
    mem_size_mib = 2048
    host_mounts = []
    jail_mounts = []
    vms = [uvm]
    try:
        source = tmp_path / "source"
        mount_hugetlbfs(uvm, source, f"{mem_size_mib // 2}M")
        host_mounts.append(source)
        vm = uvm
        vm.memory_monitor = None
        jail_mounts.append(bind_hugetlbfs_into_jail(vm, source, "source"))
        vm.spawn()
        vm.basic_config(huge_pages=HugePagesConfig.NONE, mem_size_mib=mem_size_mib)
        vm.add_net_iface()
        vm.api.balloon.put(
            amount_mib=0,
            deflate_on_oom=False,
            stats_polling_interval_s=0,
            free_page_reporting=True,
        )
        vm.start()
        kept_digest = write_guest_memory_file(vm, "kept")
        snapshot = vm.make_snapshot(SnapshotType.FULL, mem_path="source/mem")
        vm.kill()

        restored_vm = microvm_factory.build()
        vms.append(restored_vm)
        restored_vm.memory_monitor = None
        target = tmp_path / "target"
        mount_hugetlbfs(restored_vm, target)
        host_mounts.append(target)
        for name, mount in [("source", source), ("target", target)]:
            jail_mounts.append(bind_hugetlbfs_into_jail(restored_vm, mount, name))
        restored_vm.spawn()
        restored_vm.restore_from_snapshot(
            snapshot,
            resume=True,
            huge_pages=HugePagesConfig.HUGETLBFS_2MB,
            mem_backend_path="/source/mem",
        )

        # Free memory in the guest, so that it reports it and Firecracker discards it.
        pid = restored_vm.firecracker_pid
        write_guest_memory_file(restored_vm, "reported", size_mib=64)
        restored_vm.ssh.check_output(f"rm {GUEST_TMPFS}/reported")
        deadline = time.time() + 30
        while not any(
            not name.endswith("source/mem")
            for name, _ in guest_memory_mappings(pid, "source/mem", mem_size_mib)
        ):
            assert time.time() < deadline, "no guest memory was discarded"
            time.sleep(1)

        snapshot = restored_vm.make_snapshot(SnapshotType.FULL, mem_path="target/mem")
        restored_vm.resume()
        restored_vm.ssh.check_output("true")
        restored_vm.kill()

        final_vm = microvm_factory.build()
        vms.append(final_vm)
        final_vm.memory_monitor = None
        jail_mounts.append(bind_hugetlbfs_into_jail(final_vm, target, "target"))
        final_vm.spawn()
        final_vm.restore_from_snapshot(
            snapshot,
            resume=True,
            huge_pages=HugePagesConfig.HUGETLBFS_2MB,
            mem_backend_path="/target/mem",
        )
        assert guest_sha256sum(final_vm, f"{GUEST_TMPFS}/kept") == kept_digest
    finally:
        for vm in vms:
            vm.kill(might_be_dead=True)
        for mount_path in reversed(jail_mounts + host_mounts):
            utils.run_cmd(["umount", str(mount_path)], shell=False)


@pytest.mark.parametrize(
    ("source_huge_pages", "restore_huge_pages", "uffd_handler_name"),
    [
        (HugePagesConfig.NONE, HugePagesConfig.HUGETLBFS_2MB, "on_demand"),
        (HugePagesConfig.HUGETLBFS_2MB, HugePagesConfig.NONE, None),
        (HugePagesConfig.NONE, HugePagesConfig.TRANSPARENT, "on_demand"),
    ],
)
def test_snapshot_huge_pages_override(
    microvm_factory,
    uvm,
    snapshot_type,
    source_huge_pages,
    restore_huge_pages,
    uffd_handler_name,
):
    """Restore snapshots using a different huge-page configuration."""
    vm = uvm
    vm.memory_monitor = None
    vm.spawn()
    vm.basic_config(
        huge_pages=source_huge_pages,
        mem_size_mib=128,
        track_dirty_pages=snapshot_type.needs_dirty_page_tracking,
    )
    vm.add_net_iface()
    vm.start()
    snapshot = vm.make_snapshot(snapshot_type)
    vm.kill()

    vm = microvm_factory.build()
    vm.spawn()
    vm.restore_from_snapshot(
        snapshot,
        resume=True,
        huge_pages=restore_huge_pages,
        uffd_handler_name=uffd_handler_name,
    )

    assert vm.api.machine_config.get().json()["huge_pages"] == restore_huge_pages
    vm.ssh.check_output("true")
    if restore_huge_pages == HugePagesConfig.HUGETLBFS_2MB:
        check_hugetlbfs_in_use(vm.firecracker_pid, "/anon_hugepage")


@pytest.mark.parametrize("huge_pages", HugePagesConfig)
# Counts KVM exits through the host-wide kvm tracepoints, which other VMs would
# add to.
@pytest.mark.serial
def test_ept_violation_count(
    microvm_factory,
    uvm,
    metrics,
    huge_pages,
):
    """
    Tests hugetlbfs snapshot restore with a UFFD handler that pre-faults the entire guest memory
    on the first page fault. Records metrics about the number of EPT_VIOLATIONS encountered by KVM.
    """

    ### Create Snapshot ###
    vm = uvm
    vm.memory_monitor = None
    vm.spawn()
    vm.basic_config(huge_pages=huge_pages, mem_size_mib=256)
    vm.add_net_iface()
    vm.start()

    metrics.set_dimensions(
        {
            "performance_test": "test_hugetlbfs_snapshot",
            "huge_pages_config": str(huge_pages),
            **vm.dimensions,
        }
    )

    # Wait for microvm to boot. Then spawn fast_page_fault_helper to setup an environment where we can trigger
    # a lot of fast_page_faults after restoring the snapshot. This blocks until the helper has touched its
    # memory and is waiting in sigwait.
    pid = utils.start_fast_page_fault_helper(vm.ssh)

    snapshot = vm.snapshot_full()

    vm.kill()

    ### Restore Snapshot ###
    vm = microvm_factory.build()
    vm.jailer.daemonize = False
    vm.jailer.extra_args.update({"no-seccomp": None})
    vm.spawn()

    with ftrace_events("kvm:*"):
        vm.restore_from_snapshot(snapshot, resume=True, uffd_handler_name="fault_all")

        # Verify if guest can run commands, and also wake up the fast page fault helper to trigger page faults.
        vm.ssh.check_output(f"kill -s {signal.SIGUSR1} {pid}")

        # Give the helper time to touch all its pages
        time.sleep(5)

        if global_props.cpu_architecture == "x86_64":
            trace_entry = "reason EPT_VIOLATION"
            metric = "ept_violations"
        else:
            # On ARM, KVM does not differentiate why it got a guest page fault.
            # However, even in this slightly more general metric, we see a significant
            # difference between 4K and 2M pages.
            trace_entry = "kvm_guest_fault"
            metric = "guest_page_faults"

        _, metric_value, _ = utils.check_output(
            f"cat /sys/kernel/tracing/trace | grep '{trace_entry}' | wc -l"
        )

    metrics.put_metric(metric, int(metric_value), "Count")
