# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Snapshot trees: chains and branches of Diff snapshots restored through
`uffd_layered_handler`, which serves each page from the newest layer that
has it. See docs/snapshotting/handling-page-faults-on-snapshot-resume.md.

The tree built by the `tree` fixture (each node writes one marker file to
/dev/shm/tree, which lives in guest memory):

    root (Full, marker a) -> n1 (Diff, b) -> n2 (Diff, c)
"""

import errno
import os
import platform
from dataclasses import dataclass

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.microvm import Snapshot

PAGE = 4096
# aarch64 layout.rs SYSTEM_MEM_SIZE: system memory sits at offset 0 of the
# memory file, and Firecracker rewrites the top of it on every restore.
AARCH64_SYSTEM_MEM_SIZE = 0x20_0000
# tmpfs, so the markers live in guest memory only.
MARKERS = "/dev/shm/tree"


@dataclass
class Node:
    """A snapshot plus the memory layers it is a diff over (oldest first)."""

    snapshot: Snapshot
    bases: list

    @property
    def layers(self):
        """All memory layers, oldest first."""
        return self.bases + [self.snapshot.mem]


def _restore(microvm_factory, node, resume=True):
    vm = microvm_factory.build()
    vm.memory_monitor = None
    vm.spawn()
    vm.restore_from_snapshot(
        node.snapshot,
        resume=resume,
        uffd_handler_name="layered",
        uffd_base_layers=node.bases,
        # Track at every level, so the next Diff holds only written pages
        # (without it Diff falls back to mincore, which after a UFFD
        # restore also reports pages the guest only read).
        track_dirty_pages=True,
    )
    return vm


def _child(microvm_factory, parent, marker):
    """Restore `parent`, write `marker` and take a Diff: a child of `parent`."""
    vm = _restore(microvm_factory, parent)
    vm.ssh.check_output(f"echo {marker} > {MARKERS}/{marker}")
    snapshot = vm.snapshot_diff()
    vm.kill()
    return Node(snapshot, parent.layers)


def _markers(vm):
    return vm.ssh.check_output(f"ls {MARKERS}").stdout.split()


def _data_extents(fd, size):
    offset = 0
    while offset < size:
        try:
            data = os.lseek(fd, offset, os.SEEK_DATA)
        except OSError as err:
            if err.errno == errno.ENXIO:
                return
            raise
        hole = min(os.lseek(fd, data, os.SEEK_HOLE), size)
        yield data, hole - data
        offset = hole


def _merge(layers):
    """The merged image of `layers` (oldest first): newest data wins."""
    size = os.path.getsize(layers[0])
    image = bytearray(size)
    for layer in layers:
        assert os.path.getsize(layer) == size
        fd = os.open(layer, os.O_RDONLY)
        try:
            for offset, length in _data_extents(fd, size):
                image[offset : offset + length] = os.pread(fd, length, offset)
        finally:
            os.close(fd)
    return image


@pytest.fixture(name="tree")
def tree_fxt(microvm_factory, guest_kernel, rootfs):
    """Build root -> n1 -> n2, restoring through the layered handler."""
    vm = microvm_factory.build(guest_kernel, rootfs)
    vm.spawn()
    vm.basic_config(vcpu_count=2, mem_size_mib=256, track_dirty_pages=True)
    vm.add_net_iface()
    vm.start()
    vm.ssh.check_output(f"mkdir {MARKERS} && echo a > {MARKERS}/a")
    root = Node(vm.snapshot_full(), [])
    vm.kill()

    n1 = _child(microvm_factory, root, "b")
    n2 = _child(microvm_factory, n1, "c")
    return {"root": root, "n1": n1, "n2": n2}


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_chain_restore(microvm_factory, tree):
    """Each node sees its ancestors' markers and none of its descendants'."""
    for name, expected in (("n2", ["a", "b", "c"]), ("n1", ["a", "b"])):
        vm = _restore(microvm_factory, tree[name])
        assert _markers(vm) == expected, name
        vm.kill()


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_diffs_are_sparse(tree):
    """A Diff layer only allocates the pages written since its parent."""
    size = os.path.getsize(tree["root"].snapshot.mem)
    for name in ("n1", "n2"):
        mem = tree[name].snapshot.mem
        assert os.path.getsize(mem) == size
        assert os.stat(mem).st_blocks * 512 < size // 4, name


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_branches_are_isolated(microvm_factory, tree):
    """Two children of n1 each see only their own marker."""
    left = _child(microvm_factory, tree["n1"], "left")
    right = _child(microvm_factory, tree["n1"], "right")
    for node, own in ((left, "left"), (right, "right")):
        vm = _restore(microvm_factory, node)
        assert _markers(vm) == ["a", "b", own]
        vm.kill()


@pytest.mark.skipif(
    platform.machine() != "aarch64",
    reason="restore-rewritten guest ranges are only mapped for aarch64",
)
@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_memory_matches_merged_chain(microvm_factory, tree):
    """Guest memory restored from n2 is the merge of root, n1 and n2."""
    vm = _restore(microvm_factory, tree["n2"], resume=False)
    dumped = vm.snapshot_full(mem_path="dumped.mem", vmstate_path="dumped.vmstate")
    vm.kill()
    expected = _merge(tree["n2"].layers)
    actual = bytearray(dumped.mem.read_bytes())
    assert len(actual) == len(expected)

    # Firecracker itself rewrites these on every restore, so they cannot
    # match the snapshot: VMGenID's 16-byte id (a fresh random value) at the
    # top of system memory, and the VMClock page below it.
    top = AARCH64_SYSTEM_MEM_SIZE
    for start, end in ((top - 16, top), (top - 2 * PAGE, top - PAGE)):
        expected[start:end] = actual[start:end] = bytes(end - start)

    bad = [
        hex(off)
        for off in range(0, len(actual), PAGE)
        if actual[off : off + PAGE] != expected[off : off + PAGE]
    ]
    assert not bad, f"pages differ at {bad[:16]}"
