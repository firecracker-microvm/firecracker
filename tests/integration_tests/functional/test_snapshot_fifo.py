# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for snapshot memory output to FIFOs."""

import os
import threading
from pathlib import Path

import pytest

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.microvm import SnapshotType

COMPARE_CHUNK_SIZE = 64 * 1024


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_full_snapshot_to_fifo_with_unplugged_slots(uvm_configured):
    """Stream a full snapshot through a FIFO, including an unplugged slot."""
    vm = uvm_configured
    # Leave both 64 MiB slots unplugged so the memory dump contains holes.
    vm.api.memory_hotplug.put(total_size_mib=128, slot_size_mib=64, block_size_mib=2)
    vm.add_net_iface()
    vm.start()
    vm.pause()

    root = Path(vm.chroot())
    regular_mem = root / "mem_regular"
    vm.api.snapshot_create.put(
        mem_file_path="mem_regular",
        snapshot_path="vmstate_regular",
        snapshot_type=SnapshotType.FULL.api_type,
    )
    expected_size = regular_mem.stat().st_size
    assert expected_size > 256 * 1024 * 1024

    fifo_path = root / "mem_fifo"
    fifo_path.unlink(missing_ok=True)
    os.mkfifo(fifo_path)
    reader_errors = []
    bytes_compared = []

    def compare_fifo_to_regular_file():
        try:
            with regular_mem.open("rb") as expected, fifo_path.open("rb") as fifo:
                offset = 0
                while expected_chunk := expected.read(COMPARE_CHUNK_SIZE):
                    actual_chunk = fifo.read(len(expected_chunk))
                    if actual_chunk != expected_chunk:
                        raise AssertionError(
                            f"FIFO snapshot differs at byte offset {offset}"
                        )
                    offset += len(expected_chunk)
                if fifo.read(1):
                    raise AssertionError("FIFO snapshot contains trailing bytes")
                bytes_compared.append(offset)
        except Exception as exc:  # pylint: disable=broad-except
            reader_errors.append(exc)

    reader = threading.Thread(target=compare_fifo_to_regular_file, daemon=True)
    reader.start()
    try:
        vm.api.snapshot_create.put(
            mem_file_path="mem_fifo",
            snapshot_path="vmstate_fifo",
            snapshot_type=SnapshotType.FULL.api_type,
        )
    finally:
        # The writer closes the FIFO when snapshot creation returns.
        reader.join(timeout=120)

    assert not reader.is_alive(), "FIFO reader thread hung"
    assert not reader_errors, f"FIFO reader failed: {reader_errors}"
    assert bytes_compared == [expected_size]
    vm.resume()


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_diff_snapshot_to_fifo_fails_fast(uvm_configured):
    """A diff snapshot to a FIFO returns a clear error rather than seeking."""
    vm = uvm_configured
    vm.add_net_iface()
    vm.start()
    vm.pause()

    fifo_path = Path(vm.chroot()) / "mem_fifo"
    fifo_path.unlink(missing_ok=True)
    os.mkfifo(fifo_path)
    reader_errors = []

    def drain_fifo():
        try:
            with fifo_path.open("rb") as fifo:
                while fifo.read(COMPARE_CHUNK_SIZE):
                    pass
        except Exception as exc:  # pylint: disable=broad-except
            reader_errors.append(exc)

    reader = threading.Thread(target=drain_fifo, daemon=True)
    reader.start()
    try:
        with pytest.raises(
            RuntimeError,
            match="diff snapshots require a seekable regular memory backing file",
        ):
            vm.api.snapshot_create.put(
                mem_file_path="mem_fifo",
                snapshot_path="vmstate_diff_fifo",
                snapshot_type=SnapshotType.DIFF.api_type,
            )
    finally:
        reader.join(timeout=120)

    assert not reader.is_alive(), "FIFO reader thread hung"
    assert not reader_errors, f"FIFO reader failed: {reader_errors}"
