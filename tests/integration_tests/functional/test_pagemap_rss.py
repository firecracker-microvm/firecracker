# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Check the pagemap RSS sampler used by the memory monitor against smaps."""

import ctypes
import mmap
import os
from pathlib import Path

from host_tools.pagemap import PAGE_SIZE, ProcessRss

THP_PMD_SIZE = Path("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size")


def map_private(length, fileno=-1):
    """Map `length` bytes privately and return the mapping and its address."""
    mapping = mmap.mmap(fileno, length, flags=mmap.MAP_PRIVATE)
    # a flag Python's own allocations lack keeps the mapping in a VMA of its own
    mapping.madvise(mmap.MADV_DONTFORK)
    return mapping, ctypes.addressof(ctypes.c_char.from_buffer(mapping))


def smaps_rss(addr):
    """Return the smaps Rss of this process's mapping containing `addr`."""
    smaps = Path("/proc/self/smaps").read_text(encoding="utf-8", errors="replace")
    inside = False
    for line in smaps.splitlines():
        head = line.split(maxsplit=1)[0]
        if not head.endswith(":"):
            start, end = (int(bound, 16) for bound in head.split("-"))
            inside = start <= addr < end
        elif inside and head == "Rss:":
            return int(line.split()[1]) * 1024
    raise LookupError(hex(addr))


def test_pagemap_rss_matches_smaps(tmp_path):
    """
    Check ProcessRss against smaps where pagemap reports pages smaps does not
    count: read faults on anonymous memory map the zero page, or the huge zero
    page in a THP-advised range.
    """
    mappings = []

    anon, addr = map_private(16 * PAGE_SIZE)
    for page in range(16):
        _ = anon[page * PAGE_SIZE]
    anon[: 8 * PAGE_SIZE] = b"x" * (8 * PAGE_SIZE)
    mappings.append((anon, addr))

    if THP_PMD_SIZE.exists():
        pmd = int(THP_PMD_SIZE.read_text(encoding="ascii"))
        thp, base = map_private(2 * pmd)
        offset = -base % pmd
        thp.madvise(mmap.MADV_HUGEPAGE, offset, pmd)
        _ = thp[offset]
        mappings.append((thp, base + offset))

    backing = tmp_path / "backing"
    backing.write_bytes(b"y" * (64 * PAGE_SIZE))
    with backing.open("rb") as file:
        file_map, addr = map_private(64 * PAGE_SIZE, file.fileno())
    for page in range(32):
        _ = file_map[page * PAGE_SIZE]
    mappings.append((file_map, addr))

    rss = ProcessRss(os.getpid())
    try:
        for _, addr in mappings:
            sampled = rss.sample(lambda start, end, addr=addr: not start <= addr < end)
            assert sampled == smaps_rss(addr), hex(addr)
    finally:
        rss.close()
