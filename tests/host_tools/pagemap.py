# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Resident size of a process's mappings, read from /proc/<pid>/pagemap.

Reading smaps' Rss makes the kernel walk the page tables of every mapping and
compute PSS. pagemap is read by address range, so the mappings a caller skips
(for Firecracker, guest memory) cost nothing.

Like smaps, the count leaves out PTEs mapping the zero page or the huge zero
page. Recognising these pages needs their PFNs, which pagemap only shows with
CAP_SYS_ADMIN.

Only present entries are counted. Pages caught mid-migration appear as swap
entries and are omitted, unlike in smaps. A sample can therefore briefly read
low by a page per migrating PTE or a whole transparent huge page per migrating
PMD.
"""

import ctypes
import functools
import mmap
import os
from pathlib import Path

import numpy as np

PAGE_SIZE = mmap.PAGESIZE
# Bit 63 is "present"; bits 0-54 hold the PFN of a present page
# (Documentation/admin-guide/mm/pagemap.rst).
_PFN_MASK = (1 << 55) - 1

_THP = Path("/sys/kernel/mm/transparent_hugepage")


def _thp_setting(name):
    """Return a THP sysfs setting, or None if the kernel has no THP support."""
    try:
        return (_THP / name).read_text(encoding="ascii").strip()
    except OSError:
        return None


_PMD_SIZE = int(_thp_setting("hpage_pmd_size") or 0)

# Probe mappings are never unmapped, so the huge zero page stays allocated.
_PROBES = []


@functools.cache
def _zero_pfns():
    """Return the PFNs of the zero page and the huge zero page (None if absent)."""
    pagemap = os.open("/proc/self/pagemap", os.O_RDONLY | os.O_CLOEXEC)

    def read_fault_pfn(align):
        probe = mmap.mmap(-1, 2 * align, flags=mmap.MAP_PRIVATE)
        _PROBES.append(probe)
        base = ctypes.addressof(ctypes.c_char.from_buffer(probe))
        offset = -base % align
        if align > PAGE_SIZE:
            probe.madvise(mmap.MADV_HUGEPAGE, offset, align)
        elif _PMD_SIZE:
            # whatever THP's mode, this fault must map the 4 KiB zero page
            probe.madvise(mmap.MADV_NOHUGEPAGE)
        _ = probe[offset]
        entry = int.from_bytes(
            os.pread(pagemap, 8, (base + offset) // PAGE_SIZE * 8), "little"
        )
        return entry & _PFN_MASK if entry >> 63 else 0

    try:
        zero = read_fault_pfn(PAGE_SIZE)
        if not zero:
            raise PermissionError("reading PFNs from pagemap needs CAP_SYS_ADMIN")
        # With use_zero_page=0 a read fault in a THP range allocates a real
        # huge page instead, so there is no huge zero page to look for. With THP
        # disabled the fault maps the 4 KiB zero page.
        huge = None
        if _PMD_SIZE and _thp_setting("use_zero_page") == "1":
            huge = read_fault_pfn(_PMD_SIZE)
    finally:
        os.close(pagemap)
    return zero, None if huge in (None, zero) else huge


def _resident_pages(entries):
    """Count present pagemap entries that do not map either zero page."""
    zero, huge_zero = _zero_pfns()
    values = np.frombuffer(entries, dtype=np.uint64)
    pfn = values[(values >> np.uint64(63)) == 1] & np.uint64(_PFN_MASK)
    zero_page = pfn == zero
    if huge_zero is not None:
        # The huge zero page has one PFN per PAGE_SIZE slice.
        zero_page |= (pfn >= huge_zero) & (pfn < huge_zero + _PMD_SIZE // PAGE_SIZE)
    return int(pfn.size - np.count_nonzero(zero_page))


class ProcessRss:
    """Sample the resident size of a process's mappings through pagemap."""

    def __init__(self, pid):
        _zero_pfns()
        self._maps = Path(f"/proc/{pid}/maps")
        self._pagemap = os.open(f"/proc/{pid}/pagemap", os.O_RDONLY | os.O_CLOEXEC)

    def close(self):
        """Release the pagemap file descriptor."""
        os.close(self._pagemap)

    def sample(self, skip=None):
        """Return the resident bytes of the mappings for which `skip(start, end)` is false."""
        entries = []
        for line in self._maps.read_bytes().splitlines():
            fields = line.split()
            start, end = (int(addr, 16) for addr in fields[0].split(b"-"))
            # [vsyscall] lies above the address range pagemap covers
            if fields[-1] == b"[vsyscall]" or (skip and skip(start, end)):
                continue
            offset = start // PAGE_SIZE * 8
            length = (end - start) // PAGE_SIZE * 8
            entries.append(os.pread(self._pagemap, length, offset))
        # Count once per sample to amortize NumPy's fixed per-call overhead.
        return _resident_pages(b"".join(entries)) * PAGE_SIZE
