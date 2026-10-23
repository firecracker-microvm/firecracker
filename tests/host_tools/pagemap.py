# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Resident size of a process's mappings, read from /proc/<pid>/pagemap.

smaps reports the same Rss, but to produce it the kernel walks the page tables
of every mapping and computes PSS. pagemap is read by address range, so the
mappings a caller skips (for Firecracker, guest memory) cost nothing.

The count matches smaps' Rss: PTEs mapping the zero page or the huge zero page
are left out, and pages under migration are counted. Recognising the zero
pages needs their PFNs, which pagemap only shows with CAP_SYS_ADMIN.
"""

import ctypes
import functools
import mmap
import os
import re
from pathlib import Path

PAGE_SIZE = mmap.PAGESIZE
_PFN_MASK = (1 << 55) - 1
# Byte 7 of each little-endian pagemap entry holds bits 56-63: 63 present,
# 62 swapped, 61 file-backed or shared, 57 uffd-wp, 56 mapped exclusively.
_PRESENT = bytes(b >> 7 for b in range(256))
# Present but neither file-backed nor exclusive, as a zero page PTE is.
_NO_PAGE_RE = re.compile(rb"[\x80\x82]")
# Swapped, not present. smaps counts swap types 16-30 (migration, device and
# hwpoison entries) as Rss; real swap areas use lower types, and type 31 is a
# PTE marker, which maps nothing.
_SWAP_RE = re.compile(rb"[\x40-\x7f]")

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


def _resident_pages(entries, start, end):
    """Count the pagemap entries of [start, end) that smaps counts as Rss."""
    zero, huge_zero = _zero_pfns()
    top = entries[7::8]
    pages = top.translate(_PRESENT).count(1)
    for match in _NO_PAGE_RE.finditer(top):
        off = match.start() * 8
        if int.from_bytes(entries[off : off + 7], "little") & _PFN_MASK == zero:
            pages -= 1
    if huge_zero is not None:
        # the huge zero page is mapped by whole PMDs, so at aligned addresses
        for addr in range(start + (-start % _PMD_SIZE), end - _PMD_SIZE + 1, _PMD_SIZE):
            off = (addr - start) // PAGE_SIZE * 8
            entry = int.from_bytes(entries[off : off + 8], "little")
            if entry >> 63 and entry & _PFN_MASK == huge_zero:
                pages -= _PMD_SIZE // PAGE_SIZE
    for match in _SWAP_RE.finditer(top):
        # the low 5 bits of a swap-format entry hold its swap type
        if 16 <= entries[match.start() * 8] & 0x1F < 31:
            pages += 1
    return pages


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
        pages = 0
        for line in self._maps.read_bytes().splitlines():
            fields = line.split()
            start, end = (int(addr, 16) for addr in fields[0].split(b"-"))
            # [vsyscall] lies above the address range pagemap covers
            if fields[-1] == b"[vsyscall]" or (skip and skip(start, end)):
                continue
            offset = start // PAGE_SIZE * 8
            entries = os.pread(self._pagemap, (end - start) // PAGE_SIZE * 8, offset)
            pages += _resident_pages(entries, start, end)
        return pages * PAGE_SIZE
