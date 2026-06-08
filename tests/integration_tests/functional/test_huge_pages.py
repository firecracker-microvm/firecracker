# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that transparent huge pages are used (or not) based on configuration."""

import pytest

from framework import utils
from framework.microvm import HugePagesConfig


def get_anon_huge_pages_kb(pid: int) -> int:
    """Get total AnonHugePages in kB for a process from /proc/<pid>/smaps."""
    cmd = f"awk '/AnonHugePages/{{sum += $2}} END{{print sum}}' /proc/{pid}/smaps"
    _, stdout, _ = utils.check_output(cmd)
    return int(stdout.strip())


@pytest.mark.parametrize(
    "huge_pages", [HugePagesConfig.NONE, HugePagesConfig.TRANSPARENT]
)
def test_transparent_huge_pages_allocation(uvm, huge_pages):
    """
    Test that allocating memory in the guest causes transparent huge pages
    to appear on the host when configured, and not when disabled.
    """
    vm = uvm
    vm.spawn()
    vm.basic_config(vcpu_count=2, mem_size_mib=256, huge_pages=huge_pages)
    vm.add_net_iface()
    vm.start()

    # Allocate and touch anonymous memory inside the guest to trigger host-side
    # page faults on the guest memory region (which is what THP backs).
    vm.ssh.check_output("python3 -c 'x = bytearray(128 * 1024 * 1024)'")

    anon_huge_kb = get_anon_huge_pages_kb(vm.firecracker_pid)

    if huge_pages == HugePagesConfig.TRANSPARENT:
        # With THP enabled, the kernel should have promoted some pages (let's say 64 MiB out of 128MiB)
        assert (
            anon_huge_kb > 64 * 1024
        ), f"Expected AnonHugePages > 0 with Transparent huge pages, got {anon_huge_kb} kB"
    else:
        # With huge pages disabled, no anonymous huge pages should be present
        assert (
            anon_huge_kb == 0
        ), f"Expected AnonHugePages == 0 with huge pages None, got {anon_huge_kb} kB"
