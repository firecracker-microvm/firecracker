# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Track Firecracker memory overhead

Because Firecracker is a static binary, and is copied before execution, no
memory is shared across many different processes. It is thus important to track
how much memory overhead Firecracker adds.

These tests output metrics to capture the memory overhead that Firecracker adds,
both from the binary file (file-backed) and what Firecracker allocates during
the process lifetime.

The memory overhead of the jailer is not important as it is short-lived.
"""

from collections import defaultdict
from pathlib import Path

import psutil
import pytest

from framework.properties import global_props

# If guest memory is >3328MB, it is split in a 2nd region
X86_MEMORY_GAP_START = 3328 * 2**20


@pytest.mark.parametrize(
    "vcpu_count,mem_size_mib",
    [(1, 128), (1, 1024), (2, 2024), (4, 4096)],
)
def test_memory_overhead(
    microvm_factory, guest_kernel, rootfs, vcpu_count, mem_size_mib, metrics
):
    """Track Firecracker memory overhead.

    We take a single measurement as it only varies by a few KiB each run.
    """

    microvm = microvm_factory.build(guest_kernel, rootfs)
    microvm.spawn()
    microvm.basic_config(vcpu_count=vcpu_count, mem_size_mib=mem_size_mib)
    microvm.add_net_iface()
    microvm.start()

    # check that the vm is running
    microvm.ssh.run("true")

    guest_mem_bytes = mem_size_mib * 2**20
    guest_mem_splits = {
        guest_mem_bytes,
        X86_MEMORY_GAP_START,
    }
    if guest_mem_bytes > X86_MEMORY_GAP_START:
        guest_mem_splits.add(guest_mem_bytes - X86_MEMORY_GAP_START)

    mem_stats = defaultdict(int)
    mem_stats["guest_memory"] = guest_mem_bytes
    ps = psutil.Process(microvm.jailer_clone_pid)

    for pmmap in ps.memory_maps(grouped=False):
        # We publish 'size' and 'rss' (resident). size would be the worst case,
        # whereas rss is the current paged-in memory.

        mem_stats["total_size"] += pmmap.size
        mem_stats["total_rss"] += pmmap.rss
        pmmap_path = Path(pmmap.path)
        if pmmap_path.exists() and pmmap_path.name.startswith("firecracker"):
            mem_stats["binary_size"] += pmmap.size
            mem_stats["binary_rss"] += pmmap.rss

        if pmmap.size not in guest_mem_splits:
            mem_stats["overhead_size"] += pmmap.size
            mem_stats["overhead_rss"] += pmmap.rss

    dimensions = {
        # "instance": global_props.instance,
        # "cpu_model": global_props.cpu_model,
        "architecture": global_props.cpu_architecture,
        "host_kernel": "linux-" + global_props.host_linux_version,
        "guest_kernel": guest_kernel.name,
        "rootfs": rootfs.name,
    }
    metrics.set_dimensions(dimensions)
    for key, value in mem_stats.items():
        metrics.put_metric(key, value, unit="Bytes")

    mem_info = ps.memory_full_info()
    for metric in ["uss", "text"]:
        val = getattr(mem_info, metric)
        metrics.put_metric(metric, val, unit="Bytes")
