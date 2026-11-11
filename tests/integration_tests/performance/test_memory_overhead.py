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

import pytest

from framework.artifacts import ACPI_GUEST_KERNELS, pin_guest_kernel
from framework.benchmarks import emit_memory_overhead_metrics
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend


@pytest.mark.parametrize(
    "vcpu_count,mem_size_mib",
    [(1, 1024), (2, 2048), (4, 4096), (32, 4096)],
)
@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pin_vm_backend(VM_BACKEND_KVM)
@pytest.mark.nonci
def test_memory_overhead(
    microvm_factory,
    guest_kernel,
    rootfs,
    vcpu_count,
    mem_size_mib,
    pci_enabled,
    metrics,
):
    """Track Firecracker memory overhead.

    We take a single measurement as it only varies by a few KiB each run.
    """

    for _ in range(5):
        microvm = microvm_factory.build(
            guest_kernel, rootfs, pci=pci_enabled, monitor_memory=False
        )
        microvm.spawn(emit_metrics=True)
        microvm.basic_config(vcpu_count=vcpu_count, mem_size_mib=mem_size_mib)
        microvm.add_net_iface()
        microvm.start()
        metrics.set_dimensions(
            {"performance_test": "test_memory_overhead", **microvm.dimensions}
        )

        snapshot = microvm.snapshot_full()
        microvm.kill()
        microvm2 = microvm_factory.build_from_snapshot(snapshot)

        emit_memory_overhead_metrics(microvm2.firecracker_pid, mem_size_mib, metrics)
