# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Ensure multiple microVMs work correctly when spawned simultaneously."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from framework.enclave import MIN_ENCLAVE_MEM_SIZE_MIB

NO_OF_MICROVMS = 20


# The test is itself the load: 20 VMs at once, not 20 per xdist worker.
@pytest.mark.serial
def test_run_concurrency(
    microvm_factory, guest_kernel, rootfs, pci_enabled, vm_backend
):
    """
    Check we can spawn multiple microvms.
    """
    mem_size_mib = MIN_ENCLAVE_MEM_SIZE_MIB if vm_backend.is_enclave else 128

    def launch1():
        microvm = microvm_factory.build_booted(
            guest_kernel,
            rootfs,
            pci=pci_enabled,
            vcpu_count=1,
            mem_size_mib=mem_size_mib,
        )
        microvm.time_api_requests = False  # is flaky because of parallelism

    with ThreadPoolExecutor(max_workers=NO_OF_MICROVMS) as tpe:
        futures = [tpe.submit(launch1) for _ in range(NO_OF_MICROVMS)]
        for future in futures:
            future.result()
