# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Ensure multiple microVMs work correctly when spawned simultaneously."""

from concurrent.futures import ThreadPoolExecutor

NO_OF_MICROVMS = 20


def test_run_concurrency(microvm_factory, guest_kernel, rootfs):
    """
    Check we can spawn multiple microvms.
    """

    def launch1():
        microvm = microvm_factory.build(guest_kernel, rootfs)
        microvm.time_api_requests = False  # is flaky because of parallelism
        microvm.spawn()
        microvm.basic_config(vcpu_count=1, mem_size_mib=128)
        microvm.add_net_iface()
        microvm.start()
        microvm.wait_for_up()

    with ThreadPoolExecutor(max_workers=NO_OF_MICROVMS) as tpe:
        for _ in range(NO_OF_MICROVMS):
            tpe.submit(launch1)
