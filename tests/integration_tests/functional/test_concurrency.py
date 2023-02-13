# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Ensure multiple microVMs work correctly when spawned simultaneously."""

NO_OF_MICROVMS = 20


def test_run_concurrency(microvm_factory, network_config, guest_kernel, rootfs):
    """
    Check we can spawn multiple microvms.

    @type: functional
    """

    for i in range(NO_OF_MICROVMS):
        microvm = microvm_factory.build(guest_kernel, rootfs)
        microvm.spawn()
        microvm.basic_config(vcpu_count=1, mem_size_mib=128)
        microvm.ssh_network_config(network_config, str(i))
        microvm.start()

        # We check that the vm is running by testing that the ssh does
        # not time out.
        microvm.ssh.run("true")
