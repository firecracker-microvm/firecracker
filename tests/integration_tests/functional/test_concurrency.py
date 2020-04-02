# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Ensure multiple microVMs work correctly when spawned simultaneously."""

from framework import decorators

import host_tools.network as net_tools

NO_OF_MICROVMS = 20


@decorators.test_context('ssh', NO_OF_MICROVMS)
def test_run_concurrency(test_multiple_microvms, network_config):
    """Check we can spawn multiple microvms."""
    microvms = test_multiple_microvms

    for i in range(NO_OF_MICROVMS):
        microvm = microvms[i]
        _ = _configure_and_run(microvm, {
            "config": network_config, "iface_id": str(i)
        })
        # We check that the vm is running by testing that the ssh does
        # not time out.
        _ = net_tools.SSHConnection(microvm.ssh_config)


def _configure_and_run(microvm, network_info):
    """Auxiliary function for configuring and running microVM."""
    microvm.spawn()

    # Machine configuration specified in the SLA.
    config = {
        'vcpu_count': 1,
        'mem_size_mib': 128
    }

    microvm.basic_config(**config)

    _tap, _, _ = microvm.ssh_network_config(
        network_info["config"],
        network_info["iface_id"]
    )

    microvm.start()
    return _tap
