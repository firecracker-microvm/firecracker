# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Creates snapshots for other tests like test_snapshot_restore_cross_kernel.py
"""

import json
import platform
import re

import pytest

from framework.utils import (
    configure_mmds,
    generate_mmds_get_request,
    generate_mmds_session_token,
)
from framework.utils_cpu_templates import get_cpu_template_name

if platform.machine() != "x86_64":
    pytestmark = pytest.mark.skip("only x86_64 architecture supported")

# Default IPv4 address to route MMDS requests.
IPV4_ADDRESS = "169.254.169.254"
NET_IFACE_FOR_MMDS = "eth3"


@pytest.mark.nonci
def test_snapshot_phase1(
    microvm_factory, guest_kernel, rootfs, cpu_template_any, results_dir
):
    """Create a snapshot and save it to disk"""

    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.add_net_iface()

    static_cpu_template = None
    if isinstance(cpu_template_any, str):
        static_cpu_template = cpu_template_any
    elif isinstance(cpu_template_any, dict):
        vm.api.cpu_config.put(**cpu_template_any["template"])
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=512,
        cpu_template=static_cpu_template,
    )

    guest_kernel_version = re.search("vmlinux-(.*)", vm.kernel_file.name)
    cpu_template_name = get_cpu_template_name(cpu_template_any, with_type=True)
    snapshot_artifacts_dir = (
        results_dir
        / f"{guest_kernel_version.group(1)}_{cpu_template_name}_guest_snapshot"
    )

    # Add 4 network devices
    for i in range(4):
        vm.add_net_iface()
    # Add a vsock device
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/v.sock")
    # Add MMDS
    configure_mmds(vm, ["eth3"], version="V2")
    # Add a memory balloon.
    vm.api.balloon.put(amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1)

    vm.start()

    # Populate MMDS.
    data_store = {
        "latest": {
            "meta-data": {
                "ami-id": "ami-12345678",
                "reservation-id": "r-fea54097",
                "local-hostname": "ip-10-251-50-12.ec2.internal",
                "public-hostname": "ec2-203-0-113-25.compute-1.amazonaws.com",
            }
        }
    }

    # MMDS should be empty.
    assert vm.api.mmds.get().json() == {}
    # Populate MMDS with data.
    vm.api.mmds.put(**data_store)
    # Ensure data is persistent inside the data store.
    assert vm.api.mmds.get().json() == data_store

    # Iterate and validate connectivity on all ifaces after boot.
    for i in range(4):
        exit_code, _, _ = vm.ssh_iface(i).run("sync")
        assert exit_code == 0

    # Validate MMDS.
    # Configure interface to route MMDS requests
    vm.ssh.check_output(f"ip route add {IPV4_ADDRESS} dev {NET_IFACE_FOR_MMDS}")

    # Fetch metadata to ensure MMDS is accessible.
    token = generate_mmds_session_token(vm.ssh, IPV4_ADDRESS, token_ttl=60)
    cmd = generate_mmds_get_request(IPV4_ADDRESS, token=token)
    _, stdout, _ = vm.ssh.run(cmd)
    assert json.loads(stdout) == data_store

    # Copy snapshot files to be published to S3 for the 2nd part of the test
    # Create snapshot artifacts directory specific for the kernel version used.
    snapshot = vm.snapshot_full()
    snapshot_artifacts_dir.mkdir(parents=True)
    snapshot.save_to(snapshot_artifacts_dir)
