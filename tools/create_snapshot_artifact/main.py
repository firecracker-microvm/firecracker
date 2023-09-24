#!/usr/bin/env python3
# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Script used to generate snapshots of microVMs."""

import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

# Hack to be able to import testing framework functions.
sys.path.append(os.path.join(os.getcwd(), "tests"))  # noqa: E402

# pylint: disable=wrong-import-position
from framework.artifacts import disks, kernels
from framework.defs import DEFAULT_TEST_SESSION_ROOT_PATH
from framework.microvm import MicroVMFactory
from framework.utils import (
    generate_mmds_get_request,
    generate_mmds_session_token,
    run_cmd,
)
from framework.utils_cpuid import CpuVendor, get_cpu_vendor
from host_tools.cargo_build import get_firecracker_binaries

# pylint: enable=wrong-import-position

# Default IPv4 address to route MMDS requests.
IPV4_ADDRESS = "169.254.169.254"
NET_IFACE_FOR_MMDS = "eth3"
# Path to the VM configuration file.
VM_CONFIG_FILE = "tools/create_snapshot_artifact/complex_vm_config.json"
# Root directory for the snapshot artifacts.
SNAPSHOT_ARTIFACTS_ROOT_DIR = "snapshot_artifacts"


def populate_mmds(microvm, data_store):
    """Populate MMDS contents with json data provided."""
    # MMDS should be empty.
    response = microvm.api.mmds.get()
    assert response.json() == {}

    # Populate MMDS with data.
    microvm.api.mmds.put(**data_store)

    # Ensure data is persistent inside the data store.
    response = microvm.api.mmds.get()
    assert response.json() == data_store


def validate_mmds(ssh_connection, data_store):
    """Validate that MMDS contents fetched from the guest."""
    # Configure interface to route MMDS requests
    cmd = "ip route add {} dev {}".format(IPV4_ADDRESS, NET_IFACE_FOR_MMDS)
    _, stdout, stderr = ssh_connection.run(cmd)
    assert stdout == stderr == ""

    # Fetch metadata to ensure MMDS is accessible.
    token = generate_mmds_session_token(ssh_connection, IPV4_ADDRESS, token_ttl=60)

    cmd = generate_mmds_get_request(IPV4_ADDRESS, token=token)
    _, stdout, _ = ssh_connection.run(cmd)
    assert json.loads(stdout) == data_store


def main():
    """
    Run the main logic.

    Create snapshot artifacts from complex microVMs with all Firecracker's
    functionality enabled. The kernels are parametrized to include all guest
    supported versions.

    Artifacts are saved in the following format:
    snapshot_artifacts
        |
        -> <guest_kernel_supported_0>_<cpu_template>_guest_snapshot
            |
            -> vm.mem
            -> vm.vmstate
            -> ubuntu-18.04.id_rsa
            -> ubuntu-18.04.ext4
        -> <guest_kernel_supported_1>_<cpu_template>_guest_snapshot
            |
            ...
    """
    # Create directory dedicated to store snapshot artifacts for
    # each guest kernel version.
    print("Cleanup")
    shutil.rmtree(SNAPSHOT_ARTIFACTS_ROOT_DIR, ignore_errors=True)
    root_path = tempfile.mkdtemp(dir=DEFAULT_TEST_SESSION_ROOT_PATH)
    vm_factory = MicroVMFactory(root_path, None, *get_firecracker_binaries())

    cpu_templates = ["None"]
    if get_cpu_vendor() == CpuVendor.INTEL:
        cpu_templates.extend(["C3", "T2", "T2S"])

    for cpu_template in cpu_templates:
        for kernel in kernels(glob="vmlinux-*"):
            for rootfs in disks(glob="ubuntu-*.squashfs"):
                print(kernel, rootfs, cpu_template)
                vm = vm_factory.build()
                create_snapshots(vm, rootfs, kernel, cpu_template)


def create_snapshots(vm, rootfs, kernel, cpu_template):
    """Snapshot microVM built from vm configuration file."""
    # Get ssh key from read-only artifact.
    vm.ssh_key = rootfs.with_suffix(".id_rsa")
    vm.rootfs_file = rootfs
    vm.kernel_file = kernel

    # adapt the JSON file
    vm_config_file = Path(VM_CONFIG_FILE)
    obj = json.load(vm_config_file.open(encoding="UTF-8"))
    obj["boot-source"]["kernel_image_path"] = kernel.name
    obj["drives"][0]["path_on_host"] = rootfs.name
    obj["drives"][0]["is_read_only"] = True
    obj["machine-config"]["cpu_template"] = cpu_template
    vm.create_jailed_resource(vm_config_file)
    vm_config = Path(vm.chroot()) / vm_config_file.name
    vm_config.write_text(json.dumps(obj))
    vm.jailer.extra_args = {"config-file": vm_config_file.name}

    # since we are using a JSON file, we need to do this manually
    vm.create_jailed_resource(rootfs)
    vm.create_jailed_resource(kernel)

    # Create network namespace.
    run_cmd(f"ip netns add {vm.jailer.netns}")
    for i in range(4):
        vm.add_net_iface(api=False)

    vm.spawn(log_level="Info")

    # Ensure the microVM has started.
    assert vm.state == "Running"

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
    populate_mmds(vm, data_store)

    # Iterate and validate connectivity on all ifaces after boot.
    for i in range(4):
        exit_code, _, _ = vm.ssh_iface(i).run("sync")
        assert exit_code == 0

    # Validate MMDS.
    validate_mmds(vm.ssh, data_store)

    # Snapshot the microVM.
    snapshot = vm.snapshot_diff()

    # Create snapshot artifacts directory specific for the kernel version used.
    guest_kernel_version = re.search("vmlinux-(.*)", kernel.name)

    snapshot_artifacts_dir = (
        Path(SNAPSHOT_ARTIFACTS_ROOT_DIR)
        / f"{guest_kernel_version.group(1)}_{cpu_template}_guest_snapshot"
    )
    snapshot_artifacts_dir.mkdir(parents=True)
    snapshot.save_to(snapshot_artifacts_dir)
    print(f"Copied snapshot to: {snapshot_artifacts_dir}.")

    vm.kill()


if __name__ == "__main__":
    main()
