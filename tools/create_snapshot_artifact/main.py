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
from functools import partial

# Hack to be able to import testing framework functions.
sys.path.append(os.path.join(os.getcwd(), "tests"))  # noqa: E402

# pylint: disable=wrong-import-position
# The test infra assumes it is running from the `tests` directory.
os.chdir("tests")
from conftest import ARTIFACTS_COLLECTION as ARTIFACTS
from framework.artifacts import create_net_devices_configuration
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.defs import DEFAULT_TEST_SESSION_ROOT_PATH
from framework.microvm import Microvm
from framework.utils import (
    generate_mmds_get_request,
    generate_mmds_session_token,
    run_cmd,
)
from framework.utils_cpuid import CpuVendor, get_cpu_vendor
from host_tools.cargo_build import gcc_compile
from integration_tests.functional.test_cmd_line_start import _configure_vm_from_json

# restore directory
os.chdir("..")

DEST_KERNEL_NAME = "vmlinux.bin"
ROOTFS_KEY = "ubuntu-18.04"

# Define 4 net device configurations.
net_ifaces = create_net_devices_configuration(4)

# Allow routing requests to MMDS through eth3.
net_iface_for_mmds = net_ifaces[3]
# Default IPv4 address to route MMDS requests.
IPV4_ADDRESS = "169.254.169.254"
# Path to the VM configuration file.
VM_CONFIG_FILE = "tools/create_snapshot_artifact/complex_vm_config.json"
# Root directory for the snapshot artifacts.
SNAPSHOT_ARTIFACTS_ROOT_DIR = "snapshot_artifacts"


def compile_file(file_name, dest_path, bin_name):
    """
    Compile source file using gcc.

    The resulted executable is placed at `/dest_path/bin_name`.
    """
    host_tools_path = os.path.join(os.getcwd(), "tests/host_tools")

    source_file_path = os.path.join(host_tools_path, file_name)
    bin_file_path = os.path.join(dest_path, bin_name)
    gcc_compile(source_file_path, bin_file_path)
    return bin_file_path


def populate_mmds(microvm, data_store):
    """Populate MMDS contents with json data provided."""
    # MMDS should be empty.
    response = microvm.mmds.get()
    assert microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == {}

    # Populate MMDS with data.
    response = microvm.mmds.put(json=data_store)
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Ensure data is persistent inside the data store.
    response = microvm.mmds.get()
    assert microvm.api_session.is_status_ok(response.status_code)
    assert response.json() == data_store


def setup_vm(root_path, bin_cloner_path, kernel, disk):
    """Init microVM using context provided."""
    print(
        f"Creating snapshot of microVM with kernel {kernel.name()}"
        f" and disk {disk.name()}."
    )
    vm = Microvm(
        resource_path=root_path,
        bin_cloner_path=bin_cloner_path,
    )

    # Change kernel name to match the one in the config file.
    kernel_full_path = os.path.join(vm.path, DEST_KERNEL_NAME)
    shutil.copyfile(kernel.local_path(), kernel_full_path)
    vm.kernel_file = kernel_full_path

    rootfs_full_path = os.path.join(vm.path, disk.name())
    shutil.copyfile(disk.local_path(), rootfs_full_path)
    vm.rootfs_file = rootfs_full_path

    return vm


def configure_network_interfaces(microvm):
    """Create network namespace and tap device for network interfaces."""
    # Create network namespace.
    run_cmd(f"ip netns add {microvm.jailer.netns}")

    for net_iface in net_ifaces:
        _tap = microvm.create_tap_and_ssh_config(
            net_iface.host_ip, net_iface.guest_ip, net_iface.netmask, net_iface.tap_name
        )


def validate_mmds(ssh_connection, data_store):
    """Validate that MMDS contents fetched from the guest."""
    # Configure interface to route MMDS requests
    cmd = "ip route add {} dev {}".format(IPV4_ADDRESS, net_iface_for_mmds.dev_name)
    _, stdout, stderr = ssh_connection.execute_command(cmd)
    assert stdout.read() == stderr.read() == ""

    # Fetch metadata to ensure MMDS is accessible.
    token = generate_mmds_session_token(ssh_connection, IPV4_ADDRESS, token_ttl=60)

    cmd = generate_mmds_get_request(IPV4_ADDRESS, token=token)
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == data_store


def copy_snapshot_artifacts(snapshot, rootfs, kernel, ssh_key, template):
    """Copy snapshot artifacts to dedicated snapshot directory."""
    # Create snapshot artifacts directory specific for the kernel version used.
    guest_kernel_version = re.search("vmlinux-(.*).bin", os.path.basename(kernel))
    snapshot_artifacts_dir = os.path.join(
        SNAPSHOT_ARTIFACTS_ROOT_DIR,
        f"{guest_kernel_version.group(1)}_{template}_guest_snapshot",
    )
    os.mkdir(snapshot_artifacts_dir)

    # Copy snapshot artifacts.
    # Memory file.
    mem_file_path = os.path.join(snapshot_artifacts_dir, "vm.mem")
    shutil.copyfile(snapshot.mem, mem_file_path)
    # MicroVM state file.
    vmstate_file_path = os.path.join(snapshot_artifacts_dir, "vm.vmstate")
    shutil.copyfile(snapshot.vmstate, vmstate_file_path)
    # Ssh key file.
    ssh_key_file_path = os.path.join(snapshot_artifacts_dir, f"{ROOTFS_KEY}.id_rsa")
    shutil.copyfile(ssh_key.local_path(), ssh_key_file_path)
    # Rootfs file.
    disk_file_path = os.path.join(snapshot_artifacts_dir, f"{ROOTFS_KEY}.ext4")
    shutil.copyfile(rootfs, disk_file_path)

    print(
        "Copied snapshot memory file, vmstate file, disk and "
        "ssh key to: {}.".format(snapshot_artifacts_dir)
    )


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
    os.mkdir(SNAPSHOT_ARTIFACTS_ROOT_DIR)

    root_path = tempfile.mkdtemp(
        prefix=MicrovmBuilder.ROOT_PREFIX, dir=f"{DEFAULT_TEST_SESSION_ROOT_PATH}"
    )

    # Compile new-pid cloner helper.
    bin_cloner_path = compile_file(
        file_name="newpid_cloner.c", bin_name="newpid_cloner", dest_path=root_path
    )

    # Fetch kernel and rootfs artifacts from S3 bucket.
    kernels = ARTIFACTS.kernels()
    disks = ARTIFACTS.disks(keyword="ubuntu")

    cpu_templates = ["None"]
    if get_cpu_vendor() == CpuVendor.INTEL:
        cpu_templates.extend(["C3", "T2", "T2S"])

    for cpu_template in cpu_templates:
        for kernel in kernels:
            kernel.download()
            for rootfs in disks:
                rootfs.download()
                print(kernel, rootfs, cpu_template)
                vm = setup_vm(root_path, bin_cloner_path, kernel, rootfs)
                create_snapshots(vm, rootfs, kernel, cpu_template)


def add_cpu_template(template, json_data):
    """Modify the microvm config JSON to add a cpu_template."""
    json_data["machine-config"]["cpu_template"] = template
    return json_data


def create_snapshots(vm, rootfs, kernel, cpu_template):
    """Snapshot microVM built from vm configuration file."""
    # Get ssh key from read-only artifact.
    ssh_key = rootfs.ssh_key()
    ssh_key.download(vm.path)
    vm.ssh_config["ssh_key_path"] = ssh_key.local_path()
    os.chmod(vm.ssh_config["ssh_key_path"], 0o400)

    fn = partial(add_cpu_template, cpu_template)
    _configure_vm_from_json(vm, VM_CONFIG_FILE, json_xform=fn)
    configure_network_interfaces(vm)
    vm.spawn()

    # Ensure the microVM has started.
    response = vm.machine_cfg.get()
    assert vm.api_session.is_status_ok(response.status_code)
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
    for iface in net_ifaces:
        vm.ssh_config["hostname"] = iface.guest_ip
        exit_code, _, _ = vm.ssh.execute_command("sync")
        assert exit_code == 0

    # Validate MMDS.
    validate_mmds(vm.ssh, data_store)

    # Create a snapshot builder from a microVM.
    snapshot_builder = SnapshotBuilder(vm)

    # Snapshot the microVM.
    snapshot = snapshot_builder.create(
        [vm.rootfs_file], ssh_key, SnapshotType.DIFF, net_ifaces=net_ifaces
    )

    copy_snapshot_artifacts(
        snapshot, vm.rootfs_file, kernel.name(), ssh_key, cpu_template
    )

    vm.kill()


if __name__ == "__main__":
    main()
