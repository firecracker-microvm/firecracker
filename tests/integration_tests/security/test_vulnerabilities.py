# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# N.B.: Although this repository is released under the Apache-2.0, part of its test requires a
# script from the third party "Spectre & Meltdown Checker" project. This script is under the
# GPL-3.0-only license.
"""Tests vulnerabilities mitigations."""

from pathlib import Path

import pytest
import requests

from framework import utils
from framework.artifacts import DEFAULT_NETMASK
from framework.properties import global_props
from framework.utils_cpu_templates import nonci_on_arm

CHECKER_URL = "https://meltdown.ovh"
CHECKER_FILENAME = "spectre-meltdown-checker.sh"


@pytest.fixture(scope="session", name="spectre_meltdown_checker")
def download_spectre_meltdown_checker(tmp_path_factory):
    """Download spectre / meltdown checker script."""
    resp = requests.get(CHECKER_URL, timeout=5)
    resp.raise_for_status()

    path = tmp_path_factory.mktemp("tmp", True) / CHECKER_FILENAME
    path.write_bytes(resp.content)

    return path


def run_microvm(microvm, network_config, cpu_template=None, custom_cpu_template=None):
    """
    Run a microVM with a template (static or custom).
    """
    microvm.spawn()
    microvm.basic_config(cpu_template=cpu_template)
    if custom_cpu_template:
        microvm.cpu_config(custom_cpu_template)

    tap, host_ip, guest_ip = microvm.ssh_network_config(network_config, "1")
    microvm.start()

    return microvm, tap, host_ip, guest_ip


def take_snapshot_and_restore(microvm_factory, src_vm, tap, host_ip, guest_ip):
    """
    Take a snapshot from the source microVM, restore a destination microVM from the snapshot
    and return the destination VM.
    """

    # Take a snapshot of the source VM
    mem_file_path = Path(src_vm.jailer.chroot_path()) / "mem.bin"
    snapshot_path = Path(src_vm.jailer.chroot_path()) / "snapshot.bin"

    src_vm.pause_to_snapshot(
        mem_file_path=mem_file_path.name,
        snapshot_path=snapshot_path.name,
    )
    assert mem_file_path.exists()

    # Create a destination VM
    dst_vm = microvm_factory.build()
    dst_vm.spawn()
    dst_vm.create_tap_and_ssh_config(
        host_ip=host_ip,
        guest_ip=guest_ip,
        netmask_len=DEFAULT_NETMASK,
        tapname=tap.name,
    )
    dst_vm.ssh_config["ssh_key_path"] = src_vm.ssh_config["ssh_key_path"]

    # Restore the destination VM from the snapshot
    dst_vm.restore_from_snapshot(
        snapshot_vmstate=snapshot_path,
        snapshot_mem=mem_file_path,
        snapshot_disks=[src_vm.rootfs_file],
    )

    return dst_vm


def run_spectre_meltdown_checker_on_guest(
    microvm,
    spectre_meltdown_checker,
):
    """Run the spectre / meltdown checker on guest"""
    remote_path = f"/bin/{CHECKER_FILENAME}"
    microvm.ssh.scp_file(spectre_meltdown_checker, remote_path)
    ecode, stdout, stderr = microvm.ssh.execute_command(f"sh {remote_path} --explain")
    assert ecode == 0, f"stdout:\n{stdout.read()}\nstderr:\n{stderr.read()}\n"


@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
def test_spectre_meltdown_checker_on_host(spectre_meltdown_checker):
    """
    Test with the spectre / meltdown checker on host.
    """
    utils.run_cmd(f"sh {spectre_meltdown_checker} --explain")


@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
def test_spectre_meltdown_checker_on_guest(
    spectre_meltdown_checker,
    test_microvm_with_spectre_meltdown,
    network_config,
):
    """
    Test with the spectre / meltdown checker on guest.
    """
    microvm, _, _, _ = run_microvm(test_microvm_with_spectre_meltdown, network_config)

    run_spectre_meltdown_checker_on_guest(
        microvm,
        spectre_meltdown_checker,
    )


@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
def test_spectre_meltdown_checker_on_restored_guest(
    spectre_meltdown_checker,
    test_microvm_with_spectre_meltdown,
    network_config,
    microvm_factory,
):
    """
    Test with the spectre / meltdown checker on a restored guest.
    """
    src_vm, tap, host_ip, guest_ip = run_microvm(
        test_microvm_with_spectre_meltdown, network_config
    )

    dst_vm = take_snapshot_and_restore(microvm_factory, src_vm, tap, host_ip, guest_ip)

    run_spectre_meltdown_checker_on_guest(
        dst_vm,
        spectre_meltdown_checker,
    )


@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
@nonci_on_arm
def test_spectre_meltdown_checker_on_guest_with_template(
    spectre_meltdown_checker,
    test_microvm_with_spectre_meltdown,
    network_config,
    cpu_template,
):
    """
    Test with the spectre / meltdown checker on guest with CPU template.
    """
    microvm, _, _, _ = run_microvm(
        test_microvm_with_spectre_meltdown, network_config, cpu_template
    )

    run_spectre_meltdown_checker_on_guest(
        microvm,
        spectre_meltdown_checker,
    )


@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
@nonci_on_arm
def test_spectre_meltdown_checker_on_guest_with_custom_template(
    spectre_meltdown_checker,
    test_microvm_with_spectre_meltdown,
    network_config,
    custom_cpu_template,
):
    """
    Test with the spectre / meltdown checker on guest with a custom CPU template.
    """
    microvm, _, _, _ = run_microvm(
        test_microvm_with_spectre_meltdown,
        network_config,
        custom_cpu_template=custom_cpu_template["template"],
    )

    run_spectre_meltdown_checker_on_guest(
        microvm,
        spectre_meltdown_checker,
    )


@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
@nonci_on_arm
def test_spectre_meltdown_checker_on_restored_guest_with_template(
    spectre_meltdown_checker,
    test_microvm_with_spectre_meltdown,
    network_config,
    cpu_template,
    microvm_factory,
):
    """
    Test with the spectre / meltdown checker on a restored guest with a CPU template.
    """
    src_vm, tap, host_ip, guest_ip = run_microvm(
        test_microvm_with_spectre_meltdown, network_config, cpu_template
    )

    dst_vm = take_snapshot_and_restore(microvm_factory, src_vm, tap, host_ip, guest_ip)

    run_spectre_meltdown_checker_on_guest(
        dst_vm,
        spectre_meltdown_checker,
    )


@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
@nonci_on_arm
def test_spectre_meltdown_checker_on_restored_guest_with_custom_template(
    spectre_meltdown_checker,
    test_microvm_with_spectre_meltdown,
    network_config,
    custom_cpu_template,
    microvm_factory,
):
    """
    Test with the spectre / meltdown checker on a restored guest with a custom CPU template.
    """
    src_vm, tap, host_ip, guest_ip = run_microvm(
        test_microvm_with_spectre_meltdown,
        network_config,
        custom_cpu_template=custom_cpu_template["template"],
    )

    dst_vm = take_snapshot_and_restore(microvm_factory, src_vm, tap, host_ip, guest_ip)

    run_spectre_meltdown_checker_on_guest(
        dst_vm,
        spectre_meltdown_checker,
    )


def check_vulnerabilities_files_on_guest(microvm):
    """
    Check that the guest's vulnerabilities files do not contain `Vulnerable`.
    See also: https://elixir.bootlin.com/linux/latest/source/Documentation/ABI/testing/sysfs-devices-system-cpu
    and search for `vulnerabilities`.
    """
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"
    ecode, stdout, stderr = microvm.ssh.execute_command(
        f"grep -r Vulnerable {vuln_dir}"
    )
    assert ecode == 1, f"stdout:\n{stdout.read()}\nstderr:\n{stderr.read()}\n"


def test_vulnerabilities_files_on_guest(
    test_microvm_with_api,
    network_config,
):
    """
    Test vulnerabilities files on guest.
    """
    microvm, _, _, _ = run_microvm(test_microvm_with_api, network_config)

    check_vulnerabilities_files_on_guest(microvm)


def test_vulnerabilities_files_on_restored_guest(
    test_microvm_with_api,
    network_config,
    microvm_factory,
):
    """
    Test vulnerabilities files on a restored guest.
    """
    src_vm, tap, host_ip, guest_ip = run_microvm(test_microvm_with_api, network_config)

    dst_vm = take_snapshot_and_restore(microvm_factory, src_vm, tap, host_ip, guest_ip)

    check_vulnerabilities_files_on_guest(dst_vm)


@nonci_on_arm
def test_vulnerabilities_files_on_guest_with_template(
    test_microvm_with_api,
    network_config,
    cpu_template,
):
    """
    Test vulnerabilities files on guest with CPU template.
    """
    microvm, _, _, _ = run_microvm(test_microvm_with_api, network_config, cpu_template)

    check_vulnerabilities_files_on_guest(microvm)


@nonci_on_arm
def test_vulnerabilities_files_on_guest_with_custom_template(
    test_microvm_with_api,
    network_config,
    custom_cpu_template,
):
    """
    Test vulnerabilities files on guest with a custom CPU template.
    """
    microvm, _, _, _ = run_microvm(
        test_microvm_with_api,
        network_config,
        custom_cpu_template=custom_cpu_template["template"],
    )

    check_vulnerabilities_files_on_guest(microvm)


@nonci_on_arm
def test_vulnerabilities_files_on_restored_guest_with_template(
    test_microvm_with_api,
    network_config,
    cpu_template,
    microvm_factory,
):
    """
    Test vulnerabilities files on a restored guest with a CPU template.
    """
    src_vm, tap, host_ip, guest_ip = run_microvm(
        test_microvm_with_api, network_config, cpu_template
    )

    dst_vm = take_snapshot_and_restore(microvm_factory, src_vm, tap, host_ip, guest_ip)

    check_vulnerabilities_files_on_guest(dst_vm)


@nonci_on_arm
def test_vulnerabilities_files_on_restored_guest_with_custom_template(
    test_microvm_with_api,
    network_config,
    custom_cpu_template,
    microvm_factory,
):
    """
    Test vulnerabilities files on a restored guest with a custom CPU template.
    """
    src_vm, tap, host_ip, guest_ip = run_microvm(
        test_microvm_with_api,
        network_config,
        custom_cpu_template=custom_cpu_template["template"],
    )

    dst_vm = take_snapshot_and_restore(microvm_factory, src_vm, tap, host_ip, guest_ip)

    check_vulnerabilities_files_on_guest(dst_vm)
