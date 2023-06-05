# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# N.B.: Although this repository is released under the Apache-2.0, part of its test requires a
# script from the third party "Spectre & Meltdown Checker" project. This script is under the
# GPL-3.0-only license.
"""Tests vulnerabilities mitigations."""

import pytest
import requests

from framework import utils
from framework.properties import global_props
from framework.utils_cpu_templates import skip_on_arm

CHECKER_URL = "https://meltdown.ovh"
CHECKER_FILENAME = "spectre-meltdown-checker.sh"


@pytest.fixture(name="microvm")
def microvm_fxt(uvm_plain):
    """Microvm fixture"""
    uvm_plain.spawn()
    uvm_plain.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
    )
    uvm_plain.add_net_iface()
    uvm_plain.start()
    return uvm_plain


@pytest.fixture(name="microvm_with_template")
def microvm_with_template_fxt(uvm_plain, cpu_template):
    """Microvm fixture with a CPU template"""
    uvm_plain.spawn()
    uvm_plain.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
        cpu_template=cpu_template,
    )
    uvm_plain.add_net_iface()
    uvm_plain.start()
    return uvm_plain


@pytest.fixture(name="microvm_with_custom_cpu_template")
def microvm_with_custom_template_fxt(uvm_plain, custom_cpu_template):
    """Microvm fixture with a CPU template"""
    uvm_plain.spawn()
    uvm_plain.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
    )
    uvm_plain.cpu_config(custom_cpu_template["template"])
    uvm_plain.add_net_iface()
    uvm_plain.start()
    return uvm_plain


@pytest.fixture(scope="session", name="spectre_meltdown_checker")
def download_spectre_meltdown_checker(tmp_path_factory):
    """Download spectre / meltdown checker script."""
    resp = requests.get(CHECKER_URL, timeout=5)
    resp.raise_for_status()

    path = tmp_path_factory.mktemp("tmp", True) / CHECKER_FILENAME
    path.write_bytes(resp.content)

    return path


def run_spectre_meltdown_checker_on_guest(
    microvm,
    spectre_meltdown_checker,
):
    """Run the spectre / meltdown checker on guest"""
    remote_path = f"/tmp/{CHECKER_FILENAME}"
    microvm.ssh.scp_put(spectre_meltdown_checker, remote_path)
    ecode, stdout, stderr = microvm.ssh.execute_command(f"sh {remote_path} --explain")
    assert ecode == 0, f"stdout:\n{stdout}\nstderr:\n{stderr}\n"


@pytest.mark.no_block_pr
@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
def test_spectre_meltdown_checker_on_host(spectre_meltdown_checker):
    """
    Test with the spectre / meltdown checker on host.
    """
    utils.run_cmd(f"sh {spectre_meltdown_checker} --explain")


@pytest.mark.no_block_pr
@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
def test_spectre_meltdown_checker_on_guest(spectre_meltdown_checker, microvm):
    """
    Test with the spectre / meltdown checker on guest.
    """
    run_spectre_meltdown_checker_on_guest(
        microvm,
        spectre_meltdown_checker,
    )


@pytest.mark.no_block_pr
@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
def test_spectre_meltdown_checker_on_restored_guest(
    spectre_meltdown_checker,
    microvm,
    microvm_factory,
):
    """
    Test with the spectre / meltdown checker on a restored guest.
    """

    snapshot = microvm.snapshot_full()
    # Create a destination VM
    dst_vm = microvm_factory.build()
    dst_vm.spawn()
    # Restore the destination VM from the snapshot
    dst_vm.restore_from_snapshot(snapshot, resume=True)

    run_spectre_meltdown_checker_on_guest(
        dst_vm,
        spectre_meltdown_checker,
    )


@pytest.mark.no_block_pr
@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
@skip_on_arm
def test_spectre_meltdown_checker_on_guest_with_template(
    spectre_meltdown_checker,
    microvm_with_template,
):
    """
    Test with the spectre / meltdown checker on guest with CPU template.
    """

    run_spectre_meltdown_checker_on_guest(
        microvm_with_template,
        spectre_meltdown_checker,
    )


@pytest.mark.no_block_pr
@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
@skip_on_arm
def test_spectre_meltdown_checker_on_guest_with_custom_template(
    spectre_meltdown_checker,
    microvm_with_custom_cpu_template,
):
    """
    Test with the spectre / meltdown checker on guest with a custom CPU template.
    """
    microvm = microvm_with_custom_cpu_template
    run_spectre_meltdown_checker_on_guest(
        microvm,
        spectre_meltdown_checker,
    )


@pytest.mark.no_block_pr
@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
@skip_on_arm
def test_spectre_meltdown_checker_on_restored_guest_with_template(
    spectre_meltdown_checker,
    microvm_with_template,
    microvm_factory,
):
    """
    Test with the spectre / meltdown checker on a restored guest with a CPU template.
    """

    snapshot = microvm_with_template.snapshot_full()
    # Create a destination VM
    dst_vm = microvm_factory.build()
    dst_vm.spawn()
    # Restore the destination VM from the snapshot
    dst_vm.restore_from_snapshot(snapshot, resume=True)

    run_spectre_meltdown_checker_on_guest(
        dst_vm,
        spectre_meltdown_checker,
    )


@pytest.mark.no_block_pr
@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
@skip_on_arm
def test_spectre_meltdown_checker_on_restored_guest_with_custom_template(
    spectre_meltdown_checker,
    microvm_with_custom_cpu_template,
    microvm_factory,
):
    """
    Test with the spectre / meltdown checker on a restored guest with a custom CPU template.
    """

    src_vm = microvm_with_custom_cpu_template
    snapshot = src_vm.snapshot_full()
    dst_vm = microvm_factory.build()
    dst_vm.spawn()
    # Restore the destination VM from the snapshot
    dst_vm.restore_from_snapshot(snapshot, resume=True)

    run_spectre_meltdown_checker_on_guest(
        dst_vm,
        spectre_meltdown_checker,
    )


@pytest.mark.no_block_pr
def check_vulnerabilities_files_on_guest(microvm):
    """
    Check that the guest's vulnerabilities files do not contain `Vulnerable`.
    See also: https://elixir.bootlin.com/linux/latest/source/Documentation/ABI/testing/sysfs-devices-system-cpu
    and search for `vulnerabilities`.
    """
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"
    ecode, stdout, stderr = microvm.ssh.execute_command(
        f"grep -r Vulnerable {vuln_dir} | grep -v mmio_stale_data:"
    )
    assert ecode == 1, f"stdout:\n{stdout}\nstderr:\n{stderr}\n"


@pytest.mark.no_block_pr
def test_vulnerabilities_files_on_guest(microvm):
    """
    Test vulnerabilities files on guest.
    """
    check_vulnerabilities_files_on_guest(microvm)


@pytest.mark.no_block_pr
def test_vulnerabilities_files_on_restored_guest(
    microvm,
    microvm_factory,
):
    """
    Test vulnerabilities files on a restored guest.
    """
    snapshot = microvm.snapshot_full()
    # Create a destination VM
    dst_vm = microvm_factory.build()
    dst_vm.spawn()
    # Restore the destination VM from the snapshot
    dst_vm.restore_from_snapshot(snapshot, resume=True)

    check_vulnerabilities_files_on_guest(dst_vm)


@pytest.mark.no_block_pr
@skip_on_arm
def test_vulnerabilities_files_on_guest_with_template(
    microvm_with_template,
):
    """
    Test vulnerabilities files on guest with CPU template.
    """
    check_vulnerabilities_files_on_guest(microvm_with_template)


@pytest.mark.no_block_pr
@skip_on_arm
def test_vulnerabilities_files_on_guest_with_custom_template(
    microvm_with_custom_cpu_template,
):
    """
    Test vulnerabilities files on guest with a custom CPU template.
    """
    check_vulnerabilities_files_on_guest(microvm_with_custom_cpu_template)


@pytest.mark.no_block_pr
@skip_on_arm
def test_vulnerabilities_files_on_restored_guest_with_template(
    microvm_with_template,
    microvm_factory,
):
    """
    Test vulnerabilities files on a restored guest with a CPU template.
    """
    snapshot = microvm_with_template.snapshot_full()
    # Create a destination VM
    dst_vm = microvm_factory.build()
    dst_vm.spawn()
    # Restore the destination VM from the snapshot
    dst_vm.restore_from_snapshot(snapshot, resume=True)

    check_vulnerabilities_files_on_guest(dst_vm)


@pytest.mark.no_block_pr
@skip_on_arm
def test_vulnerabilities_files_on_restored_guest_with_custom_template(
    microvm_with_custom_cpu_template,
    microvm_factory,
):
    """
    Test vulnerabilities files on a restored guest with a custom CPU template.
    """
    src_vm = microvm_with_custom_cpu_template
    snapshot = src_vm.snapshot_full()
    dst_vm = microvm_factory.build()
    dst_vm.spawn()
    # Restore the destination VM from the snapshot
    dst_vm.restore_from_snapshot(snapshot, resume=True)

    check_vulnerabilities_files_on_guest(dst_vm)
