# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# N.B.: Although this repository is released under the Apache-2.0, part of its test requires a
# script from the third party "Spectre & Meltdown Checker" project. This script is under the
# GPL-3.0-only license.
"""Tests vulnerabilities mitigations."""

import os

import pytest
import requests

from framework import utils
from framework.properties import global_props
from framework.utils_cpu_templates import nonci_on_arm

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
    return uvm_plain, cpu_template


@pytest.fixture(name="microvm_with_custom_template")
def microvm_with_custom_template_fxt(uvm_plain, custom_cpu_template):
    """Microvm fixture with a CPU template"""
    uvm_plain.spawn()
    uvm_plain.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
    )
    uvm_plain.api.cpu_config.put(**custom_cpu_template["template"])
    uvm_plain.add_net_iface()
    uvm_plain.start()
    return uvm_plain, custom_cpu_template["name"]


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
    ecode, stdout, stderr = microvm.ssh.run(f"sh {remote_path} --explain --no-intel-db")
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
@nonci_on_arm
def test_spectre_meltdown_checker_on_guest_with_template(
    spectre_meltdown_checker,
    microvm_with_template,
):
    """
    Test with the spectre / meltdown checker on guest with CPU template.
    """
    microvm, _template = microvm_with_template
    run_spectre_meltdown_checker_on_guest(
        microvm,
        spectre_meltdown_checker,
    )


@pytest.mark.no_block_pr
@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
@nonci_on_arm
def test_spectre_meltdown_checker_on_guest_with_custom_template(
    spectre_meltdown_checker,
    microvm_with_custom_template,
):
    """
    Test with the spectre / meltdown checker on guest with a custom CPU template.
    """
    microvm, _template = microvm_with_custom_template
    run_spectre_meltdown_checker_on_guest(
        microvm,
        spectre_meltdown_checker,
    )


@pytest.mark.no_block_pr
@pytest.mark.skipif(
    global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14",
    reason="c7g host 4.14 requires modifications to the 5.10 guest kernel to boot successfully.",
)
@nonci_on_arm
def test_spectre_meltdown_checker_on_restored_guest_with_template(
    spectre_meltdown_checker,
    microvm_with_template,
    microvm_factory,
):
    """
    Test with the spectre / meltdown checker on a restored guest with a CPU template.
    """
    microvm, _template = microvm_with_template
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
@nonci_on_arm
def test_spectre_meltdown_checker_on_restored_guest_with_custom_template(
    spectre_meltdown_checker,
    microvm_with_custom_template,
    microvm_factory,
):
    """
    Test with the spectre / meltdown checker on a restored guest with a custom CPU template.
    """

    src_vm, _template = microvm_with_custom_template
    snapshot = src_vm.snapshot_full()
    dst_vm = microvm_factory.build()
    dst_vm.spawn()
    # Restore the destination VM from the snapshot
    dst_vm.restore_from_snapshot(snapshot, resume=True)

    run_spectre_meltdown_checker_on_guest(
        dst_vm,
        spectre_meltdown_checker,
    )


def get_vuln_files_exception_dict(template):
    """
    Returns a dictionary of expected values for vulnerability files requiring special treatment.
    """
    exception_dict = {}

    # Exception for mmio_stale_data
    # =============================
    #
    # Guests on Intel Skylake or with T2S template
    # --------------------------------------------
    # Whether mmio_stale_data is marked as "Vulnerable" or not is determined by the code here.
    # https://elixir.bootlin.com/linux/v6.1.46/source/arch/x86/kernel/cpu/bugs.c#L431
    # Virtualization of FLUSH_L1D has been available and CPUID.(EAX=0x7,ECX=0):EDX[28 (FLUSH_L1D)]
    # has been passed through to guests only since kernel v6.4.
    # https://github.com/torvalds/linux/commit/da3db168fb671f15e393b227f5c312c698ecb6ea
    # Thus, since the FLUSH_L1D bit is masked off prior to kernel v6.4, guests with
    # IA32_ARCH_CAPABILITIES.FB_CLEAR (bit 17) = 0 (like guests on Intel Skylake and guests with
    # T2S template) fall onto the second hand of the condition and fail the test. The expected value
    # "Vulnerable: Clear CPU buffers attempted, no microcode" means that the kernel is using the
    # best effort mode which invokes the mitigation instructions (VERW in this case) without a
    # guarantee that they clear the CPU buffers. If the host has the microcode update applied
    # correctly, the mitigation works and it is safe to ignore the "Vulnerable" message.
    #
    # Guest on Intel Skylake with C3 template
    # ---------------------------------------
    # If the processor does not enumerate IA32_ARCH_CAPABILITIES.{FBSDP_NO,PSDP_NO,SBDR_SSDP_NO},
    # the kernel checks its lists of affected/unaffected processors and determines whether the
    # mitigation is required, and if the processor is not included in the lists, the sysfs is marked
    # as "Unknown".
    # https://elixir.bootlin.com/linux/v6.1.50/source/arch/x86/kernel/cpu/common.c#L1387
    # The behavior for "Unknown" state was added in the following commit and older processors that
    # are no longer serviced are not listed up.
    # https://github.com/torvalds/linux/commit/7df548840c496b0141fb2404b889c346380c2b22
    # Since those bits are not set on Intel Skylake and C3 template makes guests pretend to be AWS
    # C3 instance (quite old processor now) by overwriting CPUID.1H:EAX, it is impossible to avoid
    # this "Unknown" state.
    if global_props.cpu_codename == "INTEL_SKYLAKE" and template == "C3":
        exception_dict["mmio_stale_data"] = "Unknown: No mitigations"
    elif global_props.cpu_codename == "INTEL_SKYLAKE" or template == "T2S":
        exception_dict[
            "mmio_stale_data"
        ] = "Vulnerable: Clear CPU buffers attempted, no microcode"

    return exception_dict


@pytest.mark.no_block_pr
def test_vulnerabilities_on_host():
    """
    Test vulnerabilities files on host.
    """
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"

    # `grep` returns 1 if no lines were selected.
    ecode, stdout, stderr = utils.run_cmd(
        f"grep -r Vulnerable {vuln_dir}", ignore_return_code=True
    )
    assert ecode == 1, f"stdout:\n{stdout}\nstderr:\n{stderr}\n"


@pytest.mark.no_block_pr
def check_vulnerabilities_files_on_guest(microvm, template=None):
    """
    Check that the guest's vulnerabilities files do not contain `Vulnerable`.
    See also: https://elixir.bootlin.com/linux/latest/source/Documentation/ABI/testing/sysfs-devices-system-cpu
    and search for `vulnerabilities`.
    """
    # Retrieve a list of vulnerabilities files available inside guests.
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"
    ecode, stdout, stderr = microvm.ssh.run(f"find {vuln_dir} -type f")
    assert ecode == 0, f"stdout:\n{stdout}\nstderr:\n{stderr}\n"
    vuln_files = stdout.split("\n")

    # Check that vulnerabilities files in the exception dictionary have the expected values and
    # the others do not contain "Vulnerable".
    exceptions = get_vuln_files_exception_dict(template)
    for vuln_file in vuln_files:
        filename = os.path.basename(vuln_file)
        if filename in exceptions:
            _, stdout, _ = microvm.ssh.run(f"cat {vuln_file}")
            assert exceptions[filename] in stdout
        else:
            cmd = f"grep Vulnerable {vuln_file}"
            ecode, stdout, stderr = microvm.ssh.run(cmd)
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
@nonci_on_arm
def test_vulnerabilities_files_on_guest_with_template(
    microvm_with_template,
):
    """
    Test vulnerabilities files on guest with CPU template.
    """
    microvm, template = microvm_with_template
    check_vulnerabilities_files_on_guest(microvm, template)


@pytest.mark.no_block_pr
@nonci_on_arm
def test_vulnerabilities_files_on_guest_with_custom_template(
    microvm_with_custom_template,
):
    """
    Test vulnerabilities files on guest with a custom CPU template.
    """
    microvm, template = microvm_with_custom_template
    check_vulnerabilities_files_on_guest(microvm, template)


@pytest.mark.no_block_pr
@nonci_on_arm
def test_vulnerabilities_files_on_restored_guest_with_template(
    microvm_with_template,
    microvm_factory,
):
    """
    Test vulnerabilities files on a restored guest with a CPU template.
    """
    microvm, template = microvm_with_template
    snapshot = microvm.snapshot_full()
    # Create a destination VM
    dst_vm = microvm_factory.build()
    dst_vm.spawn()
    # Restore the destination VM from the snapshot
    dst_vm.restore_from_snapshot(snapshot, resume=True)

    check_vulnerabilities_files_on_guest(dst_vm, template)


@pytest.mark.no_block_pr
@nonci_on_arm
def test_vulnerabilities_files_on_restored_guest_with_custom_template(
    microvm_with_custom_template,
    microvm_factory,
):
    """
    Test vulnerabilities files on a restored guest with a custom CPU template.
    """
    src_vm, template = microvm_with_custom_template
    snapshot = src_vm.snapshot_full()
    dst_vm = microvm_factory.build()
    dst_vm.spawn()
    # Restore the destination VM from the snapshot
    dst_vm.restore_from_snapshot(snapshot, resume=True)

    check_vulnerabilities_files_on_guest(dst_vm, template)
