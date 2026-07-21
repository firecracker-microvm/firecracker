# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# N.B.: Although this repository is released under the Apache-2.0, part of its test requires a
# script from the third party "Spectre & Meltdown Checker" project. This script is under the
# GPL-3.0-only license.
"""Tests vulnerabilities mitigations."""

import json
import re
from pathlib import Path

import pytest
import requests

from framework import utils
from framework.ab_test import git_clone
from framework.artifacts import pin_pci
from framework.microvm import MicroVMFactory
from framework.properties import global_props
from framework.utils_cpu_templates import ALL_CPU_TEMPLATES, pin_cpu_template

# Pinned due to issues introduced in https://github.com/speed47/spectre-meltdown-checker/pull/527
CHECKER_URL = "https://raw.githubusercontent.com/speed47/spectre-meltdown-checker/3a822fdcf291ebb8bfbcb77aa216ac342c6b2f12/spectre-meltdown-checker.sh"
CHECKER_FILENAME = "spectre-meltdown-checker.sh"
REMOTE_CHECKER_PATH = f"/tmp/{CHECKER_FILENAME}"
REMOTE_CHECKER_COMMAND = f"sh {REMOTE_CHECKER_PATH} --no-intel-db --batch json"

VULN_DIR = "/sys/devices/system/cpu/vulnerabilities"

# spectre-meltdown-checker does not recognise Neoverse V3 (MIDR part 0xd84), so it
# falls back to reporting Spectre v2 and Variant 3a as vulnerable. The kernel itself
# reports the CPU as mitigated (spectre_v2: "Mitigation: CSV2, BHB"), and Graviton4
# (Neoverse V2, which the checker does recognise) passes the same tests.
# TODO: remove this skip once the following issue is resolved:
# https://github.com/speed47/spectre-meltdown-checker/issues/582
SKIP_SMC_UNRECOGNISED_CPU = pytest.mark.skipif(
    global_props.cpu_codename == "ARM_NEOVERSE_V3",
    reason="spectre-meltdown-checker does not recognise Neoverse V3 (0xd84)",
)


class SpectreMeltdownChecker:
    """Helper class to use Spectre & Meltdown Checker"""

    def __init__(self, path):
        self.path = path

    def _parse_output(self, output):
        return {
            json.dumps(entry)  # dict is unhashable
            for entry in json.loads(output)
            if entry["VULNERABLE"]
        }

    def get_report_for_guest(self, vm) -> set:
        """Parses the output of `spectre-meltdown-checker.sh --batch json`
        and returns the set of issues for which it reported 'Vulnerable'.

        Sample stdout:
        ```
        [
          {
            "NAME": "SPECTRE VARIANT 1",
            "CVE": "CVE-2017-5753",
            "VULNERABLE": false,
            "INFOS": "Mitigation: usercopy/swapgs barriers and __user pointer sanitization"
          },
          { ... }
        ]
        ```
        """
        vm.ssh.scp_put(self.path, REMOTE_CHECKER_PATH)
        res = vm.ssh.run(REMOTE_CHECKER_COMMAND)
        return self._parse_output(res.stdout)

    def get_report_for_host(self) -> set:
        """Runs `spectre-meltdown-checker.sh` in the host and returns the set of
        issues for which it reported 'Vulnerable'.
        """

        res = utils.check_output(f"sh {self.path} --batch json")
        return self._parse_output(res.stdout)

    def expected_vulnerabilities(self, cpu_template_name, guest_kernel_version=None):
        """
        There is a REPTAR exception reported on INTEL_ICELAKE when spectre-meltdown-checker.sh
        script is run inside the guest from below the tests:
            test_spectre_meltdown_checker_on_guest and
            test_spectre_meltdown_checker_on_restored_guest
        The same script when run on host doesn't report the
        exception which means the instances are actually not vulnerable to REPTAR.
        The only reason why the script cannot determine if the guest
        is vulnerable or not because Firecracker does not expose the microcode
        version to the guest.

        The check in spectre_meltdown_checker is here:
            https://github.com/speed47/spectre-meltdown-checker/blob/0f2edb1a71733c1074550166c5e53abcfaa4d6ca/spectre-meltdown-checker.sh#L6635-L6637

        Since we have a test on host and the exception in guest is not valid,
        we add a check to ignore this exception.
        """
        if (
            global_props.cpu_codename in ["INTEL_ICELAKE", "INTEL_SAPPHIRE_RAPIDS"]
            and cpu_template_name == "None"
        ):
            return {
                '{"NAME": "REPTAR", "CVE": "CVE-2023-23583", "VULNERABLE": true, "INFOS": "Your microcode is too old to mitigate the vulnerability"}'
            }

        # There is a SRSO / INCEPTION (CVE-2023-20569) exception reported on AMD_MILAN and
        # AMD_GENOA when spectre-meltdown-checker.sh script is run inside the guest
        # in the following tests:
        #     test_spectre_meltdown_checker_on_guest and
        #     test_check_vulnerability_files_ab
        # On kernels >= 6.7, when SRSO safe RET is active but IBPB_BRTYPE CPU flag is
        # absent, the kernel reports "Vulnerable: Safe RET, no microcode" instead
        # of the previous "Mitigation: safe RET, no microcode". The checker treats
        # any status starting with "Vulnerable" as a vulnerability.
        # This only affects guest kernels >= 6.7 running on host kernels < 6.7,
        # because KVM did not synthesize the IBPB_BRTYPE flag for guests prior to v6.7.
        # https://github.com/torvalds/linux/commit/6f0f23ef76be
        # https://github.com/amazonlinux/linux/blob/65171e3dd9bd18f97f48f94d8dd0f50c82eb45d1/arch/x86/kvm/cpuid.c#L1226
        # With a CPU template (e.g. T2A), the overridden guest-visible FMS is not
        # classified as affected by SRSO, so the checker does not flag it.
        if (
            global_props.cpu_codename in ["AMD_MILAN", "AMD_GENOA"]
            and cpu_template_name == "None"
            and guest_kernel_version
            and guest_kernel_version >= (6, 7)
            and global_props.host_linux_version_tpl < (6, 7)
        ):
            return {
                '{"NAME": "INCEPTION", "CVE": "CVE-2023-20569", "VULNERABLE": true, "INFOS": "Vulnerable: Safe RET, no microcode"}'
            }
        return set()


@pytest.fixture(scope="session", name="spectre_meltdown_checker")
def download_spectre_meltdown_checker(tmp_path_factory):
    """Download spectre / meltdown checker script."""
    resp = requests.get(CHECKER_URL, timeout=5)
    resp.raise_for_status()
    path = tmp_path_factory.mktemp("tmp", True) / CHECKER_FILENAME
    path.write_bytes(resp.content)
    return SpectreMeltdownChecker(path)


# Nothing can be sensibly tested in a PR context here
@SKIP_SMC_UNRECOGNISED_CPU
@pytest.mark.skipif(
    global_props.buildkite_pr or global_props.is_dev_env,
    reason="Test depends solely on factors external to GitHub repository",
)
def test_spectre_meltdown_checker_on_host(spectre_meltdown_checker):
    """Test with the spectre / meltdown checker on host."""
    report = spectre_meltdown_checker.get_report_for_host()
    assert report == set(), f"Unexpected vulnerabilities: {report}"


# Nothing can be sensibly tested here in a PR context
@pytest.mark.skipif(
    global_props.buildkite_pr or global_props.is_dev_env,
    reason="Test depends solely on factors external to GitHub repository",
)
def test_vulnerabilities_on_host():
    """Test vulnerability files on host."""
    res = utils.run_cmd(f"grep -r Vulnerable {VULN_DIR}")
    # if grep finds no matching lines, it exits with status 1
    assert res.returncode == 1, res.stdout


def get_vuln_files_exception_dict(template, guest_kernel_version=None):
    """
    Returns a dictionary of expected values for vulnerability files requiring special treatment.
    """
    exception_dict = {}

    # Exception for mmio_stale_data
    # =============================
    #
    # Guests with T2S template
    # --------------------------------------------
    # Whether mmio_stale_data is marked as "Vulnerable" or not is determined by the code here.
    # https://elixir.bootlin.com/linux/v6.1.46/source/arch/x86/kernel/cpu/bugs.c#L431
    # Virtualization of FLUSH_L1D has been available and CPUID.(EAX=0x7,ECX=0):EDX[28 (FLUSH_L1D)]
    # has been passed through to guests only since kernel v6.4.
    # https://github.com/torvalds/linux/commit/da3db168fb671f15e393b227f5c312c698ecb6ea
    # Thus, since the FLUSH_L1D bit is masked off prior to kernel v6.4, guests with
    # IA32_ARCH_CAPABILITIES.FB_CLEAR (bit 17) = 0 (like guests with T2S template which presents
    # an Intel Skylake CPU) fall into the MMIO_MITIGATION_UCODE_NEEDED branch, marking the
    # system as vulnerable to MMIO Stale Data.
    # The value is "Vulnerable: Clear CPU buffers attempted, no microcode" on guests on Intel
    # Skylake and guests with T2S template but "Mitigation: Clear CPU buffers; SMT Host state
    # unknown" on kernel v6.4 or later.
    # In any case, the kernel attempts to clear CPU buffers using VERW instruction and it
    # is safe to ingore the "Vulnerable" message if the host has the microcode update applied
    # correctly. Here we expect the common string "Clear CPU buffers" to cover both cases.

    if template == "T2S":
        exception_dict["mmio_stale_data"] = r"Clear CPU buffers"

    # Exception for spectre_v2 (BHI)
    # ==============================
    #
    # Guests on kernel v6.18+ (Intel only)
    # --------------------------------------------
    # On kernel >= 6.18, the new attack vector control framework only enables BHI
    # mitigation when CPU_MITIGATE_GUEST_HOST is active (i.e., the system runs VMs).
    # https://github.com/amazonlinux/linux/blob/65171e3dd9bd18f97f48f94d8dd0f50c82eb45d1/arch/x86/kernel/cpu/bugs.c#L2221
    #
    # Firecracker guests do not run nested VMs because their kernels are built
    # with 'CONFIG_VIRTUALIZATION is not set'. As a result CONFIG_KVM=n, which causes
    # CPU_MITIGATE_GUEST_HOST to be false, so BHI mitigation is not activated.
    # https://github.com/amazonlinux/linux/blob/65171e3dd9bd18f97f48f94d8dd0f50c82eb45d1/kernel/cpu.c#L3192
    # Therefore, we accept any BHI status only if the overall spectre_v2 status
    # starts with "Mitigation:" and no other component reports "Vulnerable".

    if (
        global_props.cpu_codename.startswith("INTEL")
        and guest_kernel_version
        and guest_kernel_version >= (6, 18)
    ):
        exception_dict["spectre_v2"] = r"^Mitigation:(?!.*(?<!BHI: )Vulnerable).*$"

    # On kernels >= 6.7, when SRSO safe RET is active but IBPB_BRTYPE CPU flag is
    # absent, the kernel reports "Vulnerable: Safe RET, no microcode" instead
    # of the previous "Mitigation: safe RET, no microcode". The checker treats
    # any status starting with "Vulnerable" as a vulnerability.
    # This only affects guest kernels >= 6.7 running on host kernels < 6.7,
    # because KVM did not synthesize the IBPB_BRTYPE flag for guests prior to v6.7.
    # https://github.com/torvalds/linux/commit/6f0f23ef76be
    # https://github.com/amazonlinux/linux/blob/65171e3dd9bd18f97f48f94d8dd0f50c82eb45d1/arch/x86/kvm/cpuid.c#L1226

    if (
        global_props.cpu_codename in ["AMD_MILAN", "AMD_GENOA"]
        and template == "None"
        and guest_kernel_version
        and guest_kernel_version >= (6, 7)
        and global_props.host_linux_version_tpl < (6, 7)
    ):
        exception_dict["spec_rstack_overflow"] = r"^Vulnerable: Safe RET, no microcode"

    return exception_dict


def check_vulnerabilities_files_on_guest(microvm):
    """
    Check that the guest's vulnerabilities files do not contain `Vulnerable`.
    See also: https://elixir.bootlin.com/linux/latest/source/Documentation/ABI/testing/sysfs-devices-system-cpu
    and search for `vulnerabilities`.
    """
    # Retrieve a list of vulnerabilities files available inside guests.
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"
    _, stdout, _ = microvm.ssh.check_output(f"find -D all {vuln_dir} -type f")
    vuln_files = stdout.splitlines()

    # Fixtures in this file (test_vulnerabilities.py) add this special field.
    template = microvm.cpu_template_name

    # Check that vulnerabilities files in the exception dictionary have the expected values and
    # the others do not contain "Vulnerable".
    exceptions = get_vuln_files_exception_dict(template, microvm.guest_kernel_version)
    results = []
    for vuln_file in vuln_files:
        filename = Path(vuln_file).name
        if filename in exceptions:
            _, stdout, _ = microvm.ssh.check_output(f"cat {vuln_file}")
            assert re.search(exceptions[filename], stdout), (
                f"{vuln_file}: content '{stdout.strip()}' does not match "
                f"expected pattern r'{exceptions[filename]}'"
            )
        else:
            cmd = f"grep Vulnerable {vuln_file}"
            _ecode, stdout, _stderr = microvm.ssh.run(cmd)
            results.append({"file": vuln_file, "stdout": stdout})
    return results


@pytest.fixture
def microvm_factory_a(record_property):
    """MicroVMFactory using revision A binaries"""
    revision_a = global_props.buildkite_revision_a
    bin_dir = git_clone(Path("../build") / revision_a, revision_a).resolve()
    record_property("firecracker_bin", str(bin_dir / "firecracker"))
    uvm_factory = MicroVMFactory(bin_dir)
    yield uvm_factory
    uvm_factory.kill()


@pytest.fixture
def uvm_any_a(
    microvm_factory_a,
    uvm_lifecycle,
    guest_kernel,
    rootfs,
    pci_enabled,
    cpu_template,
):
    """Return uvm with revision A firecracker, matching uvm_any's lifecycle.

    Both `uvm_any` and `uvm_any_a` depend on `uvm_lifecycle`, which guarantees
    they pick the same booted/restored state per test run.
    """
    builder = (
        microvm_factory_a.build_booted
        if uvm_lifecycle == "booted"
        else microvm_factory_a.build_restored
    )
    return builder(guest_kernel, rootfs, pci=pci_enabled, cpu_template=cpu_template)


@pin_pci(False)
@pin_cpu_template(ALL_CPU_TEMPLATES)
def test_check_vulnerability_files_ab(request, uvm_any):
    """Test vulnerability files on guests"""
    res_b = check_vulnerabilities_files_on_guest(uvm_any)
    if global_props.buildkite_pr:
        # we only get the uvm_any_a fixtures if we need it
        uvm_a = request.getfixturevalue("uvm_any_a")
        res_a = check_vulnerabilities_files_on_guest(uvm_a)
        assert res_b <= res_a
    else:
        assert not [x for x in res_b if "Vulnerable" in x["stdout"]]


@SKIP_SMC_UNRECOGNISED_CPU
@pin_pci(False)
@pin_cpu_template(ALL_CPU_TEMPLATES)
def test_spectre_meltdown_checker_on_guest(
    request,
    uvm_any,
    spectre_meltdown_checker,
):
    """Test with the spectre / meltdown checker on any supported guest."""
    res_b = spectre_meltdown_checker.get_report_for_guest(uvm_any)
    if global_props.buildkite_pr:
        # we only get the uvm_any_a fixtures if we need it
        uvm_a = request.getfixturevalue("uvm_any_a")
        res_a = spectre_meltdown_checker.get_report_for_guest(uvm_a)
        assert res_b <= res_a
    else:
        assert res_b == spectre_meltdown_checker.expected_vulnerabilities(
            uvm_any.cpu_template_name, uvm_any.guest_kernel_version
        )
