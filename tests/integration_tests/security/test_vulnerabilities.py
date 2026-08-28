# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# N.B.: Although this repository is released under the Apache-2.0, part of its test requires a
# script from the third party "Spectre & Meltdown Checker" project. This script is under the
# GPL-3.0-only license.
"""Tests vulnerabilities mitigations."""

import json
from pathlib import Path

import pytest
import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from framework import utils
from framework.ab_test import git_clone
from framework.artifacts import pin_pci
from framework.microvm import MicroVMFactory
from framework.properties import global_props
from framework.utils_cpu_templates import ALL_CPU_TEMPLATES, pin_cpu_template

CHECKER_URL = "https://raw.githubusercontent.com/speed47/spectre-meltdown-checker/master/spectre-meltdown-checker.sh"
CHECKER_FILENAME = "spectre-meltdown-checker.sh"
REMOTE_CHECKER_PATH = f"/tmp/{CHECKER_FILENAME}"
REMOTE_CHECKER_COMMAND = f"sh {REMOTE_CHECKER_PATH} --batch json-terse"

VULN_DIR = "/sys/devices/system/cpu/vulnerabilities"


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
        """Parses the output of `spectre-meltdown-checker.sh --batch json-terse`
        and returns the set of issues for which it reported 'Vulnerable'.

        Firecracker intentionally does not expose the host's microcode update
        status to guests. KVM instead reports fixed synthetic versions: 1 on
        Intel and 0x01000065 on AMD. These otherwise arbitrary values exist
        solely to work around specific issues; they do not identify an actual
        microcode version. The checker treats the synthetic value as an
        installed version, which would require test-side exceptions for
        microcode-only mitigations. This test therefore supplies the host's
        microcode version for guests without a CPU template. Guests with a CPU
        template retain the synthetic version because the host's microcode
        version is not meaningful for their modified CPU model.

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
        command = REMOTE_CHECKER_COMMAND
        if vm.cpu_template_name == "None":
            command = f"SMC_MOCK_CPU_UCODE={global_props.cpu_microcode} {command}"
        res = vm.ssh.run(command)
        return self._parse_output(res.stdout)

    def get_report_for_host(self) -> set:
        """Runs `spectre-meltdown-checker.sh` in the host and returns the set of
        issues for which it reported 'Vulnerable'.

        `--vmm yes` forces VMM host checks even when no Firecracker process is
        running concurrently for the checker's automatic detection.
        """

        res = utils.check_output(f"sh {self.path} --batch json-terse --vmm yes")
        return self._parse_output(res.stdout)

    # pylint: disable=too-many-return-statements
    def expected_vulnerabilities(self, cpu_template_name, guest_kernel_version):
        """Return the checker findings expected for the guest configuration."""

        # SRSO / INCEPTION false positive (CVE-2023-20569)
        #
        # Affected configuration:
        # - AMD Milan or Genoa
        # - No CPU template
        # - Host kernel older than v6.7
        #
        # Root cause:
        # CPUID.80000021H:EAX[28] (IBPB_BRTYPE) indicates that IBPB flushes all branch type
        # predictions. The Milan and Genoa hosts in the test fleet have the required microcode.
        # The extended IBPB behavior also applies to IBPB commands executed inside guests.
        #
        # Before v6.7, KVM did not advertise IBPB_BRTYPE to guests. The guest kernel therefore
        # reports that the required microcode is missing even though IBPB performs the required
        # flush, making this finding a false positive.
        # https://github.com/torvalds/linux/commit/6f0f23ef76be
        #
        # Guest reporting:
        # - Guest kernels >= v6.7 report: "Vulnerable: Safe RET, no microcode".
        # - Guest kernels < v6.7 incorrectly report: "Mitigation: safe RET, no microcode".
        # https://github.com/torvalds/linux/commit/dc6306ad5b0d
        #
        # For older guest kernels, spectre-meltdown-checker treats "Mitigation: Safe RET, no
        # microcode" as vulnerable to match the corrected reporting in newer kernels, and appends
        # an explanation to INFOS.
        # https://github.com/speed47/spectre-meltdown-checker/blob/03cc4ffeb1dca9bb8d89f8096dc45015530d3214/spectre-meltdown-checker.sh#L11044-L11052
        #
        # T2A is excluded because its guest-visible FMS is not classified
        # as affected by SRSO.
        if (
            global_props.cpu_codename in ["AMD_MILAN", "AMD_GENOA"]
            and cpu_template_name == "None"
            and global_props.host_linux_version_tpl < (6, 7)
        ):
            infos_suffix = ""
            if guest_kernel_version < (6, 7):
                infos_suffix = " (your kernel incorrectly reports this as mitigated, it was fixed in more recent kernels)"

            return {
                f'{{"NAME": "INCEPTION", "CVE": "CVE-2023-20569", "VULNERABLE": true, "INFOS": "Vulnerable: Safe RET, no microcode{infos_suffix}"}}'
            }

        return set()


@pytest.fixture(scope="session", name="spectre_meltdown_checker")
def download_spectre_meltdown_checker(tmp_path_factory):
    """Download spectre / meltdown checker script."""
    resp = _download_checker_script()
    path = tmp_path_factory.mktemp("tmp", True) / CHECKER_FILENAME
    path.write_bytes(resp.content)
    return SpectreMeltdownChecker(path)


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=2, min=1),
    reraise=True,
)
def _download_checker_script():
    """Download the spectre-meltdown-checker script with retries."""
    resp = requests.get(CHECKER_URL, timeout=30)
    resp.raise_for_status()
    return resp


# Nothing can be sensibly tested in a PR context here
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


def get_vuln_files_exception_dict(template, guest_kernel_version):
    """
    Returns a dictionary of expected values for vulnerability files requiring special treatment.
    """
    exception_dict = {}

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
    if global_props.cpu_vendor == "intel" and guest_kernel_version >= (6, 18):
        exception_dict["spectre_v2"] = {
            "is_expected": lambda status: (
                status.startswith("Mitigation:")
                and all(
                    "Vulnerable" not in component
                    or component.strip() == "BHI: Vulnerable"
                    for component in status.split(";")
                )
            ),
            "expected": (
                'a status starting with "Mitigation:" and no vulnerable '
                'component other than "BHI: Vulnerable"'
            ),
        }

    # See SpectreMeltdownChecker.expected_vulnerabilities() for the cause of this SRSO false
    # positive. Guest kernels >= v6.7 report it as vulnerable in sysfs, so accept the expected
    # status here.
    if (
        global_props.cpu_codename in ["AMD_MILAN", "AMD_GENOA"]
        and template == "None"
        and guest_kernel_version >= (6, 7)
        and global_props.host_linux_version_tpl < (6, 7)
    ):
        exception_dict["spec_rstack_overflow"] = {
            "is_expected": lambda status: status.startswith(
                "Vulnerable: Safe RET, no microcode"
            ),
            "expected": 'a status starting with "Vulnerable: Safe RET, no microcode"',
        }

    return exception_dict


def check_vulnerabilities_files_on_guest(microvm):
    """Return unexpected findings from the guest's vulnerability files.

    Exception statuses are omitted when they match their expected values and
    reported as findings otherwise.

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
    findings = set()
    for vuln_file in vuln_files:
        filename = Path(vuln_file).name
        if filename in exceptions:
            _, stdout, _ = microvm.ssh.check_output(f"cat {vuln_file}")
            exception = exceptions[filename]
            status = stdout.strip()
            if not exception["is_expected"](status):
                findings.add(
                    f"{vuln_file}: expected {exception['expected']}, got {status!r}"
                )
        else:
            cmd = f"grep Vulnerable {vuln_file}"
            ecode, stdout, stderr = microvm.ssh.run(cmd)
            # grep returns 0 for a match and 1 for no match; any other code
            # indicates an error such as an unreadable file.
            if ecode == 0:
                findings.add(f"{vuln_file}: {stdout.strip()}")
            elif ecode != 1:
                pytest.fail(f"{vuln_file}: grep failed: {stderr.strip()}")
    return findings


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
        assert res_b.issubset(res_a), f"New vulnerability findings: {res_b - res_a}"
    else:
        assert not res_b, f"Unexpected vulnerability findings: {res_b}"


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
        assert res_b.issubset(res_a), f"New vulnerability findings: {res_b - res_a}"
    else:
        assert res_b == spectre_meltdown_checker.expected_vulnerabilities(
            uvm_any.cpu_template_name, uvm_any.guest_kernel_version
        )


# All Graviton generations (Neoverse N1/V1/V2/V3) are affected by erratum
# 3194386: SSBS writes are not self-synchronizing, so the kernel workaround
# adds a speculation barrier and hides the "ssbs" hwcap from userspace, which
# must request the mitigation via prctl(PR_SET_SPECULATION_CTRL) instead of
# toggling PSTATE.SSBS directly (this is why "ssbs" is absent from the
# expectations in test_cpu_features_aarch64.py).
# https://github.com/torvalds/linux/commit/adeec61a4723fd3e39da68db4cc4d924e6d7f641
#
# KVM passes the host MIDR through, so the guest kernel must detect the
# erratum itself, while still seeing SSBS hardware support via the ID
# registers KVM exposes.
@pytest.mark.skipif(
    global_props.cpu_architecture != "aarch64", reason="Only run in aarch64"
)
def test_spec_store_bypass_mitigated(uvm_booted):
    """Check the guest kernel applies the SSBS erratum 3194386 workaround."""
    dmesg = uvm_booted.ssh.check_output("dmesg").stdout
    # KVM exposed SSBS hardware support to the guest
    assert "Speculative Store Bypassing Safe (SSBS)" in dmesg
    # the guest detected erratum 3194386 via the passed-through MIDR
    assert "SSBS not fully self-synchronizing" in dmesg
