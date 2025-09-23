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

from framework import utils
from framework.ab_test import git_clone
from framework.microvm import MicroVMFactory
from framework.properties import global_props

CHECKER_URL = "https://raw.githubusercontent.com/speed47/spectre-meltdown-checker/master/spectre-meltdown-checker.sh"
CHECKER_FILENAME = "spectre-meltdown-checker.sh"
REMOTE_CHECKER_PATH = f"/tmp/{CHECKER_FILENAME}"
REMOTE_CHECKER_COMMAND = f"sh {REMOTE_CHECKER_PATH} --no-intel-db --batch json"

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

    def expected_vulnerabilities(self, cpu_template_name):
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
@pytest.mark.skipif(
    global_props.buildkite_pr,
    reason="Test depends solely on factors external to GitHub repository",
)
def test_spectre_meltdown_checker_on_host(spectre_meltdown_checker):
    """Test with the spectre / meltdown checker on host."""
    report = spectre_meltdown_checker.get_report_for_host()
    assert report == set(), f"Unexpected vulnerabilities: {report}"


# Nothing can be sensibly tested here in a PR context
@pytest.mark.skipif(
    global_props.buildkite_pr,
    reason="Test depends solely on factors external to GitHub repository",
)
def test_vulnerabilities_on_host():
    """Test vulnerability files on host."""
    res = utils.run_cmd(f"grep -r Vulnerable {VULN_DIR}")
    # if grep finds no matching lines, it exits with status 1
    assert res.returncode == 1, res.stdout


def get_vuln_files_exception_dict(template):
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
        exception_dict["mmio_stale_data"] = "Clear CPU buffers"

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
    exceptions = get_vuln_files_exception_dict(template)
    results = []
    for vuln_file in vuln_files:
        filename = Path(vuln_file).name
        if filename in exceptions:
            _, stdout, _ = microvm.ssh.check_output(f"cat {vuln_file}")
            assert exceptions[filename] in stdout
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
def uvm_any_a(microvm_factory_a, uvm_ctor, guest_kernel, rootfs, cpu_template_any):
    """Return uvm with revision A firecracker

    Since pytest caches fixtures, this guarantees uvm_any_a will match a vm from uvm_any.
    See https://docs.pytest.org/en/stable/how-to/fixtures.html#fixtures-can-be-requested-more-than-once-per-test-return-values-are-cached
    """
    return uvm_ctor(microvm_factory_a, guest_kernel, rootfs, cpu_template_any, False)


def test_check_vulnerability_files_ab(request, uvm_any_without_pci):
    """Test vulnerability files on guests"""
    res_b = check_vulnerabilities_files_on_guest(uvm_any_without_pci)
    if global_props.buildkite_pr:
        # we only get the uvm_any_a fixtures if we need it
        uvm_a = request.getfixturevalue("uvm_any_a")
        res_a = check_vulnerabilities_files_on_guest(uvm_a)
        assert res_b <= res_a
    else:
        assert not [x for x in res_b if "Vulnerable" in x["stdout"]]


def test_spectre_meltdown_checker_on_guest(
    request,
    uvm_any_without_pci,
    spectre_meltdown_checker,
):
    """Test with the spectre / meltdown checker on any supported guest."""
    res_b = spectre_meltdown_checker.get_report_for_guest(uvm_any_without_pci)
    if global_props.buildkite_pr:
        # we only get the uvm_any_a fixtures if we need it
        uvm_a = request.getfixturevalue("uvm_any_a")
        res_a = spectre_meltdown_checker.get_report_for_guest(uvm_a)
        assert res_b <= res_a
    else:
        assert res_b == spectre_meltdown_checker.expected_vulnerabilities(
            uvm_any_without_pci.cpu_template_name
        )
