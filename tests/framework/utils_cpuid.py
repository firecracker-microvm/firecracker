# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helper functions for testing CPU identification functionality."""

import platform
import re
import subprocess
from enum import Enum, auto

from framework.utils import check_output
from framework.utils_imdsv2 import imdsv2_get


class CpuVendor(Enum):
    """CPU vendors enum."""

    AMD = auto()
    INTEL = auto()
    ARM = auto()


class CpuModel(str, Enum):
    """CPU models"""

    AMD_MILAN = "AMD_MILAN"
    ARM_NEOVERSE_N1 = "ARM_NEOVERSE_N1"
    ARM_NEOVERSE_V1 = "ARM_NEOVERSE_V1"
    INTEL_SKYLAKE = "INTEL_SKYLAKE"
    INTEL_CASCADELAKE = "INTEL_CASCADELAKE"
    INTEL_ICELAKE = "INTEL_ICELAKE"


CPU_DICT = {
    CpuVendor.INTEL: {
        "Intel(R) Xeon(R) Platinum 8175M CPU": "INTEL_SKYLAKE",
        "Intel(R) Xeon(R) Platinum 8124M CPU": "INTEL_SKYLAKE",
        "Intel(R) Xeon(R) Platinum 8259CL CPU": "INTEL_CASCADELAKE",
        "Intel(R) Xeon(R) Platinum 8375C CPU": "INTEL_ICELAKE",
    },
    CpuVendor.AMD: {
        "AMD EPYC 7R13": "AMD_MILAN",
    },
    CpuVendor.ARM: {"0xd0c": "ARM_NEOVERSE_N1", "0xd40": "ARM_NEOVERSE_V1"},
}


def get_cpu_vendor():
    """Return the CPU vendor."""
    brand_str = subprocess.check_output("lscpu", shell=True).strip().decode()
    machine_str = platform.machine()
    if "AuthenticAMD" in brand_str:
        return CpuVendor.AMD
    if "aarch64" in machine_str:
        return CpuVendor.ARM
    return CpuVendor.INTEL


def get_cpu_model_name():
    """Return the CPU model name."""
    if platform.machine() == "aarch64":
        _, stdout, _ = check_output("cat /proc/cpuinfo | grep 'CPU part' | uniq")
    else:
        _, stdout, _ = check_output("cat /proc/cpuinfo | grep 'model name' | uniq")
    info = stdout.strip().split(sep=":")
    assert len(info) == 2
    raw_cpu_model = info[1].strip()
    if platform.machine() == "x86_64":
        return raw_cpu_model
    return CPU_DICT[CpuVendor.ARM].get(raw_cpu_model, "Unknown")


def get_cpu_codename(default="Unknown"):
    """Return the CPU codename."""
    cpu_model = get_cpu_model_name()
    vendor = get_cpu_vendor()
    if vendor == CpuVendor.INTEL:
        result = re.match(r"^(.*) @.*$", cpu_model)
        if result:
            return CPU_DICT[CpuVendor.INTEL].get(result.group(1), default)
    if vendor == CpuVendor.AMD:
        result = re.match(r"^(.*) [0-9]*-Core Processor$", cpu_model)
        if result:
            return CPU_DICT[CpuVendor.AMD].get(result.group(1), default)
    if vendor == CpuVendor.ARM:
        return cpu_model
    return default


def get_instance_type():
    """Get the instance type through IMDSv2"""
    return imdsv2_get("/meta-data/instance-type")


def check_guest_cpuid_output(
    vm, guest_cmd, expected_header, expected_separator, expected_key_value_store
):
    """Parse cpuid output inside guest and match with expected one."""
    _, stdout, stderr = vm.ssh.run(guest_cmd)

    assert stderr == ""
    for line in stdout.split("\n"):
        if line != "":
            # All the keys have been matched. Stop.
            if not expected_key_value_store:
                break

            # Try to match the header if needed.
            if expected_header not in (None, ""):
                if line.strip() == expected_header:
                    expected_header = None
                continue

            # See if any key matches.
            # We Use a try-catch block here since line.split() may fail.
            try:
                [key, value] = list(
                    map(lambda x: x.strip(), line.split(expected_separator))
                )
            except ValueError:
                continue

            if key in expected_key_value_store.keys():
                assert value == expected_key_value_store[key], (
                    "%s does not have the expected value" % key
                )
                del expected_key_value_store[key]
        else:
            break

    assert not expected_key_value_store, (
        "some keys in dictionary have not been found in the output: %s"
        % expected_key_value_store
    )


def build_cpuid_dict(raw_cpuid_output):
    """Build CPUID dict based on raw cpuid output"""
    cpuid_dict = {}
    ptrn = re.compile("^ *(.*) (.*): eax=(.*) ebx=(.*) ecx=(.*) edx=(.*)$")
    for line in raw_cpuid_output.strip().split("\n"):
        match = re.match(ptrn, line)
        assert match, f"`{line}` does not match the regex pattern."
        leaf, subleaf, eax, ebx, ecx, edx = [int(x, 16) for x in match.groups()]
        cpuid_dict[(leaf, subleaf, "eax")] = eax
        cpuid_dict[(leaf, subleaf, "ebx")] = ebx
        cpuid_dict[(leaf, subleaf, "ecx")] = ecx
        cpuid_dict[(leaf, subleaf, "edx")] = edx
    return cpuid_dict


def get_guest_cpuid(vm, leaf=None, subleaf=None):
    """
    Return the guest CPUID of CPU 0 in the form of a dictionary where the key
    is a tuple:
     - leaf (integer)
     - subleaf (integer)
     - register ("eax", "ebx", "ecx" or "edx")
    and the value is the register value (integer).
    """
    if leaf is not None and subleaf is not None:
        read_cpuid_cmd = f"cpuid -r -l {leaf} -s {subleaf} | head -n 2 | grep -v CPU"
    else:
        read_cpuid_cmd = "cpuid -r | sed '/CPU 1/q' | grep -v CPU"
    _, stdout, stderr = vm.ssh.run(read_cpuid_cmd)
    assert stderr == ""

    return build_cpuid_dict(stdout)


def check_cpuid_feat_flags(vm, must_be_set, must_be_unset):
    """
    Check that CPUID feature flag are set and unset as expected.
    """
    cpuid = get_guest_cpuid(vm)
    allowed_regs = ["eax", "ebx", "ecx", "edx"]

    for leaf, subleaf, reg, flags in must_be_set:
        assert reg in allowed_regs
        actual = cpuid[(leaf, subleaf, reg)] & flags
        expected = flags
        assert (
            actual == expected
        ), f"{leaf=:#x} {subleaf=:#x} {reg=} {actual=:#x}, {expected=:#x}"

    for leaf, subleaf, reg, flags in must_be_unset:
        assert reg in allowed_regs
        actual = cpuid[(leaf, subleaf, reg)] & flags
        expected = 0
        assert (
            actual == expected
        ), f"{leaf=:#x} {subleaf=:#x} {reg=} {actual=:#x}, {expected=:#x}"
