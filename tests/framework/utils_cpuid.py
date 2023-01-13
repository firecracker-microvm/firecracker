# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helper functions for testing CPU identification functionality."""

import platform
import subprocess
import re
from enum import Enum, auto

from framework.utils import run_cmd
from framework.utils_imdsv2 import imdsv2_get

ARM_CPU_DICT = {"0xd0c": "ARM_NEOVERSE_N1", "0xd40": "ARM_NEOVERSE_V1"}


class CpuVendor(Enum):
    """CPU vendors enum."""

    AMD = auto()
    INTEL = auto()
    ARM = auto()


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
        _, stdout, _ = run_cmd("cat /proc/cpuinfo | grep 'CPU part' | uniq")
    else:
        _, stdout, _ = run_cmd("cat /proc/cpuinfo | grep 'model name' | uniq")
    info = stdout.strip().split(sep=":")
    assert len(info) == 2
    raw_cpu_model = info[1].strip()
    if platform.machine() == "x86_64":
        return raw_cpu_model
    return ARM_CPU_DICT[raw_cpu_model]


def get_instance_type():
    """Get the instance type through IMDSv2"""
    return imdsv2_get("/meta-data/instance-type")


def check_guest_cpuid_output(
    vm, guest_cmd, expected_header, expected_separator, expected_key_value_store
):
    """Parse cpuid output inside guest and match with expected one."""
    _, stdout, stderr = vm.ssh.execute_command(guest_cmd)

    assert stderr.read() == ""
    while True:
        line = stdout.readline()
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
                for given_key in expected_key_value_store.keys():
                    if given_key in key:
                        assert value == expected_key_value_store[given_key], (
                            "%s does not have the expected value" % given_key
                        )
                        del expected_key_value_store[given_key]
                        break
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
    for line in raw_cpuid_output:
        match = re.match(ptrn, line)
        assert match, f"`{line}` does not match the regex pattern."
        leaf, subleaf, eax, ebx, ecx, edx = [int(x, 16) for x in match.groups()]
        cpuid_dict[(leaf, subleaf, "eax")] = eax
        cpuid_dict[(leaf, subleaf, "ebx")] = ebx
        cpuid_dict[(leaf, subleaf, "ecx")] = ecx
        cpuid_dict[(leaf, subleaf, "edx")] = edx
    return cpuid_dict


def get_guest_cpuid(vm):
    """
    Return the guest CPUID in the form of a dictionary where the key is a tuple:
     - leaf (integer)
     - subleaf (integer)
     - register ("eax", "ebx", "ecx" or "edx")
    and the value is the register value (integer).
    """
    read_cpuid_cmd = "cpuid -1 --raw | grep -v CPU"
    _, stdout, stderr = vm.ssh.execute_command(read_cpuid_cmd)
    assert stderr.read() == ""

    return build_cpuid_dict(stdout)
