# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for hotplugging vCPUs"""

import re
import time

import pytest

from framework import microvm
from framework.defs import MAX_SUPPORTED_VCPUS
from framework.microvm import Serial
from framework.utils_cpuid import check_guest_cpuid_output


@pytest.mark.parametrize("vcpu_count", [1, MAX_SUPPORTED_VCPUS - 1])
def test_hotplug_vcpus(uvm_plain, vcpu_count):
    """Test hotplugging works as intended"""
    uvm_plain.jailer.extra_args.update({"no-seccomp": None})
    uvm_plain.spawn()
    uvm_plain.basic_config(vcpu_count=1, mem_size_mib=128)
    uvm_plain.add_net_iface()
    uvm_plain.start()

    # Need to allow time for VM to finish starting before API call is made
    time.sleep(0.5)

    uvm_plain.api.hotplug.put(Vcpu={"add": vcpu_count})

    check_guest_cpuid_output(
        uvm_plain,
        "lscpu",
        None,
        ":",
        {
            "CPU(s)": str(1 + vcpu_count),
            "Off-line CPU(s) list": "1" if vcpu_count == 1 else f"1-{vcpu_count}",
        },
    )


@pytest.mark.parametrize(
    "vcpu_count", [-1, 0, MAX_SUPPORTED_VCPUS, MAX_SUPPORTED_VCPUS + 1]
)
def test_negative_hotplug_vcpus(uvm_plain, vcpu_count):
    """Test cases where hotplugging should fail."""
    uvm_plain.jailer.extra_args.update({"no-seccomp": None})
    uvm_plain.spawn()
    uvm_plain.basic_config(vcpu_count=1, mem_size_mib=128)
    uvm_plain.start()

    # Need to allow time for VM to finish starting before API call is made
    time.sleep(0.5)

    if vcpu_count == 0:
        with pytest.raises(
            RuntimeError,
            match="Hotplug error: Vcpu hotplugging error: The number of vCPUs added must be greater than 0.",
        ):
            uvm_plain.api.hotplug.put(Vcpu={"add": vcpu_count})
    elif vcpu_count < 0:
        with pytest.raises(
            RuntimeError,
            match=re.compile(
                f"An error occurred when deserializing the json body of a request: invalid value: integer `-\\d+`, expected u8+"
            ),
        ):
            uvm_plain.api.hotplug.put(Vcpu={"add": vcpu_count})
    elif vcpu_count > 31:
        with pytest.raises(
            RuntimeError,
            match="Hotplug error: Vcpu hotplugging error: The number of vCPUs added must be less than 32.",
        ):
            uvm_plain.api.hotplug.put(Vcpu={"add": vcpu_count})


@pytest.mark.parametrize("vcpu_count", [1, MAX_SUPPORTED_VCPUS - 1])
def test_online_hotplugged_vcpus(uvm_plain, vcpu_count):
    """Test that hotplugged CPUs can be onlined"""
    uvm_plain.jailer.extra_args.update({"no-seccomp": None})
    uvm_plain.spawn()
    uvm_plain.basic_config(vcpu_count=1, mem_size_mib=128)
    uvm_plain.add_net_iface()
    uvm_plain.start()

    # Need to allow time for VM to finish starting before API call is made
    time.sleep(0.5)

    uvm_plain.api.hotplug.put(Vcpu={"add": vcpu_count})

    _, _, stderr = uvm_plain.ssh.run(
        f"for i in {{1..{vcpu_count}}}; do echo 1 > /sys/devices/system/cpu/cpu$i/online; done"
    )

    assert stderr == ""

    check_guest_cpuid_output(
        uvm_plain,
        "lscpu",
        None,
        ":",
        {
            "CPU(s)": str(1 + vcpu_count),
            "On-line CPU(s) list": "0,1" if vcpu_count == 1 else f"0-{vcpu_count}",
        },
    )
