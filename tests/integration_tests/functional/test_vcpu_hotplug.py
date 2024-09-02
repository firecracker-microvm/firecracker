# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for hotplugging vCPUs"""

import platform
import re
import time

import pytest

from framework.defs import MAX_SUPPORTED_VCPUS
from framework.utils_cpuid import check_guest_cpuid_output


@pytest.mark.skipif(
    platform.machine() != "x86_64", reason="Hotplug only enabled on x86_64."
)
@pytest.mark.parametrize("vcpu_count", [1, MAX_SUPPORTED_VCPUS - 1])
def test_hotplug_vcpus(microvm_factory, guest_kernel_linux_6_1, rootfs_rw, vcpu_count):
    """
    Test that hot-plugging API call functions as intended.

    After the API call has been made, the new vCPUs should show up in the
    guest as offline.
    """
    uvm_plain = microvm_factory.build(guest_kernel_linux_6_1, rootfs_rw)
    uvm_plain.jailer.extra_args.update({"no-seccomp": None})
    uvm_plain.spawn()
    uvm_plain.basic_config(vcpu_count=1, mem_size_mib=128)
    uvm_plain.add_net_iface()
    uvm_plain.start()
    uvm_plain.wait_for_up()

    # Default udev rules are flaky, sometimes they automatically online CPUs,
    # but other times they don't. Remove the respective rule in this test so
    # they are added as offline every time.
    uvm_plain.ssh.run(
        "rm /usr/lib/udev/rules.d/40-vm-hotadd.rules && udevadm control --reload-rules"
    )

    uvm_plain.api.hotplug.put(Vcpu={"add": vcpu_count})

    time.sleep(5)

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


@pytest.mark.skipif(
    platform.machine() != "x86_64", reason="Hotplug only enabled on x86_64."
)
@pytest.mark.parametrize(
    "vcpu_count", [-1, 0, MAX_SUPPORTED_VCPUS, MAX_SUPPORTED_VCPUS + 1]
)
def test_negative_hotplug_vcpus(
    microvm_factory, guest_kernel_linux_6_1, rootfs_rw, vcpu_count
):
    """
    Test that the API rejects invalid calls.

    Test cases where the API should reject the hot-plug request, where the
    number of vCPUs is either too high or too low.
    """
    uvm_plain = microvm_factory.build(guest_kernel_linux_6_1, rootfs_rw)
    uvm_plain.jailer.extra_args.update({"no-seccomp": None})
    uvm_plain.spawn()
    uvm_plain.basic_config(vcpu_count=1, mem_size_mib=128)
    uvm_plain.add_net_iface()
    uvm_plain.start()
    uvm_plain.wait_for_up()

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
                "An error occurred when deserializing the json body of a request: invalid value: integer `-\\d+`, expected u8+"
            ),
        ):
            uvm_plain.api.hotplug.put(Vcpu={"add": vcpu_count})
    elif vcpu_count > 31:
        with pytest.raises(
            RuntimeError,
            match="Hotplug error: Vcpu hotplugging error: The number of vCPUs added must be less than 32.",
        ):
            uvm_plain.api.hotplug.put(Vcpu={"add": vcpu_count})


@pytest.mark.skipif(
    platform.machine() != "x86_64", reason="Hotplug only enabled on x86_64."
)
@pytest.mark.parametrize("vcpu_count", [1, MAX_SUPPORTED_VCPUS - 1])
def test_online_hotplugged_vcpus(
    microvm_factory, guest_kernel_linux_6_1, rootfs_rw, vcpu_count
):
    """
    Full end-to-end test of vCPU hot-plugging.

    Makes API call and then tries to online vCPUs inside the guest.
    """
    uvm_plain = microvm_factory.build(guest_kernel_linux_6_1, rootfs_rw)
    uvm_plain.jailer.extra_args.update({"no-seccomp": None})
    uvm_plain.spawn()
    uvm_plain.basic_config(vcpu_count=1, mem_size_mib=128)
    uvm_plain.add_net_iface()
    uvm_plain.start()
    uvm_plain.wait_for_up()

    # Default udev rules are flaky, sometimes they automatically online CPUs,
    # but other times they don't. Remove default rule and add our own.
    uvm_plain.ssh.run("rm /usr/lib/udev/rules.d/40-vm-hotadd.rules")
    uvm_plain.ssh.scp_put(
        "host_tools/1-cpu-hotplug.rules", "/usr/lib/udev/rules.d/1-cpu-hotplug.rules"
    )
    uvm_plain.ssh.run("udevadm control --reload-rules")

    uvm_plain.api.hotplug.put(Vcpu={"add": vcpu_count})

    time.sleep(5)

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
