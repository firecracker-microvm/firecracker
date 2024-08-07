# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for ensuring correctness of CPU and cache topology in the guest."""

import platform
import subprocess

import pytest

import framework.utils_cpuid as utils
from framework.defs import MAX_SUPPORTED_VCPUS
from framework.properties import global_props

TOPOLOGY_STR = {1: "0", 2: "0,1", 16: "0-15"}
PLATFORM = platform.machine()


def _check_cpu_topology(
    test_microvm, expected_cpu_count, expected_threads_per_core, expected_cpus_list
):
    expected_cpu_topology = {
        "CPU(s)": str(expected_cpu_count),
        "On-line CPU(s) list": expected_cpus_list,
        "Thread(s) per core": str(expected_threads_per_core),
        "Core(s) per socket": str(int(expected_cpu_count / expected_threads_per_core)),
        "Socket(s)": "1",
        "NUMA node(s)": "1",
    }

    utils.check_guest_cpuid_output(
        test_microvm, "lscpu", None, ":", expected_cpu_topology
    )


def _check_cache_topology_x86(test_microvm, num_vcpus_on_lvl_1_cache):
    vm = test_microvm
    expected_lvl_1_str = "{} ({})".format(
        hex(num_vcpus_on_lvl_1_cache), num_vcpus_on_lvl_1_cache
    )
    expected_lvl_3_str = "{} ({})".format(
        hex(MAX_SUPPORTED_VCPUS - 1), MAX_SUPPORTED_VCPUS - 1
    )

    cpu_vendor = utils.get_cpu_vendor()
    if cpu_vendor == utils.CpuVendor.AMD:
        key_share = "extra cores sharing this cache"
        expected_level_1_topology = {
            "level": "0x1 (1)",
            key_share: expected_lvl_1_str,
        }
        expected_level_3_topology = {
            "level": "0x3 (3)",
            key_share: expected_lvl_3_str,
        }
    elif cpu_vendor == utils.CpuVendor.INTEL:
        key_share = "maximum IDs for CPUs sharing cache"
        expected_level_1_topology = {
            "cache level": "0x1 (1)",
            key_share: expected_lvl_1_str,
        }
        expected_level_3_topology = {
            "cache level": "0x3 (3)",
            key_share: expected_lvl_3_str,
        }

    utils.check_guest_cpuid_output(
        vm, "cpuid -1", "--- cache 0 ---", "=", expected_level_1_topology
    )
    utils.check_guest_cpuid_output(
        vm, "cpuid -1", "--- cache 1 ---", "=", expected_level_1_topology
    )
    utils.check_guest_cpuid_output(
        vm, "cpuid -1", "--- cache 2 ---", "=", expected_level_1_topology
    )
    utils.check_guest_cpuid_output(
        vm, "cpuid -1", "--- cache 3 ---", "=", expected_level_3_topology
    )


def _aarch64_parse_cache_info(test_microvm, no_cpus):
    def parse_cache_info(info: str):
        "One line looks like this: /sys/devices/system/cpu/cpuX/cache/{index}/{name}:{value}"
        cache_info = []
        for line in info.splitlines():
            parts = line.split("/")

            index = int(parts[-2][-1])

            name, value = parts[-1].split(":")

            if len(cache_info) == index:
                cache_info.append({})
            cache_info[index][name] = value
        return cache_info

    # We will check the cache topology by looking at what each cpu
    # contains as far as cache info.
    # For that we are iterating through the hierarchy of folders inside:
    # /sys/devices/system/cpu/cpuX/cache/indexY/type - the type of the cache
    # (i.e Instruction, Data, Unified)
    # /sys/devices/system/cpu/cpuX/cache/indexY/size - size of the cache
    # /sys/devices/system/cpu/cpuX/cache/indexY/level - L1, L2 or L3 cache.
    fields = ["level", "type", "size", "coherency_line_size", "number_of_sets"]
    cmd = f"grep . /sys/devices/system/cpu/cpu{{0..{no_cpus-1}}}/cache/index*/{{{','.join(fields)}}} |sort"

    _, guest_stdout, guest_stderr = test_microvm.ssh.run(cmd)
    assert guest_stderr == ""

    host_result = subprocess.run(
        cmd,
        shell=True,
        executable="/bin/bash",
        capture_output=True,
        check=True,
        encoding="ascii",
    )
    assert host_result.stderr == ""
    host_stdout = host_result.stdout

    guest_cache_info = parse_cache_info(guest_stdout)
    host_cache_info = parse_cache_info(host_stdout)

    return guest_cache_info, host_cache_info


def _check_cache_topology_arm(test_microvm, no_cpus, kernel_version_tpl):
    guest_cache_info, host_cache_info = _aarch64_parse_cache_info(test_microvm, no_cpus)

    # Starting from 6.3 kernel cache representation for aarch64 platform has changed.
    # It is no longer equivalent to the host cache representation.
    # The main change is in the level 1 cache, so for newer kernels we
    # compare only level 2 and level 3 caches
    if kernel_version_tpl < (6, 3):
        assert guest_cache_info == host_cache_info
    else:
        guest_first_non_level_1 = 0
        while guest_cache_info[guest_first_non_level_1]["level"] == "1":
            guest_first_non_level_1 += 1
        guest_slice = guest_cache_info[guest_first_non_level_1:]

        host_first_non_level_1 = 0
        while host_cache_info[host_first_non_level_1]["level"] == "1":
            host_first_non_level_1 += 1
        host_slice = host_cache_info[host_first_non_level_1:]

        assert guest_slice == host_slice


@pytest.mark.skipif(
    PLATFORM != "x86_64", reason="Firecracker supports CPU topology only on x86_64."
)
@pytest.mark.parametrize("num_vcpus", [1, 2, 16])
@pytest.mark.parametrize("htt", [True, False])
def test_cpu_topology(uvm_plain_any, num_vcpus, htt):
    """
    Check the CPU topology for a microvm with the specified config.
    """
    vm = uvm_plain_any
    vm.spawn()
    vm.basic_config(vcpu_count=num_vcpus, smt=htt)
    vm.add_net_iface()
    vm.start()

    _check_cpu_topology(
        vm, num_vcpus, 2 if htt and num_vcpus > 1 else 1, TOPOLOGY_STR[num_vcpus]
    )


@pytest.mark.parametrize("num_vcpus", [1, 2, 16])
@pytest.mark.parametrize("htt", [True, False])
def test_cache_topology(uvm_plain_any, num_vcpus, htt):
    """
    Check the cache topology for a microvm with the specified config.
    """
    if htt and PLATFORM == "aarch64":
        pytest.skip("SMT is configurable only on x86.")
    vm = uvm_plain_any
    vm.spawn()
    vm.basic_config(vcpu_count=num_vcpus, smt=htt)
    vm.add_net_iface()
    vm.start()
    if PLATFORM == "x86_64":
        _check_cache_topology_x86(vm, 1 if htt and num_vcpus > 1 else 0)
    elif PLATFORM == "aarch64":
        _check_cache_topology_arm(vm, num_vcpus, global_props.host_linux_version_tpl)
    else:
        raise Exception("This test is not run on this platform!")
