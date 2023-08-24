# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for ensuring correctness of CPU and cache topology in the guest."""

import platform
import subprocess

import pytest

import framework.utils_cpuid as utils

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


def _check_cache_topology_x86(
    test_microvm, num_vcpus_on_lvl_1_cache, num_vcpus_on_lvl_3_cache
):
    vm = test_microvm
    expected_lvl_1_str = "{} ({})".format(
        hex(num_vcpus_on_lvl_1_cache), num_vcpus_on_lvl_1_cache
    )
    expected_lvl_3_str = "{} ({})".format(
        hex(num_vcpus_on_lvl_3_cache), num_vcpus_on_lvl_3_cache
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


def _check_cache_topology_arm(test_microvm, no_cpus):
    # We will check the cache topology by looking at what each cpu
    # contains as far as cache info.
    # For that we are iterating through the hierarchy of folders inside:
    # /sys/devices/system/cpu/cpuX/cache/indexY/type - the type of the cache
    # (i.e Instruction, Data, Unified)
    # /sys/devices/system/cpu/cpuX/cache/indexY/size - size of the cache
    # /sys/devices/system/cpu/cpuX/cache/indexY/level - L1, L2 or L3 cache.
    # There are 2 types of L1 cache (instruction and data) that is why the
    # "cache_info" variable below has 4 items.

    sys_cpu = "/sys/devices/system/cpu"
    fields = ["level", "type", "size", "coherency_line_size", "number_of_sets"]

    cmd = f"grep . {sys_cpu}/cpu{{0..{no_cpus-1}}}/cache/index*/{{{','.join(fields)}}} |sort"

    _, guest_stdout, guest_stderr = test_microvm.ssh.run(cmd)
    assert guest_stderr == ""

    res = subprocess.run(
        cmd,
        shell=True,
        executable="/bin/bash",
        capture_output=True,
        check=True,
        encoding="ascii",
    )
    assert res.stderr == ""
    assert res.stdout == guest_stdout


@pytest.mark.skipif(
    PLATFORM != "x86_64", reason="Firecracker supports CPU topology only on x86_64."
)
@pytest.mark.parametrize("num_vcpus", [1, 2, 16])
@pytest.mark.parametrize("htt", [True, False])
def test_cpu_topology(test_microvm_with_api, num_vcpus, htt):
    """
    Check the CPU topology for a microvm with the specified config.
    """
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config(vcpu_count=num_vcpus, smt=htt)
    vm.add_net_iface()
    vm.start()

    _check_cpu_topology(
        vm, num_vcpus, 2 if htt and num_vcpus > 1 else 1, TOPOLOGY_STR[num_vcpus]
    )


@pytest.mark.parametrize("num_vcpus", [1, 2, 16])
@pytest.mark.parametrize("htt", [True, False])
def test_cache_topology(test_microvm_with_api, num_vcpus, htt):
    """
    Check the cache topology for a microvm with the specified config.
    """
    if htt and PLATFORM == "aarch64":
        pytest.skip("SMT is configurable only on x86.")
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config(vcpu_count=num_vcpus, smt=htt)
    vm.add_net_iface()
    vm.start()
    if PLATFORM == "x86_64":
        _check_cache_topology_x86(vm, 1 if htt and num_vcpus > 1 else 0, num_vcpus - 1)
    elif PLATFORM == "aarch64":
        _check_cache_topology_arm(vm, num_vcpus)
    else:
        raise Exception("This test is not run on this platform!")
