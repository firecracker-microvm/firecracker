# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for ensuring correctness of CPU and cache topology in the guest."""

import os
import platform
import json
from ast import literal_eval

import pytest
import framework.utils_cpuid as utils
import host_tools.network as net_tools

TOPOLOGY_STR = {1: "0", 2: "0,1", 16: "0-15"}
PLATFORM = platform.machine()


def _check_cpu_topology(test_microvm, expected_cpu_count,
                        expected_threads_per_core,
                        expected_cpus_list):
    expected_cpu_topology = {
        "CPU(s)": str(expected_cpu_count),
        "On-line CPU(s) list": expected_cpus_list,
        "Thread(s) per core": str(expected_threads_per_core),
        "Core(s) per socket": str(
            int(expected_cpu_count / expected_threads_per_core)),
        "Socket(s)": "1",
        "NUMA node(s)": "1"
    }

    utils.check_guest_cpuid_output(test_microvm, "lscpu", None, ':',
                                   expected_cpu_topology)


def _check_cache_topology_x86(test_microvm, num_vcpus_on_lvl_1_cache,
                              num_vcpus_on_lvl_3_cache):
    vm = test_microvm
    expected_lvl_1_str = '{} ({})'.format(hex(num_vcpus_on_lvl_1_cache),
                                          num_vcpus_on_lvl_1_cache)
    expected_lvl_3_str = '{} ({})'.format(hex(num_vcpus_on_lvl_3_cache),
                                          num_vcpus_on_lvl_3_cache)

    cpu_vendor = utils.get_cpu_vendor()
    if cpu_vendor == utils.CpuVendor.AMD:
        expected_level_1_topology = {
            "level": '0x1 (1)',
            "extra cores sharing this cache": expected_lvl_1_str
        }
        expected_level_3_topology = {
            "level": '0x3 (3)',
            "extra cores sharing this cache": expected_lvl_3_str
        }
    elif cpu_vendor == utils.CpuVendor.INTEL:
        expected_level_1_topology = {
            "cache level": '0x1 (1)',
            "extra threads sharing this cache": expected_lvl_1_str,
        }
        expected_level_3_topology = {
            "cache level": '0x3 (3)',
            "extra threads sharing this cache": expected_lvl_3_str,
        }

    utils.check_guest_cpuid_output(vm, "cpuid -1", "--- cache 0 ---", '=',
                                   expected_level_1_topology)
    utils.check_guest_cpuid_output(vm, "cpuid -1", "--- cache 1 ---", '=',
                                   expected_level_1_topology)
    utils.check_guest_cpuid_output(vm, "cpuid -1", "--- cache 2 ---", '=',
                                   expected_level_1_topology)
    utils.check_guest_cpuid_output(vm, "cpuid -1", "--- cache 3 ---", '=',
                                   expected_level_3_topology)


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

    path = "/sys/devices/system/cpu/"

    cache_files = ["level", "type", "size",
                   "coherency_line_size", "number_of_sets"]

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    _, stdout, stderr = ssh_connection.execute_command(
        "/usr/local/bin/get_cache_info.sh"
    )
    assert stderr.read() == ""

    guest_dict = json.loads(literal_eval(stdout.read().strip()))
    host_dict = {}
    for i in range(no_cpus):
        cpu_path = os.path.join(os.path.join(path, 'cpu{}'.format(i)), "cache")
        dirs = os.listdir(cpu_path)
        for cache_level in dirs:
            if "index" not in os.path.basename(cache_level):
                continue
            cache_path = os.path.join(cpu_path, cache_level)

            for cache_file in cache_files:
                absolute_cache_file = os.path.join(cache_path, cache_file)
                with open(absolute_cache_file, 'r', encoding='utf-8') as file:
                    host_val = file.readline().strip()
                    host_dict[str(absolute_cache_file)] = str(host_val)
    assert guest_dict == host_dict


@pytest.mark.skipif(
    PLATFORM != "x86_64",
    reason="Firecracker supports CPU topology only on x86_64."
)
@pytest.mark.parametrize(
    "num_vcpus",
    [1, 2, 16],
)
@pytest.mark.parametrize(
    "htt",
    [True, False],
)
def test_cpu_topology(test_microvm_with_api, network_config, num_vcpus, htt):
    """
    Check the CPU topology for a microvm with the specified config.

    @type: functional
    """
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config(vcpu_count=num_vcpus, smt=htt)
    _tap, _, _ = vm.ssh_network_config(network_config, '1')
    vm.start()

    _check_cpu_topology(vm, num_vcpus, 2 if htt and num_vcpus > 1 else 1,
                        TOPOLOGY_STR[num_vcpus])


@pytest.mark.parametrize(
    "num_vcpus",
    [1, 2, 16],
)
@pytest.mark.parametrize(
    "htt",
    [True, False],
)
def test_cache_topology(test_microvm_with_api, network_config, num_vcpus, htt):
    """
    Check the cache topology for a microvm with the specified config.

    @type: functional
    """
    if htt and PLATFORM == 'aarch64':
        pytest.skip("SMT is configurable only on x86.")
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config(vcpu_count=num_vcpus, smt=htt)
    _tap, _, _ = vm.ssh_network_config(network_config, '1')
    vm.start()
    if PLATFORM == "x86_64":
        _check_cache_topology_x86(vm, 1 if htt and num_vcpus > 1 else 0,
                                  num_vcpus - 1)
    elif PLATFORM == "aarch64":
        _check_cache_topology_arm(vm, num_vcpus)
    else:
        raise Exception("This test is not run on this platform!")
