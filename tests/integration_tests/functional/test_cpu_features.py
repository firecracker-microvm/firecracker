# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CPU topology emulation feature."""

import platform
import os
import re
import pytest
from framework.utils import CpuVendor, get_cpu_vendor
import host_tools.network as net_tools  # pylint: disable=import-error

PLATFORM = platform.machine()


def _check_guest_cmd_output(test_microvm, guest_cmd, expected_header,
                            expected_separator,
                            expected_key_value_store):
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    _, stdout, stderr = ssh_connection.execute_command(guest_cmd)

    assert stderr.read() == ''
    while True:
        line = stdout.readline()
        if line != '':
            # All the keys have been matched. Stop.
            if not expected_key_value_store:
                break

            # Try to match the header if needed.
            if expected_header not in (None, ''):
                if line.strip() == expected_header:
                    expected_header = None
                continue

            # See if any key matches.
            # We Use a try-catch block here since line.split() may fail.
            try:
                [key, value] = list(
                    map(lambda x: x.strip(), line.split(expected_separator)))
            except ValueError:
                continue

            if key in expected_key_value_store.keys():
                assert value == expected_key_value_store[key], \
                    "%s does not have the expected value" % key
                del expected_key_value_store[key]

        else:
            break

    assert not expected_key_value_store, \
        "some keys in dictionary have not been found in the output: %s" \
        % expected_key_value_store


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

    _check_guest_cmd_output(test_microvm, "lscpu", None, ':',
                            expected_cpu_topology)


def _check_cpu_features_x86(test_microvm, expected_cpu_count, expected_htt):
    expected_cpu_features = {
        "cpu count": '{} ({})'.format(hex(expected_cpu_count),
                                      expected_cpu_count),
        "CLFLUSH line size": "0x8 (8)",
        "hypervisor guest status": "true",
        "hyper-threading / multi-core supported": expected_htt
    }

    _check_guest_cmd_output(test_microvm, "cpuid -1", None, '=',
                            expected_cpu_features)


def _check_cpu_features_arm(test_microvm):
    expected_cpu_features = {
        "Flags": "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs",
    }

    _check_guest_cmd_output(test_microvm, "lscpu", None, ':',
                            expected_cpu_features)


def _check_cache_topology_x86(test_microvm, num_vcpus_on_lvl_1_cache,
                          num_vcpus_on_lvl_3_cache):
    expected_lvl_1_str = '{} ({})'.format(hex(num_vcpus_on_lvl_1_cache),
                                          num_vcpus_on_lvl_1_cache)
    expected_lvl_3_str = '{} ({})'.format(hex(num_vcpus_on_lvl_3_cache),
                                          num_vcpus_on_lvl_3_cache)

    cpu_vendor = get_cpu_vendor()
    if cpu_vendor == CpuVendor.AMD:
        expected_level_1_topology = {
            "level": '0x1 (1)',
            "extra cores sharing this cache": expected_lvl_1_str
        }
        expected_level_3_topology = {
            "level": '0x3 (3)',
            "extra cores sharing this cache": expected_lvl_3_str
        }
    elif cpu_vendor == CpuVendor.INTEL:
        expected_level_1_topology = {
            "cache level": '0x1 (1)',
            "extra threads sharing this cache": expected_lvl_1_str,
        }
        expected_level_3_topology = {
            "cache level": '0x3 (3)',
            "extra threads sharing this cache": expected_lvl_3_str,
        }

    _check_guest_cmd_output(test_microvm, "cpuid -1", "--- cache 0 ---", '=',
                            expected_level_1_topology)
    _check_guest_cmd_output(test_microvm, "cpuid -1", "--- cache 1 ---", '=',
                            expected_level_1_topology)
    _check_guest_cmd_output(test_microvm, "cpuid -1", "--- cache 2 ---", '=',
                            expected_level_1_topology)
    _check_guest_cmd_output(test_microvm, "cpuid -1", "--- cache 3 ---", '=',
                            expected_level_3_topology)


def _check_cache_topology_arm(no_cpus=1):
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
    cache_info = [{"level": "1", "size": "64K", "type": "Data"}, {"level": "1", "size": "64K", "type": "Instruction"},
    {"level": "2", "size": "1024K", "type": "Unified"}, {"level": "3", "size": "32768K", "type": "Unified"}]

    for i in range(no_cpus):
        cpu_path = os.path.join(os.path.join(path, 'cpu{}'.format(i)), "cache")
        index = 0

        for j in cache_info:
            cache_path = os.path.join(cpu_path, 'index{}'.format(index))
            cache_level_path = os.path.join(cache_path, 'level')
            cache_size_path = os.path.join(cache_path, 'size')
            cache_type_path = os.path.join(cache_path, 'type')
            with open(cache_level_path, 'r') as file:
                level = file.readline().strip()
                with open(cache_size_path, 'r') as file:
                    size = file.readline().strip()
                    with open(cache_type_path, 'r') as file:
                        type = file.readline().strip()
                assert j["level"] == level
                assert j["type"] == type
                assert j["size"] == size

            index = index + 1


def test_1vcpu_ht_disabled(test_microvm_with_ssh, network_config):
    """Check the CPUID for a microvm with the specified config."""
    test_microvm_with_ssh.spawn()
    test_microvm_with_ssh.basic_config(vcpu_count=1, ht_enabled=False)
    _tap, _, _ = test_microvm_with_ssh.ssh_network_config(network_config, '1')
    test_microvm_with_ssh.start()

    _check_cpu_topology(test_microvm_with_ssh, 1, 1, "0")
    if PLATFORM == "x86_64":
        _check_cpu_features_x86(test_microvm_with_ssh, 1, "false")
        _check_cache_topology_x86(test_microvm_with_ssh, 0, 0)
    else:
        _check_cpu_features_arm(test_microvm_with_ssh)
        _check_cache_topology_arm()


def test_1vcpu_ht_enabled(test_microvm_with_ssh, network_config):
    """Check the CPUID for a microvm with the specified config."""
    test_microvm_with_ssh.spawn()
    test_microvm_with_ssh.basic_config(vcpu_count=1, ht_enabled=True)
    _tap, _, _ = test_microvm_with_ssh.ssh_network_config(network_config, '1')
    test_microvm_with_ssh.start()

    _check_cpu_topology(test_microvm_with_ssh, 1, 1, "0")
    if PLATFORM == "x86_64":
        _check_cpu_features_x86(test_microvm_with_ssh, 1, "false")
        _check_cache_topology_x86(test_microvm_with_ssh, 0, 0)
    else:
        _check_cache_topology_arm()


def test_2vcpu_ht_disabled(test_microvm_with_ssh, network_config):
    """Check the CPUID for a microvm with the specified config."""
    test_microvm_with_ssh.spawn()
    test_microvm_with_ssh.basic_config(vcpu_count=2, ht_enabled=False)
    _tap, _, _ = test_microvm_with_ssh.ssh_network_config(network_config, '1')
    test_microvm_with_ssh.start()

    _check_cpu_topology(test_microvm_with_ssh, 2, 1, "0,1")
    if PLATFORM == "x86_64":
        _check_cpu_features_x86(test_microvm_with_ssh, 2, "true")
        _check_cache_topology_x86(test_microvm_with_ssh, 0, 1)
    else:
        _check_cache_topology_arm(2)


def test_2vcpu_ht_enabled(test_microvm_with_ssh, network_config):
    """Check the CPUID for a microvm with the specified config."""
    test_microvm_with_ssh.spawn()
    test_microvm_with_ssh.basic_config(vcpu_count=2, ht_enabled=True)
    _tap, _, _ = test_microvm_with_ssh.ssh_network_config(network_config, '1')
    test_microvm_with_ssh.start()

    _check_cpu_topology(test_microvm_with_ssh, 2, 2, "0,1")
    if PLATFORM == "x86_64":
        _check_cpu_features_x86(test_microvm_with_ssh, 2, "true")
        _check_cache_topology_x86(test_microvm_with_ssh, 1, 1)
    else:
        _check_cache_topology_arm(2)


def test_16vcpu_ht_disabled(test_microvm_with_ssh, network_config):
    """Check the CPUID for a microvm with the specified config."""
    test_microvm_with_ssh.spawn()
    test_microvm_with_ssh.basic_config(vcpu_count=16, ht_enabled=False)
    _tap, _, _ = test_microvm_with_ssh.ssh_network_config(network_config, '1')
    test_microvm_with_ssh.start()

    _check_cpu_topology(test_microvm_with_ssh, 16, 1, "0-15")
    if PLATFORM == "x86_64":
        _check_cpu_features_x86(test_microvm_with_ssh, 16, "true")
        _check_cache_topology_x86(test_microvm_with_ssh, 0, 15)
    else:
        _check_cache_topology_arm(16)


def test_16vcpu_ht_enabled(test_microvm_with_ssh, network_config):
    """Check the CPUID for a microvm with the specified config."""
    test_microvm_with_ssh.spawn()
    test_microvm_with_ssh.basic_config(vcpu_count=16, ht_enabled=True)
    _tap, _, _ = test_microvm_with_ssh.ssh_network_config(network_config, '1')
    test_microvm_with_ssh.start()

    _check_cpu_topology(test_microvm_with_ssh, 16, 2, "0-15")
    if PLATFORM == "x86_64":
        _check_cpu_features_x86(test_microvm_with_ssh, 16, "true")
        _check_cache_topology_x86(test_microvm_with_ssh, 1, 15)
    else:
        _check_cache_topology_arm(16)


@pytest.mark.skipif(
    PLATFORM != "x86_64",
    reason="The CPU brand string is masked only on x86_64."
)
def test_brand_string(test_microvm_with_ssh, network_config):
    """Ensure good formatting for the guest band string.

    * For Intel CPUs, the guest brand string should be:
        Intel(R) Xeon(R) Processor @ {host frequency}
    where {host frequency} is the frequency reported by the host CPUID
    (e.g. 4.01GHz)
    * For AMD CPUs, the guest brand string should be:
        AMD EPYC
    * For other CPUs, the guest brand string should be:
        ""
    """
    cif = open('/proc/cpuinfo', 'r')
    host_brand_string = None
    while True:
        line = cif.readline()
        if line == '':
            break
        mo = re.search("^model name\\s+:\\s+(.+)$", line)
        if mo:
            host_brand_string = mo.group(1)
    cif.close()
    assert host_brand_string is not None

    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    test_microvm.basic_config(vcpu_count=1)
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    guest_cmd = "cat /proc/cpuinfo | grep 'model name' | head -1"
    _, stdout, stderr = ssh_connection.execute_command(guest_cmd)
    assert stderr.read() == ''

    line = stdout.readline().rstrip()
    mo = re.search("^model name\\s+:\\s+(.+)$", line)
    assert mo
    guest_brand_string = mo.group(1)
    assert guest_brand_string

    cpu_vendor = get_cpu_vendor()
    expected_guest_brand_string = ""
    if cpu_vendor == CpuVendor.AMD:
        expected_guest_brand_string += "AMD EPYC"
    elif cpu_vendor == CpuVendor.INTEL:
        expected_guest_brand_string = "Intel(R) Xeon(R) Processor"
        mo = re.search("[.0-9]+[MG]Hz", host_brand_string)
        if mo:
            expected_guest_brand_string += " @ " + mo.group(0)

    assert guest_brand_string == expected_guest_brand_string


@pytest.mark.skipif(
    PLATFORM != "x86_64",
    reason="CPU features are masked only on x86_64."
)
@pytest.mark.parametrize("cpu_template", ["T2", "C3"])
def test_cpu_template(test_microvm_with_ssh, network_config, cpu_template):
    """Check that AVX2 & AVX512 instructions are disabled.

    This is a rather dummy test for checking that some features are not
    exposed by mistake. It is a first step into checking the t2 & c3
    templates. In a next iteration we should check **all** cpuid entries, not
    just these features. We can achieve this with a template
    containing all features on a t2/c3 instance and check that the cpuid in
    the guest is an exact match of the template.
    """
    common_masked_features = ["avx512", "mpx", "clflushopt", "clwb", "xsavec",
                              "xgetbv1", "xsaves", "pku", "ospke"]
    c3_masked_features = ["avx2"]

    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    test_microvm.basic_config(vcpu_count=1)
    # Set template as specified in the `cpu_template` parameter.
    response = test_microvm.machine_cfg.put(
        vcpu_count=1,
        mem_size_mib=256,
        ht_enabled=False,
        cpu_template=cpu_template,
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')

    response = test_microvm.actions.put(action_type='InstanceStart')
    if get_cpu_vendor() != CpuVendor.INTEL:
        # We shouldn't be able to apply Intel templates on AMD hosts
        assert test_microvm.api_session.is_status_bad_request(
            response.status_code)
        return

    assert test_microvm.api_session.is_status_no_content(
            response.status_code)

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    guest_cmd = "cat /proc/cpuinfo | grep 'flags' | head -1"
    _, stdout, stderr = ssh_connection.execute_command(guest_cmd)
    assert stderr.read() == ''

    cpu_flags_output = stdout.readline().rstrip()

    if cpu_template == "C3":
        for feature in c3_masked_features:
            assert feature not in cpu_flags_output
    # Check that all features in `common_masked_features` are properly masked.
    for feature in common_masked_features:
        assert feature not in cpu_flags_output
