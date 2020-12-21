# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CPU topology emulation feature."""

import platform
import re
import pytest

import framework.utils_cpuid as utils
import host_tools.network as net_tools

PLATFORM = platform.machine()


def _check_cpuid_x86(test_microvm, expected_cpu_count, expected_htt):
    expected_cpu_features = {
        "cpu count": '{} ({})'.format(hex(expected_cpu_count),
                                      expected_cpu_count),
        "CLFLUSH line size": "0x8 (8)",
        "hypervisor guest status": "true",
        "hyper-threading / multi-core supported": expected_htt
    }

    utils.check_guest_cpuid_output(test_microvm, "cpuid -1", None, '=',
                                   expected_cpu_features)


def _check_cpu_features_arm(test_microvm):
    expected_cpu_features = {
        "Flags": "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
                 "asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs",
    }

    utils.check_guest_cpuid_output(test_microvm, "lscpu", None, ':',
                                   expected_cpu_features)


@pytest.mark.skipif(
    PLATFORM != "x86_64",
    reason="CPUID is only supported on x86_64."
)
@pytest.mark.parametrize(
    "num_vcpus",
    [1, 2, 16],
)
@pytest.mark.parametrize(
    "htt",
    [True, False],
)
def test_cpuid(test_microvm_with_ssh, network_config, num_vcpus, htt):
    """Check the CPUID for a microvm with the specified config."""
    vm = test_microvm_with_ssh
    vm.spawn()
    vm.basic_config(vcpu_count=num_vcpus, ht_enabled=htt)
    _tap, _, _ = vm.ssh_network_config(network_config, '1')
    vm.start()
    _check_cpuid_x86(vm, num_vcpus, "true" if num_vcpus > 1 else "false")


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="The CPU features on x86 are tested as part of the CPU templates."
)
def test_cpu_features(test_microvm_with_ssh, network_config):
    """Check the CPU features for a microvm with the specified config."""
    vm = test_microvm_with_ssh
    vm.spawn()
    vm.basic_config()
    _tap, _, _ = vm.ssh_network_config(network_config, '1')
    vm.start()
    _check_cpu_features_arm(vm)


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

    cpu_vendor = utils.get_cpu_vendor()
    expected_guest_brand_string = ""
    if cpu_vendor == utils.CpuVendor.AMD:
        expected_guest_brand_string += "AMD EPYC"
    elif cpu_vendor == utils.CpuVendor.INTEL:
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
    if utils.get_cpu_vendor() != utils.CpuVendor.INTEL:
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

    # Check if XSAVE PKRU is masked for T3/C2.
    expected_cpu_features = {
        "XCR0 supported: PKRU state": "false"
    }

    utils.check_guest_cpuid_output(test_microvm, "cpuid -1", None, '=',
                                   expected_cpu_features)
