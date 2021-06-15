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
    check_masked_features(test_microvm, cpu_template)
    check_enabled_features(test_microvm, cpu_template)


def check_masked_features(test_microvm, cpu_template):
    """Check that AVX2 & AVX512 instructions are disabled."""
    common_masked_features_lscpu = ["dtes64", "monitor", "ds_cpl", "tm2",
                                    "cnxt-id", "sdbg", "xtpr", "pdcm",
                                    "osxsave",
                                    "psn", "ds", "acpi", "tm", "ss", "pbe",
                                    "fpdp", "rdt_m", "rdt_a", "mpx", "avx512f",
                                    "intel_pt",
                                    "avx512_vpopcntdq",
                                    "3dnowprefetch", "pdpe1gb"]

    common_masked_features_cpuid = {"SGX": "false", "HLE": "false",
                                    "RTM": "false", "RDSEED": "false",
                                    "ADX": "false", "AVX512IFMA": "false",
                                    "CLFLUSHOPT": "false", "CLWB": "false",
                                    "AVX512PF": "false", "AVX512ER": "false",
                                    "AVX512CD": "false", "SHA": "false",
                                    "AVX512BW": "false", "AVX512VL": "false",
                                    "AVX512VBMI": "false", "PKU": "false",
                                    "OSPKE": "false", "RDPID": "false",
                                    "SGX_LC": "false",
                                    "AVX512_4VNNIW": "false",
                                    "AVX512_4FMAPS": "false",
                                    "XSAVEC": "false", "XGETBV": "false",
                                    "XSAVES": "false"}

    # These are all discoverable by cpuid -1.
    c3_masked_features = {"FMA": "false", "MOVBE": "false", "BMI": "false",
                          "AVX2": "false", "BMI2": "false", "INVPCID": "false"}
    # Check that all common features discoverable with lscpu
    # are properly masked.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    guest_cmd = "cat /proc/cpuinfo | grep 'flags' | head -1"
    _, stdout, stderr = ssh_connection.execute_command(guest_cmd)
    assert stderr.read() == ''

    cpu_flags_output = stdout.readline().rstrip().split(' ')

    for feature in common_masked_features_lscpu:
        assert feature not in cpu_flags_output, feature

    # Check that all common features discoverable with cpuid
    # are properly masked.
    utils.check_guest_cpuid_output(test_microvm, "cpuid -1", None, '=',
                                   common_masked_features_cpuid)

    if cpu_template == "C3":
        utils.check_guest_cpuid_output(test_microvm, "cpuid -1", None, '=',
                                       c3_masked_features)

    # Check if XSAVE PKRU is masked for T3/C2.
    expected_cpu_features = {
        "XCR0 supported: PKRU state": "false"
    }

    utils.check_guest_cpuid_output(test_microvm, "cpuid -1", None, '=',
                                   expected_cpu_features)


def check_enabled_features(test_microvm, cpu_template):
    """Test for checking that all expected features are enabled in guest."""
    enabled_list = {  # feature_info_1_edx
                      "x87 FPU on chip": "true", "CMPXCHG8B inst": "true",
                      "virtual-8086 mode enhancement": "true",
                      "SSE extensions": "true", "SSE2 extensions": "true",
                      "debugging extensions": "true",
                      "page size extensions": "true",
                      "time stamp counter": "true",
                      "RDMSR and WRMSR support": "true",
                      "physical address extensions": "true",
                      "machine check exception": "true",
                      "APIC on chip": "true", "MMX Technology": "true",
                      "SYSENTER and SYSEXIT": "true",
                      "memory type range registers": "true",
                      "PTE global bit": "true", "FXSAVE/FXRSTOR": "true",
                      "machine check architecture": "true",
                      "conditional move/compare instruction": "true",
                      "page attribute table": "true",
                      "page size extension": "true",
                      "CLFLUSH instruction": "true",
                      # feature_info_1_ecx
                      "PNI/SSE3: Prescott New Instructions": "true",
                      "PCLMULDQ instruction": "true",
                      "SSSE3 extensions": "true",
                      "AES instruction": "true",
                      "CMPXCHG16B instruction": "true",
                      "process context identifiers": "true",
                      "SSE4.1 extensions": "true",
                      "SSE4.2 extensions": "true",
                      "extended xAPIC support": "true",
                      "POPCNT instruction": "true",
                      "time stamp counter deadline": "true",
                      "XSAVE/XSTOR states": "true",
                      "OS-enabled XSAVE/XSTOR": "true",
                      "AVX: advanced vector extensions": "true",
                      "F16C half-precision convert instruction": "true",
                      "RDRAND instruction": "true",
                      "hypervisor guest status": "true",
                      # thermal_and_power_mgmt
                      "ARAT always running APIC timer": "true",
                      # extended_features
                      "FSGSBASE instructions": "true",
                      "IA32_TSC_ADJUST MSR supported": "true",
                      "SMEP supervisor mode exec protection": "true",
                      "enhanced REP MOVSB/STOSB": "true",
                      "SMAP: supervisor mode access prevention": "true",
                      # xsave_0xd_0
                      "XCR0 supported: x87 state": "true",
                      "XCR0 supported: SSE state": "true",
                      "XCR0 supported: AVX state": "true",
                      # xsave_0xd_1
                      "XSAVEOPT instruction": "true",
                      # extended_080000001_edx
                      "SYSCALL and SYSRET instructions": "true",
                      "64-bit extensions technology available": "true",
                      "execution disable": "true", "RDTSCP": "true",
                      # intel_080000001_ecx
                      "LAHF/SAHF supported in 64-bit mode": "true",
                      # adv_pwr_mgmt
                      "TscInvariant": "true"}

    utils.check_guest_cpuid_output(test_microvm, "cpuid -1", None, '=',
                                   enabled_list)
    if cpu_template == "T2":
        t2_enabled_features = {"FMA": "true", "BMI": "true", "BMI2": "true",
                               "AVX2": "true", "MOVBE": "true",
                               "INVPCID": "true"}
        utils.check_guest_cpuid_output(test_microvm, "cpuid -1", None, '=',
                                       t2_enabled_features)
