# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the verifying features exposed by CPUID and MSRs by various CPU templates."""

import pytest

from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.matrix import TestMatrix, TestContext
from framework.builder import MicrovmBuilder
import framework.utils_cpuid as cpuid_utils
import host_tools.network as net_tools


# All existing CPU templates available on Intel
INTEL_TEMPLATES = ["C3", "T2", "T2S"]
# All existing CPU templates available on AMD
AMD_TEMPLATES = []
# All existing CPU templates
ALL_TEMPLATES = INTEL_TEMPLATES + AMD_TEMPLATES
# CPU templates designed to provide instruction set feature parity
INST_SET_TEMPLATES = []


def get_supported_templates():
    """
    Returns the list of CPU templates supported by the platform.
    """
    vendor = cpuid_utils.get_cpu_vendor()
    if vendor == cpuid_utils.CpuVendor.INTEL:
        return INTEL_TEMPLATES
    if vendor == cpuid_utils.CpuVendor.AMD:
        return AMD_TEMPLATES
    return []


SUPPORTED_TEMPLATES = get_supported_templates()


def intersection(lst1, lst2):
    """
    Returns the list that is the intersection of two lists.
    """
    lst3 = [value for value in lst1 if value in lst2]
    return lst3


def get_guest_kernel_ver(vm):
    """
    Returns the guest kernel version.
    Useful when running test matrix with multiple guest kernels.
    """
    ssh_conn = net_tools.SSHConnection(vm.ssh_config)
    read_kernel_ver_cmd = "uname -r"
    _, stdout, stderr = ssh_conn.execute_command(read_kernel_ver_cmd)
    assert stderr.read() == ""
    return stdout.read().strip()


def _test_cpuid_feat_flags(context):
    vm_builder = context.custom["builder"]
    root_disk = context.disk.copy()
    cpu_template = context.custom["cpu_template"]
    must_be_set = context.custom["flags_must_be_set"]
    must_be_unset = context.custom["flags_must_be_unset"]

    vm_instance = vm_builder.build(
        kernel=context.kernel,
        disks=[root_disk],
        ssh_key=context.disk.ssh_key(),
        config=context.microvm,
        cpu_template=cpu_template,
    )
    vm = vm_instance.vm
    vm.start()

    cpuid = cpuid_utils.get_guest_cpuid(vm)
    kernel_ver = get_guest_kernel_ver(vm)
    allowed_regs = ["eax", "ebx", "ecx", "edx"]

    for leaf, subleaf, reg, flags in must_be_set:
        assert reg in allowed_regs
        actual = cpuid[(leaf, subleaf, reg)] & flags
        expected = flags
        assert (
            actual == expected
        ), f"{cpu_template}: {kernel_ver=} {leaf=:#x} {subleaf=:#x} {reg=} {actual=:#x}, {expected=:#x}"

    for leaf, subleaf, reg, flags in must_be_unset:
        assert reg in allowed_regs
        actual = cpuid[(leaf, subleaf, reg)] & flags
        expected = 0
        assert (
            actual == expected
        ), f"{cpu_template} {kernel_ver=} {leaf=:#x} {subleaf=:#x} {reg=} {actual=:#x}, {expected=:#x}"


def _test_cpuid_feat_flags_matrix(
    bin_cloner_path,
    network_config,
    cpu_template,
    flags_must_be_set,
    flags_must_be_unset,
):
    """
    This launches tests matrix for CPUID feature flag checks for the given CPU template.
    """

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: Linux 4.14 & Linux 5.10
    # - Rootfs: Ubuntu 18.04 with msr-tools package installed
    # - Microvm: 1vCPU with 1024 MB RAM
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="1vcpu_1024mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels())
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="bionic-msrtools"))
    assert len(disk_artifacts) == 1

    test_context = TestContext()
    test_context.custom = {
        "builder": MicrovmBuilder(bin_cloner_path),
        "network_config": network_config,
        "cpu_template": cpu_template,
        "flags_must_be_set": flags_must_be_set,
        "flags_must_be_unset": flags_must_be_unset,
    }
    test_matrix = TestMatrix(
        context=test_context,
        artifact_sets=[microvm_artifacts, kernel_artifacts, disk_artifacts],
    )
    test_matrix.run_test(_test_cpuid_feat_flags)


@pytest.mark.parametrize(
    "cpu_template", intersection(ALL_TEMPLATES, SUPPORTED_TEMPLATES)
)
def test_feat_parity_cpuid_mpx(bin_cloner_path, network_config, cpu_template):
    """
    Verifies that MPX (Memory Protection Extensions) is not enabled in any of the supported CPU templates.

    @type: functional
    """
    # fmt: off
    must_be_set = []
    must_be_unset = [
        (0x7, 0x0, "ebx",
            (1 << 14) # MPX
        ),
    ]
    # fmt: on

    _test_cpuid_feat_flags_matrix(
        bin_cloner_path, network_config, cpu_template, must_be_set, must_be_unset
    )


@pytest.mark.parametrize(
    "cpu_template", intersection(INST_SET_TEMPLATES + ["T2"], SUPPORTED_TEMPLATES)
)
def test_feat_parity_cpuid_inst_set(bin_cloner_path, network_config, cpu_template):
    """
    Verifies that CPUID feature flags related to instruction sets are properly set
    for the T2 CPU template.

    @type: functional
    """

    # fmt: off
    must_be_set = [
        (0x7, 0x0, "ebx",
            (1 << 5) | # AVX2
            (1 << 9) # REP MOVSB/STOSB
        ),
    ]

    must_be_unset = [
        # Instruction set related
        (0x1, 0x0, "ecx",
            (1 << 15) # PDCM
        ),
        (0x7, 0x0, "ebx",
            (1 << 16) | # AVX512F
            (1 << 17) | # AVX512DQ
            (1 << 18) | # RDSEED
            (1 << 19) | # ADX
            (1 << 23) | # CLFLUSHOPT
            (1 << 24) | # CLWB
            (1 << 29) | # SHA
            (1 << 30) | # AVX512BW
            (1 << 31) # AVX512VL
        ),
        (0x7, 0x0, "ecx",
            (1 << 1) | # AVX512_VBMI
            (1 << 6) | # AVX512_VBMI2
            (1 << 8) | # GFNI
            (1 << 9) | # VAES
            (1 << 10) | # VPCLMULQDQ
            (1 << 11) | # AVX512_VNNI
            (1 << 12) | # AVX512_BITALG
            (1 << 14) | # AVX512_VPOPCNTDQ
            (1 << 22) # RDPID/IA32_TSC_AUX
        ),
        (0x7, 0x0, "edx",
            (1 << 2) | # AVX512_4VNNIW
            (1 << 3) | # AVX512_4FMAPS
            (1 << 4) | # Fast Short REP MOV
            (1 << 8) # AVX512_VP2INTERSECT
        ),
        (0x80000001, 0x0, "ecx",
            (1 << 6) | # SSE4A
            (1 << 7) | # MisAlignSee
            (1 << 8) | # PREFETCHW
            (1 << 29) # MwaitExtended
        ),
        (0x80000001, 0x0, "edx",
            (1 << 22) | # MmxExt
            (1 << 23) | # MMX
            (1 << 24) | # FXSR
            (1 << 25) # FFXSR
        ),
        (0x80000008, 0x0, "ebx",
            (1 << 0) | # CLZERO
            (1 << 2) | # RstrFpErrPtrs
            (1 << 4) | # RDPRU
            (1 << 8) | # MCOMMIT
            (1 << 9) | # WBNOINVD
            (1 << 13) # INT_WBINVD
        ),
    ]
    # fmt: on

    _test_cpuid_feat_flags_matrix(
        bin_cloner_path, network_config, cpu_template, must_be_set, must_be_unset
    )
