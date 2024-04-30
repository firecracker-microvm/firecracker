# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the verifying features exposed by CPUID and MSRs by various CPU templates."""

import pytest

import framework.utils_cpuid as cpuid_utils
from framework.properties import global_props
from framework.utils_cpu_templates import SUPPORTED_CPU_TEMPLATES

pytestmark = pytest.mark.skipif(
    global_props.cpu_architecture != "x86_64", reason="x86_64 specific tests"
)


# CPU templates designed to provide instruction set feature parity
INST_SET_TEMPLATES = ["T2A", "T2CL"]


@pytest.fixture(
    name="inst_set_cpu_template",
    params=sorted(set(SUPPORTED_CPU_TEMPLATES).intersection(INST_SET_TEMPLATES)),
)
def inst_set_cpu_template_fxt(request):
    """CPU template fixture for instruction set feature parity templates"""
    return request.param


@pytest.fixture(name="vm")
def vm_fxt(
    microvm_factory,
    inst_set_cpu_template,
    guest_kernel,
    rootfs,
):
    """
    Create a VM, using the normal CPU templates
    """
    vm = microvm_factory.build(guest_kernel, rootfs)
    vm.spawn()
    vm.basic_config(vcpu_count=1, mem_size_mib=1024, cpu_template=inst_set_cpu_template)
    vm.add_net_iface()
    vm.start()
    return vm


def test_feat_parity_cpuid_mpx(vm):
    """
    Verify that MPX (Memory Protection Extensions) is not enabled in any of the supported CPU templates.
    """
    # fmt: off
    must_be_set = []
    must_be_unset = [
        (0x7, 0x0, "ebx",
            (1 << 14) # MPX
        ),
    ]
    # fmt: on

    cpuid_utils.check_cpuid_feat_flags(
        vm,
        must_be_set,
        must_be_unset,
    )


@pytest.mark.parametrize(
    "inst_set_cpu_template",
    sorted(set(SUPPORTED_CPU_TEMPLATES).intersection(INST_SET_TEMPLATES + ["T2"])),
    indirect=True,
)
def test_feat_parity_cpuid_inst_set(vm):
    """
    Verify that CPUID feature flags related to instruction sets are properly set
    for T2, T2CL and T2A CPU templates.
    """

    # fmt: off
    must_be_set = [
        (0x7, 0x0, "ebx",
            (1 << 5) | # AVX2
            (1 << 9) # REP MOVSB/STOSB
        ),
    ]

    must_be_unset = [
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
            (1 << 25) # FFXSR
        ),
        (0x80000008, 0x0, "ebx",
            (1 << 0) | # CLZERO
            (1 << 4) | # RDPRU
            (1 << 8) | # MCOMMIT
            (1 << 9) | # WBNOINVD
            (1 << 13) # INT_WBINVD
        ),
    ]
    # fmt: on

    cpuid_utils.check_cpuid_feat_flags(
        vm,
        must_be_set,
        must_be_unset,
    )
