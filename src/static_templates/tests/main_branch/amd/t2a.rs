// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::guest_config::cpuid::KvmCpuidFlags;
use vmm::guest_config::templates::x86_64::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier, RegisterValueFilter,
};
use vmm::guest_config::templates::CustomCpuTemplate;

use crate::main_branch::bit_helper::{BitHelper, BitRangeExt};

pub fn t2a() -> CustomCpuTemplate {
    CustomCpuTemplate {
        cpuid_modifiers: vec![
            super::super::intel::t2::leaf_0x1_subleaf_0x0(),
            super::super::intel::t2::leaf_0x7_subleaf_0x0(),
            super::super::intel::t2::leaf_0xd_subleaf_0x0(),
            super::super::intel::t2::leaf_0xd_subleaf_0x1(),
            leaf_0x80000001_subleaf_0x0(),
            leaf_0x80000008_subleaf_0x0(),
        ],
        msr_modifiers: vec![],
    }
}

pub fn leaf_0x80000001_subleaf_0x0() -> CpuidLeafModifier {
    use crate::main_branch::cpu_leaf::leaf_0x80000001::*;

    // ECX
    let mut ecx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Ecx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    ecx_modifier
        .bitmap
        .value
        .write_bit(ecx::SSE4A_BITINDEX, false)
        .write_bit(ecx::MISALIGN_SSE_BITINDEX, false)
        .write_bit(ecx::PREFETCH_BITINDEX, false)
        .write_bit(ecx::MWAIT_EXTENDED_BITINDEX, false);

    ecx_modifier.bitmap.filter = ecx::SSE4A_BITINDEX.get_mask()
        | ecx::MISALIGN_SSE_BITINDEX.get_mask()
        | ecx::PREFETCH_BITINDEX.get_mask()
        | ecx::MWAIT_EXTENDED_BITINDEX.get_mask();

    // EDX
    let mut edx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Edx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    edx_modifier
        .bitmap
        .value
        .write_bit(edx::MMX_EXT_BITINDEX, false)
        .write_bit(edx::MMX_BITINDEX, false)
        .write_bit(edx::FXSR_BITINDEX, false)
        .write_bit(edx::FFXSR_BITINDEX, false)
        .write_bit(edx::PDPE1GB_BITINDEX, false);

    edx_modifier.bitmap.filter = edx::MMX_EXT_BITINDEX.get_mask()
        | edx::MMX_BITINDEX.get_mask()
        | edx::FXSR_BITINDEX.get_mask()
        | edx::FFXSR_BITINDEX.get_mask()
        | edx::PDPE1GB_BITINDEX.get_mask();

    CpuidLeafModifier {
        leaf: LEAF_NUM,
        subleaf: 0x0,
        flags: KvmCpuidFlags(0),
        modifiers: vec![ecx_modifier, edx_modifier],
    }
}

pub fn leaf_0x80000008_subleaf_0x0() -> CpuidLeafModifier {
    use crate::main_branch::cpu_leaf::leaf_0x80000008::*;

    let mut ebx_modifier = CpuidRegisterModifier {
        register: CpuidRegister::Ebx,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    ebx_modifier
        .bitmap
        .value
        .write_bit(ebx::CLZERO_BITINDEX, false)
        .write_bit(ebx::RSTR_FP_ERR_PTRS_BITINDEX, false)
        .write_bit(ebx::WBNOINVD_BITINDEX, false)
        .write_bit(ebx::IBRS_PREFERRED_BITINDEX, true)
        .write_bit(ebx::IBRS_PROVIDES_SAME_MODE_PROTECTION_BITINDEX, true);

    ebx_modifier.bitmap.filter = ebx::CLZERO_BITINDEX.get_mask()
        | ebx::RSTR_FP_ERR_PTRS_BITINDEX.get_mask()
        | ebx::WBNOINVD_BITINDEX.get_mask()
        | ebx::IBRS_PREFERRED_BITINDEX.get_mask()
        | ebx::IBRS_PROVIDES_SAME_MODE_PROTECTION_BITINDEX.get_mask();

    CpuidLeafModifier {
        leaf: LEAF_NUM,
        subleaf: 0x0,
        flags: KvmCpuidFlags(0),
        modifiers: vec![ebx_modifier],
    }
}
