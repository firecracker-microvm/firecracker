// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{kvm_cpuid_entry2, CpuId};

use crate::bit_helper::BitHelper;
use crate::cpu_leaf::*;
use crate::template::amd::validate_vendor_id;
use crate::transformer::*;

fn update_extended_feature_info_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0x80000001::*;

    entry
        .ecx
        .write_bit(ecx::SSE4A_BITINDEX, false)
        .write_bit(ecx::MISALIGN_SSE_BITINDEX, false)
        .write_bit(ecx::PREFETCH_BITINDEX, false)
        .write_bit(ecx::MWAIT_EXTENDED_BITINDEX, false);

    entry
        .edx
        .write_bit(edx::MMX_EXT_BITINDEX, false)
        .write_bit(edx::MMX_BITINDEX, false)
        .write_bit(edx::FXSR_BITINDEX, false)
        .write_bit(edx::FFXSR_BITINDEX, false)
        .write_bit(edx::PDPE1GB_BITINDEX, false);

    Ok(())
}

fn update_extended_feature_extensions_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0x80000008::*;

    entry
        .ebx
        .write_bit(ebx::CLZERO_BITINDEX, false)
        .write_bit(ebx::RSTR_FP_ERR_PTRS_BITINDEX, false)
        .write_bit(ebx::WBNOINVD_BITINDEX, false)
        .write_bit(ebx::IBRS_PREFERRED_BITINDEX, true)
        .write_bit(ebx::IBRS_PROVIDES_SAME_MODE_PROTECTION_BITINDEX, true);

    Ok(())
}

/// Sets up the cpuid entries for a given VCPU following a T2A template.
struct T2ACpuidTransformer;

impl CpuidTransformer for T2ACpuidTransformer {
    fn entry_transformer_fn(&self, entry: &mut kvm_cpuid_entry2) -> Option<EntryTransformerFn> {
        match entry.function {
            leaf_0x1::LEAF_NUM => Some(crate::t2::update_feature_info_entry),
            leaf_0x7::LEAF_NUM => Some(crate::t2::update_structured_extended_entry),
            leaf_0xd::LEAF_NUM => Some(crate::t2::update_xsave_features_entry),
            leaf_0x80000001::LEAF_NUM => Some(update_extended_feature_info_entry),
            leaf_0x80000008::LEAF_NUM => Some(update_extended_feature_extensions_entry),
            _ => None,
        }
    }
}

/// Sets up the cpuid entries for a given VCPU following a T2A template.
pub fn set_cpuid_entries(kvm_cpuid: &mut CpuId, vm_spec: &VmSpec) -> Result<(), Error> {
    validate_vendor_id()?;
    T2ACpuidTransformer.process_cpuid(kvm_cpuid, vm_spec)
}
