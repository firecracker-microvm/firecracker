// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use arch::x86_64::msr::{ArchCapaMSRFlags, MSR_IA32_ARCH_CAPABILITIES};
use kvm_bindings::{kvm_cpuid_entry2, kvm_msr_entry, CpuId};

use crate::cpu_leaf::*;
use crate::template::intel::validate_vendor_id;
use crate::transformer::*;

/// Sets up the cpuid entries for a given VCPU following a T2S template.
struct T2SCpuidTransformer;

impl CpuidTransformer for T2SCpuidTransformer {
    fn entry_transformer_fn(&self, entry: &mut kvm_cpuid_entry2) -> Option<EntryTransformerFn> {
        match entry.function {
            leaf_0x1::LEAF_NUM => Some(crate::t2::update_feature_info_entry),
            leaf_0x7::LEAF_NUM => Some(crate::t2::update_structured_extended_entry),
            leaf_0xd::LEAF_NUM => Some(crate::t2::update_xsave_features_entry),
            leaf_0x80000001::LEAF_NUM => Some(crate::t2::update_extended_feature_info_entry),
            _ => None,
        }
    }
}

/// Sets up the cpuid entries for a given VCPU following a T2S template.
pub fn set_cpuid_entries(kvm_cpuid: &mut CpuId, vm_spec: &VmSpec) -> Result<(), Error> {
    validate_vendor_id()?;
    T2SCpuidTransformer {}.process_cpuid(kvm_cpuid, vm_spec)
}

/// Add the MSR entries speciffic to this T2S template.
pub fn update_msr_entries(msr_entries: &mut Vec<kvm_msr_entry>) {
    let capabilities = ArchCapaMSRFlags::RSBA
        | ArchCapaMSRFlags::SKIP_L1DFL_VMENTRY
        | ArchCapaMSRFlags::IF_PSCHANGE_MC_NO
        | ArchCapaMSRFlags::MISC_PACKAGE_CTRLS
        | ArchCapaMSRFlags::ENERGY_FILTERING_CTL
        | ArchCapaMSRFlags::RRSBA;
    msr_entries.push(kvm_msr_entry {
        index: MSR_IA32_ARCH_CAPABILITIES,
        data: capabilities.bits(),
        ..Default::default()
    });
}

static EXTRA_MSR_ENTRIES: &[u32] = &[MSR_IA32_ARCH_CAPABILITIES];

/// Return a list of MSRs speciffic to this T2S template.
pub fn msr_entries_to_save() -> &'static [u32] {
    EXTRA_MSR_ENTRIES
}
