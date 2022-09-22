// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use arch::x86_64::msr::{ArchCapaMSRFlags, MSR_IA32_ARCH_CAPABILITIES};
use kvm_bindings::kvm_msr_entry;

/// Add the MSR entries speciffic to this T2S template.
pub fn update_msr_entries(msr_entries: &mut Vec<kvm_msr_entry>) {
    let capabilities = ArchCapaMSRFlags::RSBA
        | ArchCapaMSRFlags::SKIP_L1DFL_VMENTRY
        | ArchCapaMSRFlags::IF_PSCHANGE_MC_NO
        | ArchCapaMSRFlags::MISC_PACKAGE_CTRLS
        | ArchCapaMSRFlags::ENERGY_FILTERING_CTL;
    msr_entries.push(kvm_msr_entry {
        index: MSR_IA32_ARCH_CAPABILITIES,
        data: capabilities.bits(),
        ..kvm_msr_entry::default()
    });
}

static EXTRA_MSR_ENTRIES: &[u32] = &[MSR_IA32_ARCH_CAPABILITIES];

/// Return a list of MSRs speciffic to this T2S template.
#[must_use]
pub fn msr_entries_to_save() -> &'static [u32] {
    EXTRA_MSR_ENTRIES
}
