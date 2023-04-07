// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::arch::x86_64::msr::{ArchCapaMSRFlags, MSR_IA32_ARCH_CAPABILITIES};
use vmm::guest_config::templates::x86_64::{RegisterModifier, RegisterValueFilter};
use vmm::guest_config::templates::CpuTemplate;

pub fn t2s() -> CpuTemplate {
    CpuTemplate {
        cpuid_modifiers: vec![
            super::t2::leaf_0x1_subleaf_0x0(),
            super::t2::leaf_0x7_subleaf_0x0(),
            super::t2::leaf_0xd_subleaf_0x0(),
            super::t2::leaf_0xd_subleaf_0x1(),
            super::t2::leaf_0x80000001_subleaf_0x0(),
            super::t2::leaf_0x80000008_subleaf_0x0(),
        ],
        msr_modifiers: vec![msr_0x10a()],
    }
}

pub fn msr_0x10a() -> RegisterModifier {
    let mut modifier = RegisterModifier {
        addr: MSR_IA32_ARCH_CAPABILITIES,
        bitmap: RegisterValueFilter {
            filter: 0,
            value: 0,
        },
    };

    modifier.bitmap.value = (ArchCapaMSRFlags::RSBA
        | ArchCapaMSRFlags::SKIP_L1DFL_VMENTRY
        | ArchCapaMSRFlags::IF_PSCHANGE_MC_NO
        | ArchCapaMSRFlags::MISC_PACKAGE_CTRLS
        | ArchCapaMSRFlags::ENERGY_FILTERING_CTL)
        .bits();

    modifier.bitmap.filter = u64::MAX;

    modifier
}
