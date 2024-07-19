// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use vmm::arch::x86_64::msr::MsrRange;
use vmm::arch_gen::x86::msr_index::*;
use vmm::cpu_config::templates::{CpuConfiguration, CustomCpuTemplate, RegisterValueFilter};
use vmm::cpu_config::x86_64::cpuid::common::get_vendor_id_from_host;
use vmm::cpu_config::x86_64::cpuid::{Cpuid, VENDOR_ID_AMD};
use vmm::cpu_config::x86_64::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier, RegisterModifier,
};
use vmm::MSR_RANGE;

use crate::utils::x86_64::{cpuid_leaf_modifier, cpuid_reg_modifier, msr_modifier};

/// Convert `&CpuConfiguration` to `CustomCputemplate`.
pub fn config_to_template(cpu_config: &CpuConfiguration) -> CustomCpuTemplate {
    CustomCpuTemplate {
        cpuid_modifiers: cpuid_to_modifiers(&cpu_config.cpuid),
        msr_modifiers: msrs_to_modifier(&cpu_config.msrs),
        ..Default::default()
    }
}

fn cpuid_to_modifiers(cpuid: &Cpuid) -> Vec<CpuidLeafModifier> {
    cpuid
        .inner()
        .iter()
        .map(|(key, entry)| {
            cpuid_leaf_modifier!(
                key.leaf,
                key.subleaf,
                entry.flags,
                vec![
                    cpuid_reg_modifier!(CpuidRegister::Eax, entry.result.eax),
                    cpuid_reg_modifier!(CpuidRegister::Ebx, entry.result.ebx),
                    cpuid_reg_modifier!(CpuidRegister::Ecx, entry.result.ecx),
                    cpuid_reg_modifier!(CpuidRegister::Edx, entry.result.edx),
                ]
            )
        })
        .collect()
}

fn msrs_to_modifier(msrs: &BTreeMap<u32, u64>) -> Vec<RegisterModifier> {
    let mut msrs: Vec<RegisterModifier> = msrs
        .iter()
        .map(|(index, value)| msr_modifier!(*index, *value))
        .collect();

    msrs.retain(|modifier| !should_exclude_msr(modifier.addr));
    if &get_vendor_id_from_host().unwrap() == VENDOR_ID_AMD {
        msrs.retain(|modifier| !should_exclude_msr_amd(modifier.addr));
    }

    msrs.sort_by_key(|modifier| modifier.addr);
    msrs
}

// List of MSR indices excluded from the CPU configuration dump.
//
// MSRs that vary depending on the elapsed time (e.g., time stamp counter) are not useful, because
// CPU configuration dump is used to check diff between CPU models and detect changes caused by
// Firecracker/KVM/BIOS changes.
//
// Fireracker diables some features (e.g., PMU) and doesn't support some features (e.g., Hyper-V),
// MSRs related to such features are not useful as CPU configuration dump. Excluding such MSRs
// reduces maintenance cost when KVM makes change their default values.
const MSR_EXCLUSION_LIST: [MsrRange; 10] = [
    // - MSR_IA32_TSC (0x10): vary depending on the elapsed time.
    MSR_RANGE!(MSR_IA32_TSC),
    // - MSR_IA32_TSC_DEADLINE (0x6e0): varies depending on the elapsed time.
    MSR_RANGE!(MSR_IA32_TSC_DEADLINE),
    // Firecracker doesn't support MCE.
    // - MSR_IA32_MCG_STATUS (0x17a)
    // - MSR_IA32_MCG_EXT_CTL (0x4d0)
    MSR_RANGE!(MSR_IA32_MCG_STATUS),
    MSR_RANGE!(MSR_IA32_MCG_EXT_CTL),
    // - MSR_IA32_PERF_CAPABILITIES (0x345) available if CPUID.01h:ECX[15] = 1 but disabled in the
    //   CPUID normalization process.
    MSR_RANGE!(MSR_IA32_PERF_CAPABILITIES),
    // Firecracker doesn't support PEBS (Precise Event-Based Sampling) that is part of Intel's PMU.
    // - MSR_IA32_PEBS_ENABLE (0x3F1)
    // - MSR_PEBS_DATA_CFG (0x3F2)
    // - MSR_IA32_DS_AREA (0x600)
    MSR_RANGE!(MSR_IA32_PEBS_ENABLE, 2),
    MSR_RANGE!(MSR_IA32_DS_AREA),
    // Firecracker doesn't support AMD PMU.
    // - MSR_K7_EVNTSELn (0xC0010000..=0xC0010003)
    // - MSR_K7_PERFCTRn (0xC0010004..=0xC0010007)
    // - MSR_F15H_PERF_CTLn & MSR_F15H_PERF_CTRn (0xC0010200..=0xC001020B)
    MSR_RANGE!(MSR_K7_EVNTSEL0, 4),
    MSR_RANGE!(MSR_K7_PERFCTR0, 4),
    MSR_RANGE!(MSR_F15H_PERF_CTL0, 12),
];

fn should_exclude_msr(index: u32) -> bool {
    MSR_EXCLUSION_LIST.iter().any(|range| range.contains(index))
}

// List of MSR indices excluded from the CPU configuration dump on AMD
const MSR_EXCLUSION_LIST_AMD: [MsrRange; 1] = [
    // MSR_IA32_ARCH_CAPABILITIES has been emulated by KVM since kernel 5.7.
    // https://github.com/torvalds/linux/commit/93c380e7b528882396ca463971012222bad7d82e
    // https://lore.kernel.org/all/20200302235709.27467-1-sean.j.christopherson@intel.com/
    // As this MSR is not available on AMD processors, Firecracker disables it explicitly by
    // setting 0 to CPUID.(EAX=07H,ECX=0):EDX[bit 29], and this MSR should be removed from the
    // dump on AMD.
    MSR_RANGE!(MSR_IA32_ARCH_CAPABILITIES),
];

fn should_exclude_msr_amd(index: u32) -> bool {
    MSR_EXCLUSION_LIST_AMD
        .iter()
        .any(|range| range.contains(index))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use vmm::cpu_config::x86_64::cpuid::{
        CpuidEntry, CpuidKey, CpuidRegisters, IntelCpuid, KvmCpuidFlags,
    };

    use super::*;

    fn build_sample_cpuid() -> Cpuid {
        Cpuid::Intel(IntelCpuid(BTreeMap::from([
            (
                CpuidKey {
                    leaf: 0x0,
                    subleaf: 0x0,
                },
                CpuidEntry {
                    flags: KvmCpuidFlags::EMPTY,
                    result: CpuidRegisters {
                        eax: 0xffff_ffff,
                        ebx: 0x0000_ffff,
                        ecx: 0xffff_0000,
                        edx: 0x0000_0000,
                    },
                },
            ),
            (
                CpuidKey {
                    leaf: 0x1,
                    subleaf: 0x1,
                },
                CpuidEntry {
                    flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                    result: CpuidRegisters {
                        eax: 0xaaaa_aaaa,
                        ebx: 0xaaaa_5555,
                        ecx: 0x5555_aaaa,
                        edx: 0x5555_5555,
                    },
                },
            ),
        ])))
    }

    fn build_expected_cpuid_modifiers() -> Vec<CpuidLeafModifier> {
        vec![
            cpuid_leaf_modifier!(
                0x0,
                0x0,
                KvmCpuidFlags::EMPTY,
                vec![
                    cpuid_reg_modifier!(CpuidRegister::Eax, 0xffff_ffff),
                    cpuid_reg_modifier!(CpuidRegister::Ebx, 0x0000_ffff),
                    cpuid_reg_modifier!(CpuidRegister::Ecx, 0xffff_0000),
                    cpuid_reg_modifier!(CpuidRegister::Edx, 0x0000_0000),
                ]
            ),
            cpuid_leaf_modifier!(
                0x1,
                0x1,
                KvmCpuidFlags::SIGNIFICANT_INDEX,
                vec![
                    cpuid_reg_modifier!(CpuidRegister::Eax, 0xaaaa_aaaa),
                    cpuid_reg_modifier!(CpuidRegister::Ebx, 0xaaaa_5555),
                    cpuid_reg_modifier!(CpuidRegister::Ecx, 0x5555_aaaa),
                    cpuid_reg_modifier!(CpuidRegister::Edx, 0x5555_5555),
                ]
            ),
        ]
    }

    fn build_sample_msrs() -> BTreeMap<u32, u64> {
        let mut map = BTreeMap::from([
            // should be sorted in the result.
            (0x1, 0xffff_ffff_ffff_ffff),
            (0x5, 0xffff_ffff_0000_0000),
            (0x3, 0x0000_0000_ffff_ffff),
            (0x2, 0x0000_0000_0000_0000),
        ]);
        // should be excluded from the result.
        MSR_EXCLUSION_LIST
            .iter()
            .chain(MSR_EXCLUSION_LIST_AMD.iter())
            .for_each(|range| {
                (range.base..(range.base + range.nmsrs)).for_each(|id| {
                    map.insert(id, 0);
                })
            });
        map
    }

    fn build_expected_msr_modifiers() -> Vec<RegisterModifier> {
        let mut v = vec![
            msr_modifier!(0x1, 0xffff_ffff_ffff_ffff),
            msr_modifier!(0x2, 0x0000_0000_0000_0000),
            msr_modifier!(0x3, 0x0000_0000_ffff_ffff),
            msr_modifier!(0x5, 0xffff_ffff_0000_0000),
        ];
        if &get_vendor_id_from_host().unwrap() != VENDOR_ID_AMD {
            MSR_EXCLUSION_LIST_AMD.iter().for_each(|range| {
                (range.base..(range.base + range.nmsrs)).for_each(|id| {
                    v.push(msr_modifier!(id, 0));
                })
            });
        }
        v
    }

    #[test]
    fn test_config_to_template() {
        let cpu_config = CpuConfiguration {
            cpuid: build_sample_cpuid(),
            msrs: build_sample_msrs(),
        };
        let cpu_template = CustomCpuTemplate {
            cpuid_modifiers: build_expected_cpuid_modifiers(),
            msr_modifiers: build_expected_msr_modifiers(),
            ..Default::default()
        };
        assert_eq!(config_to_template(&cpu_config), cpu_template);
    }
}
