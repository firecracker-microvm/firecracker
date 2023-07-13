// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use vmm::cpu_config::templates::{CpuConfiguration, CustomCpuTemplate, RegisterValueFilter};
use vmm::cpu_config::x86_64::cpuid::Cpuid;
use vmm::cpu_config::x86_64::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier, RegisterModifier,
};

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

fn msrs_to_modifier(msrs: &HashMap<u32, u64>) -> Vec<RegisterModifier> {
    let mut msrs: Vec<RegisterModifier> = msrs
        .iter()
        .map(|(index, value)| msr_modifier!(*index, *value))
        .collect();
    msrs.sort_by_key(|modifier| modifier.addr);
    msrs
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

    fn build_sample_msrs() -> HashMap<u32, u64> {
        HashMap::from([
            (0x1, 0xffff_ffff_ffff_ffff),
            (0x5, 0xffff_ffff_0000_0000),
            (0x3, 0x0000_0000_ffff_ffff),
            (0x2, 0x0000_0000_0000_0000),
        ])
    }

    fn build_expected_msr_modifiers() -> Vec<RegisterModifier> {
        vec![
            msr_modifier!(0x1, 0xffff_ffff_ffff_ffff),
            msr_modifier!(0x2, 0x0000_0000_0000_0000),
            msr_modifier!(0x3, 0x0000_0000_ffff_ffff),
            msr_modifier!(0x5, 0xffff_ffff_0000_0000),
        ]
    }

    #[test]
    fn test_cpuid_to_modifier() {
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
