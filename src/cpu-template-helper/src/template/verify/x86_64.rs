// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::cpu_config::templates::CustomCpuTemplate;

use super::{verify_common, VerifyError};
use crate::utils::x86_64::{CpuidModifierMap, MsrModifierMap};

pub fn verify(
    cpu_template: CustomCpuTemplate,
    cpu_config: CustomCpuTemplate,
) -> Result<(), VerifyError> {
    let cpuid_template = CpuidModifierMap::from(cpu_template.cpuid_modifiers);
    let cpuid_config = CpuidModifierMap::from(cpu_config.cpuid_modifiers);
    verify_common(cpuid_template.0, cpuid_config.0)?;

    let msr_template = MsrModifierMap::from(cpu_template.msr_modifiers);
    let msr_config = MsrModifierMap::from(cpu_config.msr_modifiers);
    verify_common(msr_template.0, msr_config.0)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use vmm::cpu_config::templates::RegisterValueFilter;
    use vmm::cpu_config::x86_64::cpuid::KvmCpuidFlags;
    use vmm::cpu_config::x86_64::custom_cpu_template::CpuidRegister::*;
    use vmm::cpu_config::x86_64::custom_cpu_template::{
        CpuidLeafModifier, CpuidRegisterModifier, RegisterModifier,
    };

    use super::*;
    use crate::utils::x86_64::{
        cpuid_leaf_modifier, cpuid_reg_modifier, msr_modifier, CpuidModifierMapKey,
        MsrModifierMapKey,
    };

    macro_rules! cpuid_modifier_map {
        ($leaf:expr, $subleaf:expr, $flags:expr, $register:expr, $value:expr) => {
            (
                CpuidModifierMapKey {
                    leaf: $leaf,
                    subleaf: $subleaf,
                    flags: $flags,
                    register: $register,
                },
                RegisterValueFilter {
                    filter: u32::MAX.into(),
                    value: $value,
                },
            )
        };
    }

    macro_rules! msr_modifier_map {
        ($addr:expr, $value:expr) => {
            (
                MsrModifierMapKey($addr),
                RegisterValueFilter {
                    filter: u64::MAX.into(),
                    value: $value,
                },
            )
        };
    }

    #[test]
    fn test_format_cpuid_modifier_map_key() {
        let key = CpuidModifierMapKey {
            leaf: 0x0,
            subleaf: 0x1,
            flags: KvmCpuidFlags::STATEFUL_FUNC,
            register: Edx,
        };
        assert_eq!(
            key.to_string(),
            "leaf=0x0, subleaf=0x1, flags=0b10, register=edx",
        )
    }

    #[test]
    #[rustfmt::skip]
    fn test_cpuid_modifier_from_vec_to_map() {
        let modifier_vec = vec![
            cpuid_leaf_modifier!(0x0, 0x0, KvmCpuidFlags::EMPTY, vec![
                cpuid_reg_modifier!(Eax, 0x0),
            ]),
            cpuid_leaf_modifier!(0x1, 0x2, KvmCpuidFlags::SIGNIFICANT_INDEX, vec![
                cpuid_reg_modifier!(Ebx, 0x3),
                cpuid_reg_modifier!(Ecx, 0x4),
            ]),
        ];
        let modifier_map = HashMap::from([
            cpuid_modifier_map!(0x0, 0x0, KvmCpuidFlags::EMPTY, Eax, 0x0),
            cpuid_modifier_map!(0x1, 0x2, KvmCpuidFlags::SIGNIFICANT_INDEX, Ebx, 0x3),
            cpuid_modifier_map!(0x1, 0x2, KvmCpuidFlags::SIGNIFICANT_INDEX, Ecx, 0x4),
        ]);
        assert_eq!(
            CpuidModifierMap::from(modifier_vec),
            CpuidModifierMap(modifier_map),
        );
    }

    #[test]
    fn test_format_msr_modifier_map_key() {
        let key = MsrModifierMapKey(0x1234);
        assert_eq!(key.to_string(), "index=0x1234");
    }

    #[test]
    fn test_msr_modifier_from_vec_to_map() {
        let modifier_vec = vec![
            msr_modifier!(0x1, 0x2),
            msr_modifier!(0x0, 0x0),
            msr_modifier!(0x3, 0x2),
        ];
        let modifier_map = HashMap::from([
            msr_modifier_map!(0x0, 0x0),
            msr_modifier_map!(0x1, 0x2),
            msr_modifier_map!(0x3, 0x2),
        ]);
        assert_eq!(
            MsrModifierMap::from(modifier_vec),
            MsrModifierMap(modifier_map),
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_verify_non_existing_cpuid() {
        // Test with a sample whose CPUID exists in template, but not in config.
        let template = CustomCpuTemplate {
            cpuid_modifiers: vec![cpuid_leaf_modifier!(0x0, 0x0, KvmCpuidFlags::EMPTY, vec![
                cpuid_reg_modifier!(Eax, 0b10101010, 0b11110000),
                cpuid_reg_modifier!(Ebx, 0b01010101, 0b00001111),
            ])],
            msr_modifiers: vec![],
            ..Default::default()
        };
        let config = CustomCpuTemplate {
            cpuid_modifiers: vec![cpuid_leaf_modifier!(0x0, 0x0, KvmCpuidFlags::EMPTY, vec![
                cpuid_reg_modifier!(Eax, 0b10101010, 0b11111111),
            ])],
            msr_modifiers: vec![],
            ..Default::default()
        };
        assert_eq!(
            verify(template, config).unwrap_err().to_string(),
            "leaf=0x0, subleaf=0x0, flags=0b0, register=ebx not found in CPU configuration."
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_verify_mismatched_cpuid() {
        // Test with a sample whose CPUID value mismatches.
        let template = CustomCpuTemplate {
            cpuid_modifiers: vec![cpuid_leaf_modifier!(0x0, 0x0, KvmCpuidFlags::EMPTY,
                vec![cpuid_reg_modifier!(Eax, 0b10101010, 0b11110000)]
            )],
            msr_modifiers: vec![],
            ..Default::default()
        };
        let config = CustomCpuTemplate {
            cpuid_modifiers: vec![cpuid_leaf_modifier!(0x0, 0x0, KvmCpuidFlags::EMPTY,
                vec![cpuid_reg_modifier!(Eax, 0b11111111)]
            )],
            msr_modifiers: vec![],
            ..Default::default()
        };
        assert_eq!(
            verify(template, config).unwrap_err().to_string(),
            "Value for leaf=0x0, subleaf=0x0, flags=0b0, register=eax mismatched.\n\
             * CPU template     : 0b00000000000000000000000010100000\n\
             * CPU configuration: 0b00000000000000000000000011110000\n\
             * Diff             :                            ^ ^    ",
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_verify_non_existing_msr() {
        // Test with a sample whose MSR exists in template, but not in config.
        let template = CustomCpuTemplate {
            cpuid_modifiers: vec![],
            msr_modifiers: vec![
                msr_modifier!(0x0, 0b00000000),
                msr_modifier!(0x1, 0b11111111),
            ],
            ..Default::default()
        };
        let config = CustomCpuTemplate {
            cpuid_modifiers: vec![],
            msr_modifiers: vec![
                msr_modifier!(0x0, 0b00000000),
            ],
            ..Default::default()
        };
        assert_eq!(
            verify(template, config).unwrap_err().to_string(),
            "index=0x1 not found in CPU configuration."
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_verify_mismatched_msr() {
        // Test with a sample whose CPUID value mismatches.
        let template = CustomCpuTemplate {
            cpuid_modifiers: vec![],
            msr_modifiers: vec![
                msr_modifier!(0x0, 0b10101010, 0b11110000),
            ],
            ..Default::default()
        };
        let config = CustomCpuTemplate {
            cpuid_modifiers: vec![],
            msr_modifiers: vec![
                msr_modifier!(0x0, 0b01010101, 0b11111111)
            ],
            ..Default::default()
        };
        assert_eq!(
            verify(template, config).unwrap_err().to_string(),
            "Value for index=0x0 mismatched.\n\
             * CPU template     : 0b0000000000000000000000000000000000000000000000000000000010100000\n\
             * CPU configuration: 0b0000000000000000000000000000000000000000000000000000000001010000\n\
             * Diff             :                                                           ^^^^    ",
        );
    }
}
