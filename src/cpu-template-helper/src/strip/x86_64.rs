// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use vmm::guest_config::templates::CustomCpuTemplate;

use crate::strip::remove_common;

#[allow(dead_code)]
pub fn strip(templates: Vec<CustomCpuTemplate>) -> Vec<CustomCpuTemplate> {
    // Convert `Vec<CustomCpuTemplate>` to two `Vec<HashSet<_>>` of modifiers.
    let (mut cpuid_modifiers_sets, mut msr_modifiers_sets): (Vec<_>, Vec<_>) = templates
        .into_iter()
        .map(|template| {
            (
                template.cpuid_modifiers.into_iter().collect::<HashSet<_>>(),
                template.msr_modifiers.into_iter().collect::<HashSet<_>>(),
            )
        })
        .unzip();

    // Remove common items.
    remove_common(&mut cpuid_modifiers_sets);
    remove_common(&mut msr_modifiers_sets);

    // Convert back to `Vec<CustomCpuTemplate>`.
    cpuid_modifiers_sets
        .into_iter()
        .zip(msr_modifiers_sets.into_iter())
        .map(|(cpuid_modifiers_set, msr_modifiers_set)| {
            let mut cpuid_modifiers = cpuid_modifiers_set.into_iter().collect::<Vec<_>>();
            let mut msr_modifiers = msr_modifiers_set.into_iter().collect::<Vec<_>>();

            cpuid_modifiers.sort_by_key(|modifier| (modifier.leaf, modifier.subleaf));
            msr_modifiers.sort_by_key(|modifier| modifier.addr);

            CustomCpuTemplate {
                cpuid_modifiers,
                msr_modifiers,
            }
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use vmm::guest_config::cpuid::KvmCpuidFlags;
    use vmm::guest_config::templates::x86_64::CpuidRegister::*;
    use vmm::guest_config::templates::x86_64::{
        CpuidLeafModifier, CpuidRegisterModifier, RegisterModifier, RegisterValueFilter,
    };

    use super::*;

    macro_rules! cpuid_reg_modifier {
        ($register:expr, $value:literal) => {
            CpuidRegisterModifier {
                register: $register,
                bitmap: RegisterValueFilter {
                    filter: u32::MAX.into(),
                    value: $value,
                },
            }
        };
    }

    macro_rules! cpuid_leaf_modifier {
        ($leaf:literal, $subleaf:literal, $flags:expr, $reg_modifiers:expr) => {
            CpuidLeafModifier {
                leaf: $leaf,
                subleaf: $subleaf,
                flags: $flags,
                modifiers: $reg_modifiers,
            }
        };
    }

    macro_rules! msr_modifier {
        ($addr:literal, $value:literal) => {
            RegisterModifier {
                addr: $addr,
                bitmap: RegisterValueFilter {
                    filter: u64::MAX,
                    value: $value,
                },
            }
        };
    }

    // Summary of CPUID modifiers:
    // * As CPUID leaf 0x0 / subleaf 0x0 modifier exists in all the templates and its values are
    //   different, it should be removed.
    // * As CPUID leaf 0x1 / subleaf 0x0 modifier only exists in the second template, it should be
    //   preserved.
    // * As CPUID leaf 0x2 / subleaf 0x1 modifier exists in all the templates but EBX values are
    //   different, the leaf modifier (not only the register modifier EBX) should be preserved.
    #[rustfmt::skip]
    fn build_input_cpuid_templates() -> Vec<CustomCpuTemplate> {
        vec![
            CustomCpuTemplate {
                cpuid_modifiers: vec![
                    cpuid_leaf_modifier!(0x0, 0x0, KvmCpuidFlags::EMPTY, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                    ]),
                    cpuid_leaf_modifier!(0x2, 0x1, KvmCpuidFlags::SIGNIFICANT_INDEX, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                        cpuid_reg_modifier!(Ebx, 0x0),
                    ]),
                ],
                msr_modifiers: vec![],
            },
            CustomCpuTemplate {
                cpuid_modifiers: vec![
                    cpuid_leaf_modifier!(0x0, 0x0, KvmCpuidFlags::EMPTY, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                    ]),
                    cpuid_leaf_modifier!(0x1, 0x0, KvmCpuidFlags::EMPTY, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                    ]),
                    cpuid_leaf_modifier!(0x2, 0x1, KvmCpuidFlags::SIGNIFICANT_INDEX, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                        cpuid_reg_modifier!(Ebx, 0x1),
                    ]),
                ],
                msr_modifiers: vec![],
            },
            CustomCpuTemplate {
                cpuid_modifiers: vec![
                    cpuid_leaf_modifier!(0x0, 0x0, KvmCpuidFlags::EMPTY, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                    ]),
                    cpuid_leaf_modifier!(0x2, 0x1, KvmCpuidFlags::SIGNIFICANT_INDEX, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                        cpuid_reg_modifier!(Ebx, 0x2),
                    ]),
                ],
                msr_modifiers: vec![],
            },
        ]
    }

    #[rustfmt::skip]
    fn build_expected_cpuid_templates() -> Vec<CustomCpuTemplate> {
        vec![
            CustomCpuTemplate {
                cpuid_modifiers: vec![
                    cpuid_leaf_modifier!(0x2, 0x1, KvmCpuidFlags::SIGNIFICANT_INDEX, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                        cpuid_reg_modifier!(Ebx, 0x0),
                    ]),
                ],
                msr_modifiers: vec![],
            },
            CustomCpuTemplate {
                cpuid_modifiers: vec![
                    cpuid_leaf_modifier!(0x1, 0x0, KvmCpuidFlags::EMPTY, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                    ]),
                    cpuid_leaf_modifier!(0x2, 0x1, KvmCpuidFlags::SIGNIFICANT_INDEX, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                        cpuid_reg_modifier!(Ebx, 0x1),
                    ]),
                ],
                msr_modifiers: vec![],
            },
            CustomCpuTemplate {
                cpuid_modifiers: vec![
                    cpuid_leaf_modifier!(0x2, 0x1, KvmCpuidFlags::SIGNIFICANT_INDEX, vec![
                        cpuid_reg_modifier!(Eax, 0x0),
                        cpuid_reg_modifier!(Ebx, 0x2),
                    ]),
                ],
                msr_modifiers: vec![],
            },
        ]
    }

    // Summary of MSR modifiers:
    // * As addr 0x0 modifier exists in all the templates but its values are different, it should be
    //   preserved.
    // * As addr 0x1 modifier exists in all the templates and its values are same, it should be
    //   removed.
    // * As addr 0x2 modifier only exist in the third template, it should be preserved.
    #[rustfmt::skip]
    fn build_input_msr_templates() -> Vec<CustomCpuTemplate> {
        vec![
            CustomCpuTemplate {
                cpuid_modifiers: vec![],
                msr_modifiers: vec![
                    msr_modifier!(0x0, 0x0),
                    msr_modifier!(0x1, 0x1),
                ],
            },
            CustomCpuTemplate {
                cpuid_modifiers: vec![],
                msr_modifiers: vec![
                    msr_modifier!(0x0, 0x1),
                    msr_modifier!(0x1, 0x1),
                ],
            },
            CustomCpuTemplate {
                cpuid_modifiers: vec![],
                msr_modifiers: vec![
                    msr_modifier!(0x0, 0x2),
                    msr_modifier!(0x1, 0x1),
                    msr_modifier!(0x2, 0x1),
                ],
            },
        ]
    }

    #[rustfmt::skip]
    fn build_expected_msr_templates() -> Vec<CustomCpuTemplate> {
        vec![
            CustomCpuTemplate {
                cpuid_modifiers: vec![],
                msr_modifiers: vec![
                    msr_modifier!(0x0, 0x0),
                ],
            },
            CustomCpuTemplate {
                cpuid_modifiers: vec![],
                msr_modifiers: vec![
                    msr_modifier!(0x0, 0x1),
                ],
            },
            CustomCpuTemplate {
                cpuid_modifiers: vec![],
                msr_modifiers: vec![
                    msr_modifier!(0x0, 0x2),
                    msr_modifier!(0x2, 0x1),
                ],
            },
        ]
    }

    #[test]
    fn test_strip_cpuid_modifiers() {
        let input = build_input_cpuid_templates();
        let result = strip(input);
        let expected = build_expected_cpuid_templates();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_strip_msr_modifiers() {
        let input = build_input_msr_templates();
        let result = strip(input);
        let expected = build_expected_msr_templates();
        assert_eq!(result, expected);
    }
}
