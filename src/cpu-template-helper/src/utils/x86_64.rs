// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Display;

use vmm::cpu_config::templates::RegisterValueFilter;
use vmm::cpu_config::x86_64::cpuid::KvmCpuidFlags;
use vmm::cpu_config::x86_64::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier, RegisterModifier,
};

use super::ModifierMapKey;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct CpuidModifierMapKey {
    pub leaf: u32,
    pub subleaf: u32,
    pub flags: KvmCpuidFlags,
    pub register: CpuidRegister,
}

impl ModifierMapKey for CpuidModifierMapKey {}
impl Display for CpuidModifierMapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "leaf={:#x}, subleaf={:#x}, flags={:#b}, register={}",
            self.leaf,
            self.subleaf,
            self.flags.0,
            format!("{:?}", self.register).to_lowercase()
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CpuidModifierMap(pub HashMap<CpuidModifierMapKey, RegisterValueFilter<u32>>);

impl From<Vec<CpuidLeafModifier>> for CpuidModifierMap {
    fn from(leaf_modifiers: Vec<CpuidLeafModifier>) -> Self {
        let mut map = HashMap::new();
        for leaf_modifier in leaf_modifiers {
            for reg_modifier in leaf_modifier.modifiers {
                map.insert(
                    CpuidModifierMapKey {
                        leaf: leaf_modifier.leaf,
                        subleaf: leaf_modifier.subleaf,
                        flags: leaf_modifier.flags,
                        register: reg_modifier.register,
                    },
                    reg_modifier.bitmap,
                );
            }
        }
        CpuidModifierMap(map)
    }
}

impl From<CpuidModifierMap> for Vec<CpuidLeafModifier> {
    fn from(modifier_map: CpuidModifierMap) -> Self {
        let mut leaf_modifiers = Vec::<CpuidLeafModifier>::new();
        for (modifier_key, modifier_value) in modifier_map.0 {
            let leaf_modifier = leaf_modifiers.iter_mut().find(|leaf_modifier| {
                leaf_modifier.leaf == modifier_key.leaf
                    && leaf_modifier.subleaf == modifier_key.subleaf
                    && leaf_modifier.flags == modifier_key.flags
            });

            if let Some(leaf_modifier) = leaf_modifier {
                leaf_modifier.modifiers.push(CpuidRegisterModifier {
                    register: modifier_key.register,
                    bitmap: modifier_value,
                });
            } else {
                leaf_modifiers.push(CpuidLeafModifier {
                    leaf: modifier_key.leaf,
                    subleaf: modifier_key.subleaf,
                    flags: modifier_key.flags,
                    modifiers: vec![CpuidRegisterModifier {
                        register: modifier_key.register,
                        bitmap: modifier_value,
                    }],
                });
            }
        }

        leaf_modifiers.sort_by_key(|leaf_modifier| (leaf_modifier.leaf, leaf_modifier.subleaf));
        leaf_modifiers.iter_mut().for_each(|leaf_modifier| {
            leaf_modifier
                .modifiers
                .sort_by_key(|reg_modifier| reg_modifier.register.clone())
        });
        leaf_modifiers
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct MsrModifierMapKey(pub u32);

impl ModifierMapKey for MsrModifierMapKey {}
impl Display for MsrModifierMapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "index={:#x}", self.0)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct MsrModifierMap(pub HashMap<MsrModifierMapKey, RegisterValueFilter<u64>>);

impl From<Vec<RegisterModifier>> for MsrModifierMap {
    fn from(modifiers: Vec<RegisterModifier>) -> Self {
        let mut map = HashMap::new();
        for modifier in modifiers {
            map.insert(MsrModifierMapKey(modifier.addr), modifier.bitmap);
        }
        MsrModifierMap(map)
    }
}

impl From<MsrModifierMap> for Vec<RegisterModifier> {
    fn from(modifier_map: MsrModifierMap) -> Self {
        let mut modifier_vec = modifier_map
            .0
            .into_iter()
            .map(|(modifier_key, modifier_value)| RegisterModifier {
                addr: modifier_key.0,
                bitmap: modifier_value,
            })
            .collect::<Vec<_>>();
        modifier_vec.sort_by_key(|modifier| modifier.addr);
        modifier_vec
    }
}

macro_rules! cpuid_reg_modifier {
    ($register:expr, $value:expr) => {
        CpuidRegisterModifier {
            register: $register,
            bitmap: RegisterValueFilter {
                filter: u32::MAX.into(),
                value: $value,
            },
        }
    };
    ($register:expr, $value:expr, $filter:expr) => {
        CpuidRegisterModifier {
            register: $register,
            bitmap: RegisterValueFilter {
                filter: $filter,
                value: $value,
            },
        }
    };
}

macro_rules! cpuid_leaf_modifier {
    ($leaf:expr, $subleaf:expr, $flags:expr, $reg_modifiers:expr) => {
        CpuidLeafModifier {
            leaf: $leaf,
            subleaf: $subleaf,
            flags: $flags,
            modifiers: $reg_modifiers,
        }
    };
}

macro_rules! msr_modifier {
    ($addr:expr, $value:expr) => {
        RegisterModifier {
            addr: $addr,
            bitmap: RegisterValueFilter {
                filter: u64::MAX,
                value: $value,
            },
        }
    };
    ($addr:expr, $value:expr, $filter:expr) => {
        RegisterModifier {
            addr: $addr,
            bitmap: RegisterValueFilter {
                filter: $filter,
                value: $value,
            },
        }
    };
}

pub(crate) use {cpuid_leaf_modifier, cpuid_reg_modifier, msr_modifier};

#[cfg(test)]
mod tests {
    use vmm::cpu_config::x86_64::custom_cpu_template::CpuidRegister::*;
    use vmm::cpu_config::x86_64::custom_cpu_template::CpuidRegisterModifier;

    use super::*;
    use crate::utils::x86_64::{cpuid_leaf_modifier, cpuid_reg_modifier, msr_modifier};

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

    #[rustfmt::skip]
    fn build_sample_cpuid_modifier_vec() -> Vec<CpuidLeafModifier> {
        vec![
            cpuid_leaf_modifier!(0x0, 0x0, KvmCpuidFlags::EMPTY, vec![
                cpuid_reg_modifier!(Eax, 0x0),
            ]),
            cpuid_leaf_modifier!(0x1, 0x2, KvmCpuidFlags::SIGNIFICANT_INDEX, vec![
                cpuid_reg_modifier!(Ebx, 0x3),
                cpuid_reg_modifier!(Ecx, 0x4),
            ]),
        ]
    }

    #[rustfmt::skip]
    fn build_sample_cpuid_modifier_map() -> CpuidModifierMap {
        CpuidModifierMap(HashMap::from([
            cpuid_modifier_map!(0x0, 0x0, KvmCpuidFlags::EMPTY, Eax, 0x0),
            cpuid_modifier_map!(0x1, 0x2, KvmCpuidFlags::SIGNIFICANT_INDEX, Ebx, 0x3),
            cpuid_modifier_map!(0x1, 0x2, KvmCpuidFlags::SIGNIFICANT_INDEX, Ecx, 0x4),
        ]))
    }

    #[test]
    fn test_cpuid_modifier_from_vec_to_map() {
        let modifier_vec = build_sample_cpuid_modifier_vec();
        let modifier_map = build_sample_cpuid_modifier_map();
        assert_eq!(CpuidModifierMap::from(modifier_vec), modifier_map);
    }

    #[test]
    fn test_cpuid_modifier_from_map_to_vec() {
        let modifier_map = build_sample_cpuid_modifier_map();
        let modifier_vec = build_sample_cpuid_modifier_vec();
        assert_eq!(Vec::<CpuidLeafModifier>::from(modifier_map), modifier_vec);
    }

    #[test]
    fn test_format_msr_modifier_map_key() {
        let key = MsrModifierMapKey(0x1234);
        assert_eq!(key.to_string(), "index=0x1234");
    }

    fn build_sample_msr_modifier_vec() -> Vec<RegisterModifier> {
        vec![
            msr_modifier!(0x0, 0x0),
            msr_modifier!(0x1, 0x2),
            msr_modifier!(0x3, 0x2),
        ]
    }

    fn build_sample_msr_modifier_map() -> MsrModifierMap {
        MsrModifierMap(HashMap::from([
            msr_modifier_map!(0x0, 0x0),
            msr_modifier_map!(0x1, 0x2),
            msr_modifier_map!(0x3, 0x2),
        ]))
    }

    #[test]
    fn test_msr_modifier_from_vec_to_map() {
        let modifier_vec = build_sample_msr_modifier_vec();
        let modifier_map = build_sample_msr_modifier_map();
        assert_eq!(MsrModifierMap::from(modifier_vec), modifier_map);
    }

    #[test]
    fn test_msr_modifier_from_map_to_vec() {
        let modifier_map = build_sample_msr_modifier_map();
        let modifier_vec = build_sample_msr_modifier_vec();
        assert_eq!(Vec::<RegisterModifier>::from(modifier_map), modifier_vec);
    }
}
