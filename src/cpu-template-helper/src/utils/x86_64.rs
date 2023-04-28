// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Display;

use vmm::guest_config::cpuid::KvmCpuidFlags;
use vmm::guest_config::templates::x86_64::{
    CpuidLeafModifier, CpuidRegister, RegisterModifier, RegisterValueFilter,
};

use super::{ModifierMapKey, ModifierMapValue};

#[derive(Debug, Eq, PartialEq, Hash)]
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
pub struct CpuidModifierMapValue(pub RegisterValueFilter);

impl ModifierMapValue for CpuidModifierMapValue {
    type Type = u32;

    fn filter(&self) -> Self::Type {
        // Filters of CPUID modifiers should fit in `u32`.
        self.0.filter.try_into().unwrap()
    }

    fn value(&self) -> Self::Type {
        // Values of CPUID modifiers should fit in `u32`.
        self.0.value.try_into().unwrap()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CpuidModifierMap(pub HashMap<CpuidModifierMapKey, CpuidModifierMapValue>);

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
                    CpuidModifierMapValue(reg_modifier.bitmap),
                );
            }
        }
        CpuidModifierMap(map)
    }
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct MsrModifierMapKey(pub u32);

impl ModifierMapKey for MsrModifierMapKey {}
impl Display for MsrModifierMapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "index={:#x}", self.0)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct MsrModifierMapValue(pub RegisterValueFilter);

impl ModifierMapValue for MsrModifierMapValue {
    type Type = u64;

    fn filter(&self) -> Self::Type {
        self.0.filter
    }

    fn value(&self) -> Self::Type {
        self.0.value
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct MsrModifierMap(pub HashMap<MsrModifierMapKey, MsrModifierMapValue>);

impl From<Vec<RegisterModifier>> for MsrModifierMap {
    fn from(modifiers: Vec<RegisterModifier>) -> Self {
        let mut map = HashMap::new();
        for modifier in modifiers {
            map.insert(
                MsrModifierMapKey(modifier.addr),
                MsrModifierMapValue(modifier.bitmap),
            );
        }
        MsrModifierMap(map)
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
    use vmm::guest_config::templates::x86_64::CpuidRegister::*;
    use vmm::guest_config::templates::x86_64::CpuidRegisterModifier;

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
                CpuidModifierMapValue(RegisterValueFilter {
                    filter: u32::MAX.into(),
                    value: $value,
                }),
            )
        };
    }

    macro_rules! msr_modifier_map {
        ($addr:expr, $value:expr) => {
            (
                MsrModifierMapKey($addr),
                MsrModifierMapValue(RegisterValueFilter {
                    filter: u64::MAX.into(),
                    value: $value,
                }),
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
                cpuid_reg_modifier!(Ecx, 0x4),
                cpuid_reg_modifier!(Ebx, 0x3),
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
}
