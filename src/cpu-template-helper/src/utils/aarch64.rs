// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Display;

use vmm::cpu_config::aarch64::custom_cpu_template::RegisterModifier;
use vmm::cpu_config::templates::RegisterValueFilter;

use super::ModifierMapKey;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct RegModifierMapKey(pub u64);

impl ModifierMapKey for RegModifierMapKey {}
impl Display for RegModifierMapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ID={:#x}", self.0)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RegModifierMap(pub HashMap<RegModifierMapKey, RegisterValueFilter<u128>>);

impl From<Vec<RegisterModifier>> for RegModifierMap {
    fn from(modifiers: Vec<RegisterModifier>) -> Self {
        let mut map = HashMap::new();
        for modifier in modifiers {
            map.insert(RegModifierMapKey(modifier.addr), modifier.bitmap);
        }
        RegModifierMap(map)
    }
}

impl From<RegModifierMap> for Vec<RegisterModifier> {
    fn from(modifier_map: RegModifierMap) -> Self {
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

macro_rules! reg_modifier {
    ($addr:expr, $value:expr) => {
        RegisterModifier {
            addr: $addr,
            bitmap: RegisterValueFilter {
                filter: u128::MAX,
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

pub(crate) use reg_modifier;

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! reg_modifier_map {
        ($id:expr, $value:expr) => {
            (
                RegModifierMapKey($id),
                RegisterValueFilter {
                    filter: u128::MAX,
                    value: $value,
                },
            )
        };
    }

    #[test]
    fn test_format_reg_modifier_map_key() {
        let key = RegModifierMapKey(0x1234);
        assert_eq!(key.to_string(), "ID=0x1234");
    }

    fn build_sample_reg_modifier_vec() -> Vec<RegisterModifier> {
        vec![
            reg_modifier!(0x0, 0x0),
            reg_modifier!(0x1, 0x2),
            reg_modifier!(0x3, 0x2),
        ]
    }

    fn build_sample_reg_modifier_map() -> RegModifierMap {
        RegModifierMap(HashMap::from([
            reg_modifier_map!(0x0, 0x0),
            reg_modifier_map!(0x1, 0x2),
            reg_modifier_map!(0x3, 0x2),
        ]))
    }

    #[test]
    fn test_reg_modifier_from_vec_to_map() {
        let modifier_vec = build_sample_reg_modifier_vec();
        let modifier_map = build_sample_reg_modifier_map();
        assert_eq!(RegModifierMap::from(modifier_vec), modifier_map);
    }

    #[test]
    fn test_reg_modifier_from_map_to_vec() {
        let modifier_map = build_sample_reg_modifier_map();
        let modifier_vec = build_sample_reg_modifier_vec();
        assert_eq!(Vec::<RegisterModifier>::from(modifier_map), modifier_vec);
    }
}
