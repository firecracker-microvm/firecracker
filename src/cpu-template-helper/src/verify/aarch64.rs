// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Display;

use vmm::guest_config::templates::aarch64::{RegisterModifier, RegisterValueFilter};
use vmm::guest_config::templates::CustomCpuTemplate;

use super::{verify_common, Error, ModifierMapKey, ModifierMapValue};

#[derive(Debug, Eq, PartialEq, Hash)]
struct RegModifierMapKey(u64);

impl ModifierMapKey for RegModifierMapKey {}
impl Display for RegModifierMapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ID={:#x}", self.0)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RegModifierMapValue(RegisterValueFilter);

impl ModifierMapValue for RegModifierMapValue {
    type Type = u128;

    fn filter(&self) -> Self::Type {
        self.0.filter
    }

    fn value(&self) -> Self::Type {
        self.0.value
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RegModifierMap(HashMap<RegModifierMapKey, RegModifierMapValue>);

impl From<Vec<RegisterModifier>> for RegModifierMap {
    fn from(modifiers: Vec<RegisterModifier>) -> Self {
        let mut map = HashMap::new();
        for modifier in modifiers {
            map.insert(
                RegModifierMapKey(modifier.addr),
                RegModifierMapValue(modifier.bitmap),
            );
        }
        RegModifierMap(map)
    }
}

pub fn verify(cpu_template: CustomCpuTemplate, cpu_config: CustomCpuTemplate) -> Result<(), Error> {
    let reg_template = RegModifierMap::from(cpu_template.reg_modifiers);
    let reg_config = RegModifierMap::from(cpu_config.reg_modifiers);
    verify_common(reg_template.0, reg_config.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::aarch64::reg_modifier;

    macro_rules! reg_modifier_map {
        ($id:expr, $value:expr) => {
            (
                RegModifierMapKey($id),
                RegModifierMapValue(RegisterValueFilter {
                    filter: u128::MAX,
                    value: $value,
                }),
            )
        };
    }

    #[test]
    fn test_format_reg_modifier_map_key() {
        let key = RegModifierMapKey(0x1234);
        assert_eq!(key.to_string(), "ID=0x1234");
    }

    #[test]
    fn test_reg_modifier_from_vec_to_map() {
        let modifier_vec = vec![
            reg_modifier!(0x1, 0x2),
            reg_modifier!(0x0, 0x0),
            reg_modifier!(0x3, 0x2),
        ];
        let modifier_map = HashMap::from([
            reg_modifier_map!(0x0, 0x0),
            reg_modifier_map!(0x1, 0x2),
            reg_modifier_map!(0x3, 0x2),
        ]);
        assert_eq!(
            RegModifierMap::from(modifier_vec),
            RegModifierMap(modifier_map),
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_verify_non_existing_reg() {
        // Test with a sample whose register exists in template, but not in config.
        let template = CustomCpuTemplate {
            reg_modifiers: vec![
                reg_modifier!(0x0, 0b00000000),
                reg_modifier!(0x1, 0b11111111),
            ],
        };
        let config = CustomCpuTemplate {
            reg_modifiers: vec![
                reg_modifier!(0x0, 0b00000000),
            ],
        };
        assert_eq!(
            verify(template, config).unwrap_err().to_string(),
            "ID=0x1 not found in CPU configuration."
        );
    }

    #[test]
    fn test_verify_mismatched_reg() {
        // Test with a sample whose register value mismatches.
        let template = CustomCpuTemplate {
            reg_modifiers: vec![reg_modifier!(0x0, 0b10101010, 0b11110000)],
        };
        let config = CustomCpuTemplate {
            reg_modifiers: vec![reg_modifier!(0x0, 0b01010101, 0b11111111)],
        };
        assert_eq!(
            verify(template, config).unwrap_err().to_string(),
            "Value for ID=0x0 mismatched.\n\
             * CPU template     : 0b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010100000\n\
             * CPU configuration: 0b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010000\n\
             * Diff             :                                                                                                                           ^^^^    "
        )
    }
}
