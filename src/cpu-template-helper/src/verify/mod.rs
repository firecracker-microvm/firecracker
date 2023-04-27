// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::{Binary, Display};
use std::hash::Hash;
use std::ops::{BitAnd, Shl};

#[allow(unused_variables)]
pub fn verify(
    cpu_template: vmm::guest_config::templates::CustomCpuTemplate,
    cpu_config: vmm::guest_config::templates::CustomCpuTemplate,
) -> Result<(), Error> {
    // This is a placeholder of `verify()`.
    // TODO: Add arch-specific `verify()` under arch-specific module.
    Ok(())
}

#[rustfmt::skip]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0} not found in CPU configuration.")]
    KeyNotFound(String),
    #[error("Value for {0} mismatched.\n{1}")]
    ValueMismatched(String, String),
}

/// Trait for key of `HashMap`-based modifier.
///
/// This is a wrapper trait of some traits required for a key of `HashMap` modifier.
pub trait ModifierMapKey: Eq + PartialEq + Hash + Display {}

/// Trait for value of `HashMap`-based modifier.
pub trait ModifierMapValue {
    // The data size of `Self::Type` varies depending on the target modifier.
    // * x86_64 CPUID: `u32`
    // * x86_64 MSR: `u64`
    // * aarch64 registers: `u128`
    //
    // These trait bounds are required for the following reasons:
    // * `PartialEq + Eq`: To compare `Self::Type` values (like `filter()` and `value()`).
    // * `BitAnd<Output = Self::Type>`: To use AND operation (like `filter() & value()`).
    // * `Binary`: To display in a bitwise format.
    // * `From<bool> + Shl<usize, Output = Self::Type>`: To construct bit masks in
    //   `to_diff_string()`.
    type Type: PartialEq
        + Eq
        + Copy
        + BitAnd<Output = Self::Type>
        + Binary
        + From<bool>
        + Shl<usize, Output = Self::Type>;

    // Return `filter` of arch-specific `RegisterValueFilter` in the size for the target.
    fn filter(&self) -> Self::Type;

    // Return `value` of arch-specific `RegisterValueFilter` in the size for the target.
    fn value(&self) -> Self::Type;

    // Generate a string to display difference of filtered values between CPU template and guest
    // CPU config.
    #[rustfmt::skip]
    fn to_diff_string(template: Self::Type, config: Self::Type) -> String {
        let nbits = std::mem::size_of::<Self::Type>() * 8;

        let mut diff = String::new();
        for i in (0..nbits).rev() {
            let mask = Self::Type::from(true) << i;
            let template_bit = template & mask;
            let config_bit = config & mask;
            diff.push(match template_bit == config_bit {
                true => ' ',
                false => '^',
            });
        }

        format!(
            "* CPU template     : 0b{template:0width$b}\n\
             * CPU configuration: 0b{config:0width$b}\n\
             * Diff             :   {diff}",
            width = nbits,
        )
    }
}

/// Verify that the given CPU template is applied as intended.
///
/// This function is an arch-agnostic part of CPU template verification. As template formats differ
/// between x86_64 and aarch64, the arch-specific part converts the structure to an arch-agnostic
/// `HashMap` implementing `ModifierMapKey` and `ModifierMapValue` for its key and value
/// respectively before calling this arch-agnostic function.
pub fn verify_common<K, V>(template: HashMap<K, V>, config: HashMap<K, V>) -> Result<(), Error>
where
    K: ModifierMapKey,
    V: ModifierMapValue,
{
    for (key, template_value_filter) in template {
        let config_value_filter = config
            .get(&key)
            .ok_or(Error::KeyNotFound(key.to_string()))?;

        let template_value = template_value_filter.value() & template_value_filter.filter();
        let config_value = config_value_filter.value() & template_value_filter.filter();

        if template_value != config_value {
            return Err(Error::ValueMismatched(
                key.to_string(),
                V::to_diff_string(template_value, config_value),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(PartialEq, Eq, Hash)]
    struct MockModifierMapKey(u8);

    impl ModifierMapKey for MockModifierMapKey {}
    impl Display for MockModifierMapKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ID={:#x}", self.0)
        }
    }

    struct MockModifierMapValue {
        filter: u8,
        value: u8,
    }

    impl ModifierMapValue for MockModifierMapValue {
        type Type = u8;

        fn filter(&self) -> Self::Type {
            self.filter
        }

        fn value(&self) -> Self::Type {
            self.value
        }
    }

    macro_rules! mock_modifier {
        ($key:expr, ($filter:expr, $value:expr)) => {
            (
                MockModifierMapKey($key),
                MockModifierMapValue {
                    filter: $filter,
                    value: $value,
                },
            )
        };
    }

    #[test]
    fn test_verify_modifier_map_with_non_existing_key() {
        // Test with a sample whose key exists in CPU template but not in CPU config.
        let cpu_template_map =
            HashMap::from([mock_modifier!(0b0000_0000, (0b0000_0000, 0b0000_0000))]);
        let cpu_config_map = HashMap::new();

        assert_eq!(
            verify_common(cpu_template_map, cpu_config_map)
                .unwrap_err()
                .to_string(),
            "ID=0x0 not found in CPU configuration.".to_string()
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_verify_modifier_map_with_mismatched_value() {
        // Test with a sample whose filtered value mismatches between CPU config and CPU template.
        let cpu_template_map =
            HashMap::from([mock_modifier!(0b0000_0000, (0b0000_1111, 0b0000_0101))]);
        let cpu_config_map =
            HashMap::from([mock_modifier!(0b0000_0000, (u8::MAX, 0b0000_0000))]);

        assert_eq!(
            verify_common(cpu_template_map, cpu_config_map)
                .unwrap_err()
                .to_string(),
            "Value for ID=0x0 mismatched.\n\
             * CPU template     : 0b00000101\n\
             * CPU configuration: 0b00000000\n\
             * Diff             :        ^ ^"
        )
    }

    #[test]
    fn test_verify_modifier_map_with_valid_value() {
        // Test with valid CPU template and CPU config.
        let cpu_template_map =
            HashMap::from([mock_modifier!(0b0000_0000, (0b0000_1111, 0b0000_1010))]);
        let cpu_config_map = HashMap::from([mock_modifier!(0b0000_0000, (u8::MAX, 0b1010_1010))]);

        verify_common(cpu_template_map, cpu_config_map).unwrap();
    }
}
