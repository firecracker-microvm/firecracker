// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Guest config sub-module specifically for
/// config templates.
use std::str::FromStr;

use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wrapper type to containing aarch64 CPU config modifiers.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCpuTemplate {
    /// Modifiers for registers on Aarch64 CPUs.
    #[serde(default)]
    pub reg_modifiers: Vec<RegisterModifier>,
}

/// Wrapper of a mask defined as a bitmap to apply
/// changes to a given register's value.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterModifier {
    /// Pointer of the location to be bit mapped.
    #[serde(
        deserialize_with = "deserialize_u64_from_str",
        serialize_with = "serialize_u64_to_hex_str"
    )]
    pub addr: u64,
    /// Bit mapping to be applied as a modifier to the
    /// register's value at the address provided.
    #[serde(
        deserialize_with = "deserialize_u128_bitmap",
        serialize_with = "serialize_u128_bitmap"
    )]
    pub bitmap: RegisterValueFilter,
}

/// Bit-mapped value to adjust targeted bits of a register.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RegisterValueFilter {
    /// Filter to be used when writing the value bits.
    pub filter: u128,
    /// Value to be applied.
    pub value: u128,
}

impl RegisterValueFilter {
    /// Applies filter to the value
    #[inline]
    pub fn apply(&self, value: u128) -> u128 {
        (value & !self.filter) | self.value
    }
}

/// Deserialize a composite bitmap string into a value pair
/// input string: "010x"
/// result: {
///     filter: 1110
///     value: 0100
/// }
pub fn deserialize_u128_bitmap<'de, D>(deserializer: D) -> Result<RegisterValueFilter, D::Error>
where
    D: Deserializer<'de>,
{
    let mut bitmap_str = String::deserialize(deserializer)?;

    if bitmap_str.starts_with("0b") {
        bitmap_str = bitmap_str[2..].to_string();
    }

    let filter_str = bitmap_str.replace('0', "1");
    let filter_str = filter_str.replace('x', "0");
    let value_str = bitmap_str.replace('x', "0");

    Ok(RegisterValueFilter {
        filter: u128::from_str_radix(filter_str.as_str(), 2).map_err(|err| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a bitmap - {:?}",
                bitmap_str, err
            ))
        })?,
        value: u128::from_str_radix(value_str.as_str(), 2).map_err(|err| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a bitmap - {:?}",
                bitmap_str, err
            ))
        })?,
    })
}

fn serialize_u64_to_hex_str<S>(number: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(format!("0x{:x}", number).as_str())
}

/// Serialize a RegisterValueFilter (bitmap) into a composite string
/// RegisterValueFilter {
///     filter: 1110
///     value: 0100
/// }
/// Result string: "010x"
fn serialize_u128_bitmap<S>(bitmap: &RegisterValueFilter, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let value_str = format!("{:0128b}", bitmap.value);
    let filter_str = format!("{:0128b}", bitmap.filter);

    let mut bitmap_str = String::from("0b");
    for (idx, character) in filter_str.char_indices() {
        match character {
            '1' => bitmap_str.push(value_str.as_bytes()[idx] as char),
            _ => bitmap_str.push('x'),
        }
    }

    serializer.serialize_str(bitmap_str.as_str())
}

fn deserialize_u64_from_str<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let number_str = String::deserialize(deserializer)?;
    let deserialized_number: u64 = if number_str.len() > 2 {
        match &number_str[0..2] {
            "0b" => u64::from_str_radix(&number_str[2..], 2),
            "0x" => u64::from_str_radix(&number_str[2..], 16),
            _ => u64::from_str(&number_str),
        }
        .map_err(|err| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a number for CPU template - {:?}",
                number_str, err
            ))
        })?
    } else {
        u64::from_str(&number_str).map_err(|err| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a decimal number for CPU template - {:?}",
                number_str, err
            ))
        })?
    };
    Ok(deserialized_number)
}

// TODO mark with #[cfg(test)] when we combine all crates into
// one firecracker crate
impl CustomCpuTemplate {
    /// Test CPU template in JSON format
    pub const TEST_TEMPLATE_JSON: &str = r#"{
        "reg_modifiers":  [
            {
                "addr": "0x0AAC",
                "bitmap": "0b1xx1"
            },
            {
                "addr": "0x0AAB",
                "bitmap": "0b1x00"
            }
        ]
    }"#;

    /// Test CPU template in JSON format but has an invalid field for the architecture.
    /// "msr_modifiers" is the field name for the model specific registers for
    /// defined by x86 CPUs.
    pub const TEST_INVALID_TEMPLATE_JSON: &str = r#"{
        "msr_modifiers":  [
            {
                "addr": "0x0AAC",
                "bitmap": "0b1xx1"
            }
        ]
    }"#;

    /// Builds a sample custom CPU template
    pub fn build_test_template() -> CustomCpuTemplate {
        CustomCpuTemplate {
            reg_modifiers: vec![
                RegisterModifier {
                    addr: 0x9999,
                    bitmap: RegisterValueFilter {
                        filter: 0b100010001,
                        value: 0b100000001,
                    },
                },
                RegisterModifier {
                    addr: 0x8000,
                    bitmap: RegisterValueFilter {
                        filter: 0b1110,
                        value: 0b0110,
                    },
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn test_malformed_json() {
        // Malformed register address
        let cpu_config_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "reg_modifiers":  [
                        {
                            "addr": "j",
                            "bitmap": "0bx00100xxx1xxxx00xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_config_result.is_err());
        assert!(cpu_config_result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse string [j] as a decimal number for CPU template"));

        // Malformed address as binary
        let cpu_config_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "reg_modifiers":  [
                        {
                            "addr": "0bK",
                            "bitmap": "0bx00100xxx1xxxx00xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_config_result.is_err());
        assert!(cpu_config_result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse string [0bK] as a number for CPU template"));

        // Malformed 64-bit bitmap - filter failed
        let cpu_config_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "reg_modifiers":  [
                        {
                            "addr": "200",
                            "bitmap": "0bx0?100x?x1xxxx00xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_config_result.is_err());
        assert!(cpu_config_result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse string [x0?100x?x1xxxx00xxx1xxxxxxxxxxx1] as a bitmap"));

        // Malformed 64-bit bitmap - value failed
        let cpu_config_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "reg_modifiers":  [
                        {
                            "addr": "200",
                            "bitmap": "0bx00100x0x1xxxx05xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_config_result.is_err());
        assert!(cpu_config_result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse string [x00100x0x1xxxx05xxx1xxxxxxxxxxx1] as a bitmap"));
    }

    #[test]
    fn test_deserialization_lifecycle() {
        let cpu_config =
            serde_json::from_str::<CustomCpuTemplate>(CustomCpuTemplate::TEST_TEMPLATE_JSON)
                .expect("Failed to deserialize custom CPU template.");
        assert_eq!(2, cpu_config.reg_modifiers.len());
    }

    #[test]
    fn test_serialization_lifecycle() {
        let template = CustomCpuTemplate::build_test_template();
        let template_json_str_result = serde_json::to_string_pretty(&template);
        assert!(&template_json_str_result.is_ok());
        let template_json = template_json_str_result.unwrap();

        let deserialization_result = serde_json::from_str::<CustomCpuTemplate>(&template_json);
        assert!(deserialization_result.is_ok());
        assert_eq!(template, deserialization_result.unwrap());
    }

    /// Test to confirm that templates for different CPU architectures have
    /// a size bitmask that is supported by the architecture when serialized to JSON.
    #[test]
    fn test_bitmap_width() {
        let mut checked = false;

        let template = CustomCpuTemplate::build_test_template();

        let aarch64_template_str =
            serde_json::to_string(&template).expect("Error serializing aarch64 template");
        let json_tree: Value = serde_json::from_str(&aarch64_template_str)
            .expect("Error deserializing aarch64 template JSON string");

        // Check that bitmap for aarch64 masks are serialized to 128-bits
        if let Some(modifiers_root) = json_tree.get("reg_modifiers") {
            let mod_node = &modifiers_root.as_array().unwrap()[0];
            if let Some(bit_map_str) = mod_node.get("bitmap") {
                // 128-bit width with a "0b" prefix for binary-formatted numbers
                assert_eq!(bit_map_str.as_str().unwrap().len(), 130);
                assert!(bit_map_str.as_str().unwrap().starts_with("0b"));
                checked = true;
            }
        }

        assert!(
            checked,
            "Bitmap width in a aarch64 template was not tested."
        );
    }
}
