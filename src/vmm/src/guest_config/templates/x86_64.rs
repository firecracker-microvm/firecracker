// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Guest config sub-module specifically useful for
/// config templates.
use std::str::FromStr;

use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{CpuTemplateType, StaticCpuTemplate, TakeCpuTemplate};
use crate::guest_config::cpuid::cpuid_ffi::KvmCpuidFlags;
use crate::guest_config::x86_64::static_templates::*;

impl TakeCpuTemplate for Option<CpuTemplateType> {
    /// Take cpu template
    fn take_template(&mut self) -> Option<CustomCpuTemplate> {
        match self.take() {
            Some(CpuTemplateType::Custom(template)) => Some(template),
            Some(CpuTemplateType::Static(template)) => {
                *self = Some(CpuTemplateType::Static(template));
                Some(match template {
                    StaticCpuTemplate::C3 => c3(),
                    StaticCpuTemplate::T2 => t2(),
                    StaticCpuTemplate::T2A => t2a(),
                    StaticCpuTemplate::T2CL => t2cl(),
                    StaticCpuTemplate::T2S => t2s(),
                    StaticCpuTemplate::None => unreachable!("None static template is invalid"),
                })
            }
            None => None,
        }
    }
}

/// CPUID register enumeration
#[allow(missing_docs)]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum CpuidRegister {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

/// Target register to be modified by a bitmap.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CpuidRegisterModifier {
    /// CPUID register to be modified by the bitmap.
    #[serde(
        deserialize_with = "deserialize_cpuid_register",
        serialize_with = "serialize_cpuid_register"
    )]
    pub register: CpuidRegister,
    /// Bit mapping to be applied as a modifier to the
    /// register's value at the address provided.
    #[serde(
        deserialize_with = "deserialize_u64_bitmap",
        serialize_with = "serialize_u32_bitmap"
    )]
    pub bitmap: RegisterValueFilter,
}

/// Composite type that holistically provides
/// the location of a specific register being used
/// in the context of a CPUID tree.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CpuidLeafModifier {
    /// Leaf value.
    #[serde(
        deserialize_with = "deserialize_u32_from_str",
        serialize_with = "serialize_u32_to_hex_str"
    )]
    pub leaf: u32,
    /// Sub-Leaf value.
    #[serde(
        deserialize_with = "deserialize_u32_from_str",
        serialize_with = "serialize_u32_to_hex_str"
    )]
    pub subleaf: u32,
    /// KVM feature flags for this leaf-subleaf.
    #[serde(deserialize_with = "deserialize_kvm_cpuid_flags")]
    pub flags: KvmCpuidFlags,
    /// All registers to be modified under the sub-leaf.
    pub modifiers: Vec<CpuidRegisterModifier>,
}

/// Wrapper type to containing x86_64 CPU config modifiers.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCpuTemplate {
    /// Modifiers for CPUID configuration.
    #[serde(default)]
    pub cpuid_modifiers: Vec<CpuidLeafModifier>,
    /// Modifiers for model specific registers.
    #[serde(default)]
    pub msr_modifiers: Vec<RegisterModifier>,
}

impl CustomCpuTemplate {
    /// Get mrs ids from the template
    pub fn msr_ids(&self) -> Vec<u32> {
        self.msr_modifiers.iter().map(|m| m.addr).collect()
    }
}

/// Bit-mapped value to adjust targeted bits of a register.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct RegisterValueFilter {
    /// Filter to be used when writing the value bits.
    pub filter: u64,
    /// Value to be applied.
    pub value: u64,
}

impl RegisterValueFilter {
    /// Applies filter to the value
    #[inline]
    pub fn apply(&self, value: u64) -> u64 {
        (value & !self.filter) | self.value
    }
}

/// Wrapper of a mask defined as a bitmap to apply
/// changes to a given register's value.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterModifier {
    /// Pointer of the location to be bit mapped.
    #[serde(
        deserialize_with = "deserialize_u32_from_str",
        serialize_with = "serialize_u32_to_hex_str"
    )]
    pub addr: u32,
    /// Bit mapping to be applied as a modifier to the
    /// register's value at the address provided.
    #[serde(
        deserialize_with = "deserialize_u64_bitmap",
        serialize_with = "serialize_u64_bitmap"
    )]
    pub bitmap: RegisterValueFilter,
}

fn deserialize_kvm_cpuid_flags<'de, D>(deserializer: D) -> Result<KvmCpuidFlags, D::Error>
where
    D: Deserializer<'de>,
{
    let flag = u32::deserialize(deserializer)?;
    Ok(KvmCpuidFlags(flag))
}

fn deserialize_cpuid_register<'de, D>(deserializer: D) -> Result<CpuidRegister, D::Error>
where
    D: Deserializer<'de>,
{
    let cpuid_register_str = String::deserialize(deserializer)?;

    Ok(match cpuid_register_str.as_str() {
        "eax" => CpuidRegister::Eax,
        "ebx" => CpuidRegister::Ebx,
        "ecx" => CpuidRegister::Ecx,
        "edx" => CpuidRegister::Edx,
        _ => {
            return Err(D::Error::custom(
                "Invalid CPUID register. Must be one of [eax, ebx, ecx, edx]",
            ))
        }
    })
}

fn deserialize_u32_from_str<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let number_str = String::deserialize(deserializer)?;
    let deserialized_number: u32 = if number_str.len() > 2 {
        match &number_str[0..2] {
            "0b" => u32::from_str_radix(&number_str[2..], 2),
            "0x" => u32::from_str_radix(&number_str[2..], 16),
            _ => u32::from_str(&number_str),
        }
        .map_err(|err| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a number for CPU template - {:?}",
                number_str, err
            ))
        })?
    } else {
        u32::from_str(&number_str).map_err(|err| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a decimal number for CPU template - {:?}",
                number_str, err
            ))
        })?
    };

    Ok(deserialized_number)
}

fn serialize_cpuid_register<S>(cpuid_reg: &CpuidRegister, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match cpuid_reg {
        CpuidRegister::Eax => serializer.serialize_str("eax"),
        CpuidRegister::Ebx => serializer.serialize_str("ebx"),
        CpuidRegister::Ecx => serializer.serialize_str("ecx"),
        CpuidRegister::Edx => serializer.serialize_str("edx"),
    }
}

fn serialize_u32_to_hex_str<S>(number: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(format!("0x{:x}", number).as_str())
}
/// Deserialize a composite bitmap string into a value pair
/// input string: "010x"
/// result: {
///     filter: 1110
///     value: 0100
/// }
pub fn deserialize_u64_bitmap<'de, D>(deserializer: D) -> Result<RegisterValueFilter, D::Error>
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
        filter: u64::from_str_radix(filter_str.as_str(), 2).map_err(|err| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a bitmap - {:?}",
                bitmap_str, err
            ))
        })?,
        value: u64::from_str_radix(value_str.as_str(), 2).map_err(|err| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a bitmap - {:?}",
                bitmap_str, err
            ))
        })?,
    })
}

/// Serialize a RegisterValueFilter (bitmap)
/// into a composite string.
/// RegisterValueFilter {
///     filter: 1110
///     value: 0100
/// }
/// Result string: "010x"
fn serialize_u32_bitmap<S>(bitmap: &RegisterValueFilter, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let value_str = format!("{:032b}", bitmap.value);
    let filter_str = format!("{:032b}", bitmap.filter);

    let mut bitmap_str = String::from("0b");
    for (idx, character) in filter_str.char_indices() {
        match character {
            '1' => bitmap_str.push(value_str.as_bytes()[idx] as char),
            _ => bitmap_str.push('x'),
        }
    }

    serializer.serialize_str(bitmap_str.as_str())
}

/// Serialize a RegisterValueFilter (bitmap)
/// into a composite string.
/// RegisterValueFilter {
///     filter: 1110
///     value: 0100
/// }
/// Result string: "010x"
fn serialize_u64_bitmap<S>(bitmap: &RegisterValueFilter, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let value_str = format!("{:064b}", bitmap.value);
    let filter_str = format!("{:064b}", bitmap.filter);

    let mut bitmap_str = String::from("0b");
    for (idx, character) in filter_str.char_indices() {
        match character {
            '1' => bitmap_str.push(value_str.as_bytes()[idx] as char),
            _ => bitmap_str.push('x'),
        }
    }

    serializer.serialize_str(bitmap_str.as_str())
}

// TODO mark with #[cfg(test)] when we combine all crates into
// one firecracker crate
impl CustomCpuTemplate {
    /// Test CPU template in JSON format
    pub const TEST_TEMPLATE_JSON: &str = r#"{
        "cpuid_modifiers": [
            {
                "leaf": "0x80000001",
                "subleaf": "0x0007",
                "flags": 0,
                "modifiers": [
                    {
                        "register": "eax",
                        "bitmap": "0bx00100xxx1xxxxxxxxxxxxxxxxxxxxx1"
                    }
                ]
            },
            {
                "leaf": "0x80000002",
                "subleaf": "0x0004",
                "flags": 0,
                "modifiers": [
                    {
                        "register": "ebx",
                        "bitmap": "0bxxx1xxxxxxxxxxxxxxxxxxxxx1"
                    },
                    {
                        "register": "ecx",
                        "bitmap": "0bx00100xxx1xxxxxxxxxxx0xxxxx0xxx1"
                    }
                ]
            },
            {
                "leaf": "0x80000003",
                "subleaf": "0x0004",
                "flags": 0,
                "modifiers": [
                    {
                        "register": "edx",
                        "bitmap": "0bx00100xxx1xxxxxxxxxxx0xxxxx0xxx1"
                    }
                ]
            },
            {
                "leaf": "0x80000004",
                "subleaf": "0x0004",
                "flags": 0,
                "modifiers": [
                    {
                        "register": "edx",
                        "bitmap": "0b00100xxx1xxxxxx1xxxxxxxxxxxxxx1"
                    },
                    {
                        "register": "ecx",
                        "bitmap": "0bx00100xxx1xxxxxxxxxxxxx111xxxxx1"
                    }
                ]
            },
            {
                "leaf": "0x80000005",
                "subleaf": "0x0004",
                "flags": 0,
                "modifiers": [
                    {
                        "register": "eax",
                        "bitmap": "0bx00100xxx1xxxxx00xxxxxx000xxxxx1"
                    },
                    {
                        "register": "edx",
                        "bitmap": "0bx10100xxx1xxxxxxxxxxxxx000xxxxx1"
                    }
                ]
            }
        ],
        "msr_modifiers":  [
            {
                "addr": "0x0",
                "bitmap": "0bx00100xxx1xxxx00xxx1xxxxxxxxxxx1"
            },
            {
                "addr": "0x1",
                "bitmap": "0bx00111xxx1xxxx111xxxxx101xxxxxx1"
            },
            {
                "addr": "2",
                "bitmap": "0bx00100xxx1xxxxxx0000000xxxxxxxx1"
            },
            {
                "addr": "0xbbca",
                "bitmap": "0bx00100xxx1xxxxxxxxx1"
            }
        ]
    }"#;

    /// Test CPU template in JSON format but has an invalid field for the architecture.
    /// "reg_modifiers" is the field name for the registers for aarch64"
    pub const TEST_INVALID_TEMPLATE_JSON: &str = r#"{
        "reg_modifiers":  [
            {
                "addr": "0x0AAC",
                "bitmap": "0b1xx1"
            }
        ]
    }"#;

    /// Builds a sample custom CPU template
    pub fn build_test_template() -> CustomCpuTemplate {
        CustomCpuTemplate {
            cpuid_modifiers: vec![CpuidLeafModifier {
                leaf: 0x3,
                subleaf: 0x0,
                flags: KvmCpuidFlags(kvm_bindings::KVM_CPUID_FLAG_STATEFUL_FUNC),
                modifiers: vec![
                    CpuidRegisterModifier {
                        register: CpuidRegister::Eax,
                        bitmap: RegisterValueFilter {
                            filter: 0b0111,
                            value: 0b0101,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ebx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0111,
                            value: 0b0100,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0111,
                            value: 0b0111,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0111,
                            value: 0b0001,
                        },
                    },
                ],
            }],
            msr_modifiers: vec![
                RegisterModifier {
                    addr: 0x9999,
                    bitmap: RegisterValueFilter {
                        filter: 0,
                        value: 0,
                    },
                },
                RegisterModifier {
                    addr: 0x8000,
                    bitmap: RegisterValueFilter {
                        filter: 0,
                        value: 0,
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
        // Misspelled field name, register
        let cpu_template_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "cpuid_modifiers": [
                        {
                            "leaf": "0x80000001",
                            "subleaf": "0b000111",
                            "flags": 0,
                            "modifiers": [
                                {
                                    "register": "ekx",
                                    "bitmap": "0bx00100xxx1xxxxxxxxxxxxxxxxxxxxx1"
                                }
                            ]
                        },
                    ],
                }"#,
        );
        assert!(cpu_template_result.is_err());
        assert!(cpu_template_result
            .unwrap_err()
            .to_string()
            .contains("Invalid CPUID register. Must be one of [eax, ebx, ecx, edx]"));

        // Malformed MSR register address
        let cpu_template_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "msr_modifiers":  [
                        {
                            "addr": "0jj0",
                            "bitmap": "0bx00100xxx1xxxx00xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_template_result.is_err());
        assert!(cpu_template_result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse string [0jj0] as a number for CPU template -"));

        // Malformed CPUID leaf address
        let cpu_template_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "cpuid_modifiers": [
                        {
                            "leaf": "k",
                            "subleaf": "0b000111",
                            "flags": 0,
                            "modifiers": [
                                {
                                    "register": "eax",
                                    "bitmap": "0bx00100xxx1xxxxxxxxxxxxxxxxxxxxx1"
                                }
                            ]
                        },
                    ],
                }"#,
        );
        assert!(cpu_template_result.is_err());
        assert!(cpu_template_result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse string [k] as a decimal number for CPU template"));

        // Malformed 64-bit bitmap - filter failed
        let cpu_template_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "msr_modifiers":  [
                        {
                            "addr": "200",
                            "bitmap": "0bx0?100x?x1xxxx00xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_template_result.is_err());
        assert!(cpu_template_result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse string [x0?100x?x1xxxx00xxx1xxxxxxxxxxx1] as a bitmap"));
        // Malformed 64-bit bitmap - value failed
        let cpu_template_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "msr_modifiers":  [
                        {
                            "addr": "200",
                            "bitmap": "0bx00100x0x1xxxx05xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_template_result.is_err());
        assert!(cpu_template_result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse string [x00100x0x1xxxx05xxx1xxxxxxxxxxx1] as a bitmap"));
    }

    #[test]
    fn test_deserialization_lifecycle() {
        let cpu_template =
            serde_json::from_str::<CustomCpuTemplate>(CustomCpuTemplate::TEST_TEMPLATE_JSON)
                .expect("Failed to deserialize custom CPU template.");
        assert_eq!(5, cpu_template.cpuid_modifiers.len());
        assert_eq!(4, cpu_template.msr_modifiers.len());
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
        let mut cpuid_checked = false;
        let mut msr_checked = false;

        let template = CustomCpuTemplate::build_test_template();

        let x86_template_str =
            serde_json::to_string(&template).expect("Error serializing x86 template");
        let json_tree: Value = serde_json::from_str(&x86_template_str)
            .expect("Error deserializing x86 template JSON string");

        // Check that bitmaps for CPUID values are 32-bits in width
        if let Some(cpuid_modifiers_root) = json_tree.get("cpuid_modifiers") {
            let cpuid_mod_node = &cpuid_modifiers_root.as_array().unwrap()[0];
            if let Some(modifiers_node) = cpuid_mod_node.get("modifiers") {
                let mod_node = &modifiers_node.as_array().unwrap()[0];
                if let Some(bit_map_str) = mod_node.get("bitmap") {
                    // 32-bit width with a "0b" prefix for binary-formatted numbers
                    assert_eq!(bit_map_str.as_str().unwrap().len(), 34);
                    cpuid_checked = true;
                }
            }
        }

        // Check that bitmaps for MSRs are 64-bits in width
        if let Some(msr_modifiers_root) = json_tree.get("msr_modifiers") {
            let msr_mod_node = &msr_modifiers_root.as_array().unwrap()[0];
            if let Some(bit_map_str) = msr_mod_node.get("bitmap") {
                // 64-bit width with a "0b" prefix for binary-formatted numbers
                assert_eq!(bit_map_str.as_str().unwrap().len(), 66);
                assert!(bit_map_str.as_str().unwrap().starts_with("0b"));
                msr_checked = true;
            }
        }

        assert!(
            cpuid_checked,
            "CPUID bitmap width in a x86_64 template was not tested."
        );
        assert!(
            msr_checked,
            "MSR bitmap width in a x86_64 template was not tested."
        );
    }
}
