// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TODO: Refactor code to merge deserialize_* functions for modules x86_64 and aarch64
/// Templates module to contain sub-modules for aarch64 and x86_64 templates

/// Guest config sub-module specifically useful for
/// config templates.
#[cfg(target_arch = "x86_64")]
pub mod x86_64 {
    use std::collections::{BTreeMap, HashMap};
    use std::str::FromStr;

    use serde::de::Error as SerdeError;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::guest_config::cpuid::cpuid_ffi::KvmCpuidFlags;
    use crate::guest_config::cpuid::{
        AmdCpuid, Cpuid, CpuidEntry, CpuidKey, CpuidRegisters, IntelCpuid,
    };
    use crate::guest_config::templates::Error;
    use crate::guest_config::x86_64::X86_64CpuConfiguration;

    /// CPUID register enumeration
    #[allow(missing_docs)]
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum CpuidRegister {
        Eax,
        Ebx,
        Ecx,
        Edx,
    }

    /// Target register to be modified by a bitmap.
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
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
        pub flags: crate::guest_config::cpuid::cpuid_ffi::KvmCpuidFlags,
        /// All registers to be modified under the sub-leaf.
        pub modifiers: Vec<CpuidRegisterModifier>,
    }

    /// Wrapper type to containing x86_64 CPU config modifiers.
    #[derive(Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    pub struct X86_64CpuTemplate {
        /// Modifiers for CPUID configuration.
        #[serde(default)]
        pub cpuid_modifiers: Vec<CpuidLeafModifier>,
        /// Modifiers for model specific registers.
        #[serde(default)]
        pub msr_modifiers: Vec<RegisterModifier>,
    }

    /// Bit-mapped value to adjust targeted bits of a register.
    #[derive(Debug, Eq, PartialEq)]
    pub struct RegisterValueFilter {
        /// Filter to be used when writing the value bits.
        pub filter: u64,
        /// Value to be applied.
        pub value: u64,
    }

    /// Wrapper of a mask defined as a bitmap to apply
    /// changes to a given register's value.
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
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

    /// CPU template with modifiers to be applied on
    /// top of an existing configuration to generate
    /// the guest configuration to be used.
    pub fn create_guest_cpu_config(
        template: &X86_64CpuTemplate,
        host_config: &X86_64CpuConfiguration,
    ) -> Result<X86_64CpuConfiguration, Error> {
        let mut guest_msrs_map: HashMap<u32, u64> = HashMap::new();
        let mut guest_cpuid_map: BTreeMap<CpuidKey, CpuidEntry>;

        // Get the hash map of CPUID data
        guest_cpuid_map = match host_config.cpuid.clone() {
            Cpuid::Intel(cpuid) => cpuid.0,
            Cpuid::Amd(cpuid) => cpuid.0,
        };

        // Apply CPUID modifiers
        for mod_leaf in &template.cpuid_modifiers {
            let cpuid_key = CpuidKey {
                leaf: mod_leaf.leaf,
                subleaf: mod_leaf.subleaf,
            };

            let cpuid_entry_option = guest_cpuid_map.get(&cpuid_key);
            let mut guest_cpuid_entry = if let Some(entry) = cpuid_entry_option {
                entry.clone()
            } else {
                return Err(Error::CpuidFeatureNotSupported(format!(
                    "Leaf: {:0x}, Subleaf: {:0x}",
                    &cpuid_key.leaf, &cpuid_key.subleaf
                )));
            };
            guest_cpuid_entry.flags = mod_leaf.flags;

            let (mut mod_eax, mut mod_ebx, mut mod_ecx, mut mod_edx) = (
                u64::from(guest_cpuid_entry.result.eax),
                u64::from(guest_cpuid_entry.result.ebx),
                u64::from(guest_cpuid_entry.result.ecx),
                u64::from(guest_cpuid_entry.result.edx),
            );

            for mod_reg in &mod_leaf.modifiers {
                match mod_reg.register {
                    CpuidRegister::Eax => mod_eax = apply_mask(Some(&mod_eax), &mod_reg.bitmap),
                    CpuidRegister::Ebx => mod_ebx = apply_mask(Some(&mod_ebx), &mod_reg.bitmap),
                    CpuidRegister::Ecx => mod_ecx = apply_mask(Some(&mod_ecx), &mod_reg.bitmap),
                    CpuidRegister::Edx => mod_edx = apply_mask(Some(&mod_edx), &mod_reg.bitmap),
                }
            }

            guest_cpuid_entry = CpuidEntry {
                flags: mod_leaf.flags,
                result: CpuidRegisters {
                    eax: mod_eax as u32,
                    ebx: mod_ebx as u32,
                    ecx: mod_ecx as u32,
                    edx: mod_edx as u32,
                },
            };

            guest_cpuid_map.insert(cpuid_key, guest_cpuid_entry);
        }

        // Apply MSR modifiers
        for modifier in &template.msr_modifiers {
            let msr_value = if let Some(reg_value) = host_config.msrs.get(&modifier.addr) {
                reg_value
            } else {
                return Err(Error::MsrNotSupported(format!(
                    "Register Address: {:0x}",
                    &modifier.addr,
                )));
            };

            guest_msrs_map.insert(modifier.addr, apply_mask(Some(msr_value), &modifier.bitmap));
        }

        Ok(X86_64CpuConfiguration {
            cpuid: match host_config.cpuid {
                Cpuid::Amd(_) => Cpuid::Amd(AmdCpuid(guest_cpuid_map)),
                Cpuid::Intel(_) => Cpuid::Intel(IntelCpuid(guest_cpuid_map)),
            },
            msrs: guest_msrs_map,
        })
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

    fn serialize_cpuid_register<S>(
        cpuid_reg: &CpuidRegister,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
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

    fn apply_mask(source: Option<&u64>, bitmap: &RegisterValueFilter) -> u64 {
        if let Some(value) = source {
            (value & !&bitmap.filter) | bitmap.value
        } else {
            bitmap.value
        }
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
    fn serialize_u32_bitmap<S>(
        bitmap: &RegisterValueFilter,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
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
    fn serialize_u64_bitmap<S>(
        bitmap: &RegisterValueFilter,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
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
}

/// Errors thrown while configuring templates.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Failure in processing the CPUID in template for x86_64 CPU configuration.
    #[error("Template changes a CPUID entry not supported by the host - [{0}]")]
    CpuidFeatureNotSupported(String),
    /// Failure in processing the MSRs in template for x86_64 CPU configuration.
    #[error("Template changes an MSR entry not supported by the host - [{0}]")]
    MsrNotSupported(String),
    /// Internal and unexpected error occurred while using custom templates.
    #[error("Internal error occurred while using templates - [{0}]")]
    Internal(String),
}

/// Guest config sub-module specifically for
/// config templates.
#[cfg(target_arch = "aarch64")]
pub mod aarch64 {
    use std::collections::HashMap;
    use std::str::FromStr;

    use serde::de::Error as SerdeError;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::guest_config::aarch64::Aarch64CpuConfiguration;
    use crate::guest_config::templates::Error;

    /// Wrapper type to containing aarch64 CPU config modifiers.
    #[derive(Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    pub struct Aarch64CpuTemplate {
        /// Modifiers for registers on Aarch64 CPUs.
        pub reg_modifiers: Vec<RegisterModifier>,
    }

    /// Wrapper of a mask defined as a bitmap to apply
    /// changes to a given register's value.
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    #[derive(Debug, Eq, PartialEq)]
    pub struct RegisterValueFilter {
        /// Filter to be used when writing the value bits.
        pub filter: u128,
        /// Value to be applied.
        pub value: u128,
    }

    /// CPU template with modifiers to be applied on
    /// top of an existing configuration to generate
    /// the guest configuration to be used.
    pub fn create_guest_cpu_config(
        template: &Aarch64CpuTemplate,
        host_config: &Aarch64CpuConfiguration,
    ) -> Result<Aarch64CpuConfiguration, Error> {
        let mut guest_config_map: HashMap<u64, u128> = HashMap::new();
        // Apply MSR modifiers
        for mod_reg in &template.reg_modifiers {
            let reg_value = if let Some(reg_value) = host_config.regs.get(&mod_reg.addr) {
                reg_value
            } else {
                return Err(Error::Aarch64RegNotSupported(format!(
                    "Register Address: {:0x}",
                    &mod_reg.addr,
                )));
            };

            guest_config_map.insert(mod_reg.addr, apply_mask(Some(reg_value), &mod_reg.bitmap));
        }

        Ok(Aarch64CpuConfiguration {
            regs: guest_config_map,
        })
    }

    fn apply_mask(source: Option<&u128>, bitmap: &RegisterValueFilter) -> u128 {
        if let Some(value) = source {
            (value & !&bitmap.filter) | bitmap.value
        } else {
            bitmap.value
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
    fn serialize_u128_bitmap<S>(
        bitmap: &RegisterValueFilter,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
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
}

/// Errors thrown while configuring templates.
#[cfg(target_arch = "aarch64")]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Failure in processing the aarch64 CPU template.
    #[error("Template changes a register not supported by the host - [{0}]")]
    Aarch64RegNotSupported(String),
    /// Internal and unexpected error occurred while using custom templates.
    #[error("Internal error occurred while using templates - [{0}]")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use std::collections::BTreeMap;

    #[cfg(target_arch = "x86_64")]
    use kvm_bindings::KVM_CPUID_FLAG_STATEFUL_FUNC;
    use serde_json::Value;

    #[cfg(target_arch = "aarch64")]
    use crate::guest_config::aarch64::Aarch64CpuConfiguration;
    #[cfg(target_arch = "x86_64")]
    use crate::guest_config::cpuid::KvmCpuidFlags;
    #[cfg(target_arch = "x86_64")]
    use crate::guest_config::cpuid::{Cpuid, IntelCpuid};
    #[cfg(target_arch = "x86_64")]
    use crate::guest_config::static_templates::t2::t2;
    #[cfg(target_arch = "aarch64")]
    use crate::guest_config::templates::aarch64::{
        create_guest_cpu_config, Aarch64CpuTemplate, RegisterModifier, RegisterValueFilter,
    };
    #[cfg(target_arch = "x86_64")]
    use crate::guest_config::templates::x86_64::{
        create_guest_cpu_config, CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier,
        RegisterModifier, RegisterValueFilter, X86_64CpuTemplate,
    };
    use crate::guest_config::templates::Error;
    #[cfg(target_arch = "x86_64")]
    use crate::guest_config::x86_64::X86_64CpuConfiguration;

    #[cfg(target_arch = "x86_64")]
    const X86_64_TEMPLATE_JSON: &str = r#"{
        "cpuid_modifiers": [
            {
                "leaf": "0x80000001",
                "subleaf": "0b000111",
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
                "flags": 1,
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
                "addr": "0b1",
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

    #[cfg(target_arch = "aarch64")]
    const AARCH64_TEMPLATE_JSON: &str = r#"{
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

    #[test]
    fn test_malformed_json() {
        #[cfg(target_arch = "x86_64")]
        {
            // Mispelled register
            let cpu_config_result = serde_json::from_str::<X86_64CpuTemplate>(
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
            assert!(cpu_config_result.is_err());
            assert!(cpu_config_result
                .unwrap_err()
                .to_string()
                .contains("Invalid CPUID register. Must be one of [eax, ebx, ecx, edx]"));

            // Malformed MSR register address
            let cpu_config_result = serde_json::from_str::<X86_64CpuTemplate>(
                r#"{
                    "msr_modifiers":  [
                        {
                            "addr": "0jj0",
                            "bitmap": "0bx00100xxx1xxxx00xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
            );
            assert!(cpu_config_result.is_err());
            assert!(cpu_config_result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse string [0jj0] as a number for CPU template -"));

            // Malformed CPUID leaf address
            let cpu_config_result = serde_json::from_str::<X86_64CpuTemplate>(
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
            assert!(cpu_config_result.is_err());
            assert!(cpu_config_result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse string [k] as a decimal number for CPU template"));

            // Malformed 64-bit bitmap - filter failed
            let cpu_config_result = serde_json::from_str::<X86_64CpuTemplate>(
                r#"{
                    "msr_modifiers":  [
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
            let cpu_config_result = serde_json::from_str::<X86_64CpuTemplate>(
                r#"{
                    "msr_modifiers":  [
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

        #[cfg(target_arch = "aarch64")]
        {
            // Malformed register address
            let cpu_config_result = serde_json::from_str::<Aarch64CpuTemplate>(
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
            let cpu_config_result = serde_json::from_str::<Aarch64CpuTemplate>(
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
            let cpu_config_result = serde_json::from_str::<Aarch64CpuTemplate>(
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
            let cpu_config_result = serde_json::from_str::<Aarch64CpuTemplate>(
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
    }

    #[test]
    fn test_deserialization_lifecycle() {
        #[cfg(target_arch = "x86_64")]
        {
            let cpu_config: X86_64CpuTemplate = serde_json::from_str(X86_64_TEMPLATE_JSON)
                .expect("Failed to deserialize x86_64 CPU template.");

            assert_eq!(5, cpu_config.cpuid_modifiers.len());
            assert_eq!(4, cpu_config.msr_modifiers.len());
        }

        #[cfg(target_arch = "aarch64")]
        {
            let cpu_config: Aarch64CpuTemplate = serde_json::from_str(AARCH64_TEMPLATE_JSON)
                .expect("Failed to deserialize aarch64 CPU template.");

            assert_eq!(2, cpu_config.reg_modifiers.len());
        }
    }

    #[test]
    fn test_empty_template() {
        #[cfg(target_arch = "x86_64")]
        {
            let host_configuration = supported_cpu_config();
            let guest_config_result =
                create_guest_cpu_config(&X86_64CpuTemplate::default(), &host_configuration);
            assert!(
                guest_config_result.is_ok(),
                "{}",
                guest_config_result.unwrap_err()
            );
            // CPUID will be comparable, but not MSRs.
            // The configuration will be configuration required by the template,
            // not a holistic view of all registers.
            assert_eq!(guest_config_result.unwrap().cpuid, host_configuration.cpuid);
        }

        #[cfg(target_arch = "aarch64")]
        {
            let host_configuration = supported_cpu_config();
            let guest_config_result =
                create_guest_cpu_config(&Aarch64CpuTemplate::default(), &host_configuration);
            assert!(
                guest_config_result.is_ok(),
                "{}",
                guest_config_result.unwrap_err()
            );
        }
    }

    #[test]
    fn test_apply_template() {
        #[cfg(target_arch = "x86_64")]
        {
            let host_configuration = supported_cpu_config();
            let guest_config_result =
                create_guest_cpu_config(&build_test_template(), &host_configuration);
            assert!(
                guest_config_result.is_ok(),
                "{}",
                guest_config_result.unwrap_err()
            );
            assert_ne!(guest_config_result.unwrap(), host_configuration);
        }

        #[cfg(target_arch = "aarch64")]
        {
            let host_configuration = supported_cpu_config();
            let guest_config_result =
                create_guest_cpu_config(&build_test_template(), &host_configuration);
            assert!(
                guest_config_result.is_ok(),
                "{}",
                guest_config_result.unwrap_err()
            );
            assert_ne!(guest_config_result.unwrap(), host_configuration);
        }
    }

    #[test]
    fn test_serialization_lifecycle() {
        #[cfg(target_arch = "x86_64")]
        {
            let template = build_test_template();
            let template_json_str_result = serde_json::to_string_pretty(&template);
            assert!(&template_json_str_result.is_ok());
            let template_json = template_json_str_result.unwrap();

            let deserialization_result = serde_json::from_str::<X86_64CpuTemplate>(&template_json);
            assert!(deserialization_result.is_ok());
            assert_eq!(template, deserialization_result.unwrap());
        }
    }

    /// Invalid test in this context is when the template
    /// has modifiers for registers that are not supported.
    #[test]
    fn test_invalid_template() {
        #[cfg(target_arch = "x86_64")]
        {
            // Test CPUID validation
            let host_configuration = build_empty_x86_config();
            let guest_template = build_test_template();
            let guest_config_result = create_guest_cpu_config(&guest_template, &host_configuration);
            assert!(
                guest_config_result.is_err(),
                "Expected an error as template should have failed to modify a CPUID entry that is \
                 not supported by host configuration",
            );
            assert_eq!(
                guest_config_result.unwrap_err(),
                Error::CpuidFeatureNotSupported(format!(
                    "Leaf: {:0x}, Subleaf: {:0x}",
                    guest_template.cpuid_modifiers[0].leaf,
                    guest_template.cpuid_modifiers[0].subleaf
                ))
            );

            // Test MSR validation
            let host_configuration = unsupported_cpu_config();
            let guest_template = build_test_template();
            let guest_config_result = create_guest_cpu_config(&guest_template, &host_configuration);
            assert!(
                guest_config_result.is_err(),
                "Expected an error as template should have failed to modify an MSR value that is \
                 not supported by host configuration",
            );
            assert_eq!(
                guest_config_result.unwrap_err(),
                Error::MsrNotSupported(format!(
                    "Register Address: {:0x}",
                    &guest_template.msr_modifiers[0].addr,
                ))
            )
        }

        #[cfg(target_arch = "aarch64")]
        {
            let host_configuration = unsupported_cpu_config();
            let guest_template = build_test_template();
            let guest_config_result = create_guest_cpu_config(&guest_template, &host_configuration);
            assert!(
                guest_config_result.is_err(),
                "Expected an error as template should have failed to modify a register that is \
                 not supported by host configuration",
            );
            assert_eq!(
                guest_config_result.unwrap_err(),
                Error::Aarch64RegNotSupported(format!(
                    "Register Address: {:0x}",
                    &guest_template.reg_modifiers[0].addr,
                ))
            )
        }
    }

    /// Test to confirm that templates for different CPU architectures have
    /// a size bitmask that is supported by the architecture when serialized to JSON.
    #[test]
    fn test_bitmap_width() {
        #[cfg(target_arch = "x86_64")]
        {
            let mut cpuid_checked = false;
            let mut msr_checked = false;

            let template = &build_test_template();

            let x86_template_str =
                serde_json::to_string(template).expect("Error serializing x86 template");
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

        #[cfg(target_arch = "aarch64")]
        {
            let mut checked = false;

            let template = &build_test_template();

            let aarch64_template_str =
                serde_json::to_string(template).expect("Error serializing aarch64 template");
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

    #[cfg(target_arch = "x86_64")]
    fn build_test_template() -> X86_64CpuTemplate {
        X86_64CpuTemplate {
            cpuid_modifiers: Vec::from([CpuidLeafModifier {
                leaf: 0x3,
                subleaf: 0x0,
                flags: KvmCpuidFlags(KVM_CPUID_FLAG_STATEFUL_FUNC),
                modifiers: Vec::from([
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
                ]),
            }]),
            msr_modifiers: Vec::from([
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
            ]),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn build_empty_x86_config() -> X86_64CpuConfiguration {
        X86_64CpuConfiguration {
            cpuid: Cpuid::Intel(IntelCpuid(BTreeMap::new())),
            msrs: Default::default(),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn build_test_template() -> Aarch64CpuTemplate {
        Aarch64CpuTemplate {
            reg_modifiers: Vec::from([
                RegisterModifier {
                    addr: 0x9999,
                    bitmap: RegisterValueFilter {
                        filter: 100010001,
                        value: 10000001,
                    },
                },
                RegisterModifier {
                    addr: 0x8000,
                    bitmap: RegisterValueFilter {
                        filter: 0b1110,
                        value: 0b0110,
                    },
                },
            ]),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn supported_cpu_config() -> X86_64CpuConfiguration {
        X86_64CpuConfiguration {
            cpuid: t2(),
            msrs: std::collections::HashMap::from([(0x8000, 0b1000), (0x9999, 0b1010)]),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn unsupported_cpu_config() -> X86_64CpuConfiguration {
        X86_64CpuConfiguration {
            cpuid: t2(),
            msrs: std::collections::HashMap::from([(0x8000, 0b1000), (0x8001, 0b1010)]),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn supported_cpu_config() -> Aarch64CpuConfiguration {
        Aarch64CpuConfiguration {
            regs: std::collections::HashMap::from([(0x8000, 0b1000), (0x9999, 0b1010)]),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn unsupported_cpu_config() -> Aarch64CpuConfiguration {
        Aarch64CpuConfiguration {
            regs: std::collections::HashMap::from([(0x8000, 0b1000), (0x8001, 0b1010)]),
        }
    }
}
