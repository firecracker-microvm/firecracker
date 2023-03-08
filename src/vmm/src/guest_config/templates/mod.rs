// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer};

// TODO: Refactor code to merge deserialize_* functions for modules x86_64 and aarch64
/// Templates module to contain sub-modules for aarch64 and x86_64 templates

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
            SerdeError::custom(format!(
                "Failed to parse string [{}] as a number for CPU template - {:?}",
                number_str, err
            ))
        })?
    } else {
        u64::from_str(&number_str).map_err(|err| {
            SerdeError::custom(format!(
                "Failed to parse string [{}] as a decimal number for CPU template - {:?}",
                number_str, err
            ))
        })?
    };

    Ok(deserialized_number)
}

/// Errors thrown while configuring templates.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Failure in processing the CPUID configuration.
    #[error("Error deserializing CPUID")]
    Cpuid,
    /// Unknown failure in processing the CPU template.
    #[error("Internal error processing CPU template")]
    Internal,
}

/// Guest config sub-module specifically useful for
/// config templates.
#[cfg(target_arch = "x86_64")]
pub mod x86_64 {
    use std::collections::{BTreeMap, HashMap};
    use std::str::FromStr;

    use log::debug;
    use serde::de::Error as SerdeError;
    use serde::{Deserialize, Deserializer};

    use crate::guest_config::cpuid::cpuid_ffi::KvmCpuidFlags;
    use crate::guest_config::cpuid::{
        AmdCpuid, Cpuid, CpuidEntry, CpuidKey, CpuidRegisters, IntelCpuid,
    };
    use crate::guest_config::templates::{deserialize_u64_from_str, Error};
    use crate::guest_config::x86_64::X86_64CpuConfiguration;

    /// CPUID register enumeration
    #[allow(missing_docs)]
    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub enum CpuidRegister {
        Eax,
        Ebx,
        Ecx,
        Edx,
    }

    /// Target register to be modified by a bitmap.
    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub struct CpuidRegisterModifier {
        /// CPUID register to be modified by the bitmap.
        #[serde(deserialize_with = "deserialize_cpuid_register")]
        pub register: CpuidRegister,
        /// Bit mapping to be applied as a modifier to the
        /// register's value at the address provided.
        #[serde(deserialize_with = "deserialize_bitmap")]
        pub bitmap: RegisterValueFilter,
    }

    /// Composite type that holistically provides
    /// the location of a specific register being used
    /// in the context of a CPUID tree.
    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub struct CpuidLeafModifier {
        /// Leaf value.
        #[serde(deserialize_with = "deserialize_u32_from_str")]
        pub leaf: u32,
        /// Sub-Leaf value.
        #[serde(deserialize_with = "deserialize_u32_from_str")]
        pub subleaf: u32,
        /// KVM feature flags for this leaf-subleaf.
        #[serde(deserialize_with = "deserialize_kvm_cpuid_flags")]
        pub flags: crate::guest_config::cpuid::cpuid_ffi::KvmCpuidFlags,
        /// All registers to be modified under the sub-leaf.
        pub modifiers: Vec<CpuidRegisterModifier>,
    }

    /// Wrapper type to containing x86_64 CPU config modifiers.
    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub struct X86_64CpuTemplate {
        /// Modifiers for CPUID configuration.
        #[serde(default)]
        pub cpuid_modifiers: Vec<CpuidLeafModifier>,
        /// Modifiers for model specific registers.
        #[serde(default)]
        pub msr_modifiers: Vec<RegisterModifier>,
    }

    /// Bit-mapped value to adjust targeted bits of a register.
    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub struct RegisterValueFilter {
        /// Filter to be used when writing the value bits.
        #[serde(deserialize_with = "deserialize_u64_from_str")]
        pub filter: u64,
        /// Value to be applied.
        #[serde(deserialize_with = "deserialize_u64_from_str")]
        pub value: u64,
    }

    /// Wrapper of a mask defined as a bitmap to apply
    /// changes to a given register's value.
    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub struct RegisterModifier {
        /// Pointer of the location to be bit mapped.
        #[serde(deserialize_with = "deserialize_u32_from_str")]
        pub addr: u32,
        /// Bit mapping to be applied as a modifier to the
        /// register's value at the address provided.
        #[serde(deserialize_with = "deserialize_bitmap")]
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
        if host_config.cpuid.amd().is_some() {
            guest_cpuid_map = host_config.cpuid.amd().unwrap().0.clone();
        } else if host_config.cpuid.intel().is_some() {
            guest_cpuid_map = host_config.cpuid.intel().unwrap().0.clone();
        } else {
            return Err(Error::Cpuid);
        }

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
                CpuidEntry::default()
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
            guest_msrs_map.insert(
                modifier.addr,
                apply_mask(host_config.msrs.get(&modifier.addr), &modifier.bitmap),
            );
        }

        if host_config.cpuid.amd().is_some() {
            Ok(X86_64CpuConfiguration {
                cpuid: Cpuid::Amd(AmdCpuid(guest_cpuid_map)),
                msrs: guest_msrs_map,
            })
        } else if host_config.cpuid.intel().is_some() {
            Ok(X86_64CpuConfiguration {
                cpuid: Cpuid::Intel(IntelCpuid(guest_cpuid_map)),
                msrs: guest_msrs_map,
            })
        } else {
            Err(Error::Internal)
        }
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
    pub fn deserialize_bitmap<'de, D>(deserializer: D) -> Result<RegisterValueFilter, D::Error>
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

        debug!(
            "{}",
            format!(
                "Input composite bitmap: [{}]\nFilter: [{}]\nValue: [{}]",
                bitmap_str, filter_str, value_str
            )
        );
        Ok(RegisterValueFilter {
            filter: u64::from_str_radix(filter_str.as_str(), 2).map_err(|err| {
                SerdeError::custom(format!(
                    "Failed to parse string [{}] as a bitmap - {:?}",
                    bitmap_str, err
                ))
            })?,
            value: u64::from_str_radix(value_str.as_str(), 2).map_err(|err| {
                SerdeError::custom(format!(
                    "Failed to parse string [{}] as a bitmap - {:?}",
                    bitmap_str, err
                ))
            })?,
        })
    }
}

/// Guest config sub-module specifically for
/// config templates.
#[cfg(target_arch = "aarch64")]
pub mod aarch64 {
    use std::str::FromStr;

    use log::debug;
    use serde::de::Error as SerdeError;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::guest_config::aarch64::Aarch64CpuConfiguration;
    use crate::guest_config::templates::{deserialize_u64_from_str, Error};

    /// Wrapper type to containing aarch64 CPU config modifiers.
    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub struct Aarch64CpuTemplate {
        /// Modifiers for registers on Aarch64 CPUs.
        pub reg_modifiers: Vec<RegisterModifier>,
    }

    /// Wrapper of a mask defined as a bitmap to apply
    /// changes to a given register's value.
    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub struct RegisterModifier {
        /// Pointer of the location to be bit mapped.
        #[serde(deserialize_with = "deserialize_u64_from_str")]
        pub addr: u64,
        /// Bit mapping to be applied as a modifier to the
        /// register's value at the address provided.
        pub bitmap: RegisterValueFilter,
    }

    /// Bit-mapped value to adjust targeted bits of a register.
    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub struct RegisterValueFilter {
        /// Filter to be used when writing the value bits.
        #[serde(deserialize_with = "deserialize_u128_from_str")]
        pub filter: u128,
        /// Value to be applied.
        #[serde(deserialize_with = "deserialize_u128_from_str")]
        pub value: u128,
    }

    /// CPU template with modifiers to be applied on
    /// top of an existing configuration to generate
    /// the guest configuration to be used.
    pub fn create_guest_cpu_config(
        _template: &Aarch64CpuTemplate,
        _host_config: &Aarch64CpuConfiguration,
    ) -> Result<Aarch64CpuConfiguration, Error> {
        // TODO
        Ok(Aarch64CpuConfiguration::default())
    }

    fn deserialize_u128_from_str<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let number_str = String::deserialize(deserializer)?;
        let deserialized_number: u128 = if number_str.len() > 2 {
            match &number_str[0..2] {
                "0b" => u128::from_str_radix(&number_str[2..], 2),
                "0x" => u128::from_str_radix(&number_str[2..], 16),
                _ => u128::from_str(&number_str),
            }
            .map_err(|err| {
                D::Error::custom(format!(
                    "Failed to parse string [{}] as a number for CPU template - {:?}",
                    number_str, err
                ))
            })?
        } else {
            u128::from_str(&number_str).map_err(|err| {
                D::Error::custom(format!(
                    "Failed to parse string [{}] as a decimal number for CPU template - {:?}",
                    number_str, err
                ))
            })?
        };

        Ok(deserialized_number)
    }

    /// Deserialize a composite bitmap string into a value pair
    /// input string: "010x"
    /// result: {
    ///     filter: 1110
    ///     value: 0100
    /// }
    pub fn deserialize_bitmap<'de, D>(deserializer: D) -> Result<RegisterValueFilter, D::Error>
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

        debug!(
            "{}",
            format!(
                "Input composite bitmap: [{}]\nFilter: [{}]\nValue: [{}]",
                bitmap_str, filter_str, value_str
            )
        );
        Ok(RegisterValueFilter {
            filter: u128::from_str_radix(filter_str.as_str(), 2).map_err(|err| {
                SerdeError::custom(format!(
                    "Failed to parse string [{}] as a bitmap - {:?}",
                    bitmap_str, err
                ))
            })?,
            value: u128::from_str_radix(value_str.as_str(), 2).map_err(|err| {
                SerdeError::custom(format!(
                    "Failed to parse string [{}] as a bitmap - {:?}",
                    bitmap_str, err
                ))
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use kvm_bindings::KVM_CPUID_FLAG_STATEFUL_FUNC;

    #[cfg(target_arch = "x86_64")]
    use crate::guest_config::cpuid::KvmCpuidFlags;
    #[cfg(target_arch = "aarch64")]
    use crate::guest_config::templates::aarch64::{
        Aarch64CpuTemplate, RegisterModifier, RegisterValueFilter,
    };
    #[cfg(target_arch = "x86_64")]
    use crate::guest_config::templates::x86_64::{
        create_guest_cpu_config, CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier,
        RegisterModifier, RegisterValueFilter, X86_64CpuTemplate,
    };
    #[cfg(target_arch = "x86_64")]
    use crate::guest_config::x86_64::X86_64CpuConfiguration;
    #[cfg(target_arch = "x86_64")]
    use crate::vstate::vcpu::x86_64::cpuid_templates;

    #[cfg(target_arch = "x86_64")]
    const X86_64_TEMPLATE_JSON: &str = r#"{
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
    fn test_serialization_lifecycle() {
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

            let template = X86_64CpuTemplate {
                cpuid_modifiers: vec![],
                msr_modifiers: vec![],
            };

            let guest_config_result = create_guest_cpu_config(&template, &host_configuration);
            assert!(
                guest_config_result.is_ok(),
                "{}",
                guest_config_result.unwrap_err()
            );
            assert_eq!(guest_config_result.unwrap(), host_configuration);
        }

        // TODO - Aarch64 test
        // #[cfg(target_arch = "aarch64")]
    }

    #[test]
    fn test_template() {
        #[cfg(target_arch = "x86_64")]
        {
            let host_configuration = supported_cpu_config();

            let template = X86_64CpuTemplate {
                cpuid_modifiers: Vec::from([CpuidLeafModifier {
                    leaf: 0x1,
                    subleaf: 0x1,
                    flags: KvmCpuidFlags(KVM_CPUID_FLAG_STATEFUL_FUNC),
                    modifiers: Vec::from([
                        CpuidRegisterModifier {
                            register: CpuidRegister::Eax,
                            bitmap: RegisterValueFilter {
                                filter: 0,
                                value: 0,
                            },
                        },
                        CpuidRegisterModifier {
                            register: CpuidRegister::Eax,
                            bitmap: RegisterValueFilter {
                                filter: 0,
                                value: 0,
                            },
                        },
                    ]),
                }]),
                msr_modifiers: Vec::from([RegisterModifier {
                    addr: 0x8000,
                    bitmap: RegisterValueFilter {
                        filter: 0,
                        value: 0,
                    },
                }]),
            };

            let guest_config_result = create_guest_cpu_config(&template, &host_configuration);
            assert!(
                guest_config_result.is_ok(),
                "{}",
                guest_config_result.unwrap_err()
            );
            assert_ne!(guest_config_result.unwrap(), host_configuration);
        }

        // TODO - Aarch64 test
        // #[cfg(target_arch = "aarch64")]
    }

    #[cfg(target_arch = "x86_64")]
    fn supported_cpu_config() -> X86_64CpuConfiguration {
        X86_64CpuConfiguration {
            cpuid: cpuid_templates::t2::template(),
            msrs: Default::default(),
        }
    }
}
