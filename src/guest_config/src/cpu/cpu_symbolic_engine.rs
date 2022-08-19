// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;

use arch::x86_64::msr::{SpectreControlMSRFlags, MSR_IA32_SPEC_CTRL};
use cpuid::bit_helper::BitHelper;
use cpuid::common::*;
use cpuid::{Cpuid, RawCpuid};
use itertools::Itertools;
use kvm_bindings::kvm_msr_entry;
use logger::*;
use phf::phf_map;

use crate::cpu::cpu_config::CpuConfigurationAttribute;
use crate::CustomCpuConfiguration;

/// "Database" that maps register configuration to symbolic names for CPU features.
pub static CPU_FEATURE_INDEX_MAP: phf::Map<&'static str, CpuFeatureArchMapping> = phf_map! {
   "ibrs" => CpuFeatureArchMapping {
        leaf: None,
        register: Register::MSR { addr: MSR_IA32_SPEC_CTRL },
        bit_index: SpectreControlMSRFlags::IBRS.bits() as u32,
        feature_type: CpuRegisterFeatureType::SpecialPurpose,
    },
    "ssbd" => CpuFeatureArchMapping {
        leaf: None,
        register: Register::MSR { addr: MSR_IA32_SPEC_CTRL },
        bit_index: SpectreControlMSRFlags::SSBD.bits() as u32,
        feature_type: CpuRegisterFeatureType::SpecialPurpose,
    },
    "stibp" => CpuFeatureArchMapping {
        leaf: None,
        register: Register::MSR { addr: MSR_IA32_SPEC_CTRL },
        bit_index: SpectreControlMSRFlags::SSBD.bits() as u32,
        feature_type: CpuRegisterFeatureType::SpecialPurpose,
    },
    "sse4_2" => CpuFeatureArchMapping {
        leaf: Some(leaf_0x1::LEAF_NUM),
        register: Register::EDX,
        bit_index: leaf_0x1::edx::SSE42_BITINDEX,
        feature_type: CpuRegisterFeatureType::GeneralPurpose,
    },
};

/// Configure all CPU features as per the provided configuration
pub fn configure_cpu_features(
    msr_boot_entries: &mut Vec<kvm_msr_entry>,
    cpu_config: &CustomCpuConfiguration,
) -> Cpuid {
    configure_cpu_features_and_build_msr_config(
        &cpu_config.base_arch_features_configuration,
        msr_boot_entries,
        &cpu_config
            .cpu_feature_overrides
            .iter() // For each CPU feature
            // Filter for CPU features we have a defined mapping for
            .filter_map(|attr| {
                Option::from({
                    // Create a CPU configuration structure.
                    let feature_arch_option = CPU_FEATURE_INDEX_MAP.get(attr.name.as_str());

                    match feature_arch_option {
                        None => {
                            // Invalid/Unknown/Undefined CPU features should have been synchronously
                            // validated for and should not undiscoverable at this point.
                            panic!(
                                "Critical error - Unable to find requested CPU feature [{}]",
                                attr.name.as_str(),
                            )
                        }
                        Some(feature_arch) => CpuConfigurationInstruction {
                            feature_mapping: feature_arch.clone(),
                            config: attr.clone(),
                        },
                    }
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn configure_cpu_features_and_build_msr_config(
    cpuid: &Cpuid,
    msr_boot_entries: &mut Vec<kvm_msr_entry>,
    cpu_features: &Vec<CpuConfigurationInstruction>,
) -> Cpuid {
    // Process MSR features
    // First group enabled CPU features by the MSR they are configured by
    // Key: leaf, Value: CpuFeatureArchMapping
    let msr_to_features_map = cpu_features
        .into_iter()
        .filter(|&config_instruction| {
            config_instruction.feature_mapping.feature_type
                == CpuRegisterFeatureType::SpecialPurpose
        })
        .into_group_map_by(|&x| x.feature_mapping.register);

    // Extend our MSR boot entries with our MSR feature keys
    msr_boot_entries.extend(
        msr_to_features_map
            .keys()
            .into_iter()
            // Filter out MSR feature keys from which we cannot build a configuration structure.
            .filter_map(|msr_pointer| {
                build_single_msr_configuration(msr_pointer, msr_to_features_map.get(msr_pointer))
            }),
    );

    // Process CPUID features
    // First group enabled CPU features by the leaf they are configured by
    let leaf_to_cpuid_features_map = cpu_features
        .into_iter()
        .filter(|&config_instruction| {
            config_instruction.feature_mapping.feature_type
                == CpuRegisterFeatureType::GeneralPurpose
                && !config_instruction.feature_mapping.leaf.is_none()
        })
        .into_group_map_by(|&feature_mapping| feature_mapping.feature_mapping.leaf.unwrap());

    let mut raw_cpuid = RawCpuid::from(cpuid.clone());
    for leaf_config_pair in leaf_to_cpuid_features_map {
        for entry in raw_cpuid.iter_mut() {
            for cpu_feature_mapping in leaf_config_pair.1.iter() {
                if Some(entry.function) == cpu_feature_mapping.feature_mapping.leaf {
                    warn!(
                        "Configuring feature flag: [{}] - [{}]",
                        cpu_feature_mapping.config.name, cpu_feature_mapping.config.is_enabled,
                    );
                    match cpu_feature_mapping.feature_mapping.register {
                        Register::EAX => {
                            entry.eax.write_bit(
                                cpu_feature_mapping.feature_mapping.bit_index,
                                cpu_feature_mapping.config.is_enabled,
                            );
                        }
                        Register::EBX => {
                            entry.ebx.write_bit(
                                cpu_feature_mapping.feature_mapping.bit_index,
                                cpu_feature_mapping.config.is_enabled,
                            );
                        }
                        Register::ECX => {
                            entry.ecx.write_bit(
                                cpu_feature_mapping.feature_mapping.bit_index,
                                cpu_feature_mapping.config.is_enabled,
                            );
                        }
                        Register::EDX => {
                            entry.edx.write_bit(
                                cpu_feature_mapping.feature_mapping.bit_index,
                                cpu_feature_mapping.config.is_enabled,
                            );
                        }
                        Register::MSR { .. } => {}
                    }
                }
            }
        }
    }

    Cpuid::try_from(raw_cpuid).unwrap()
}

fn build_single_msr_configuration(
    msr_pointer: &Register,
    msr_enabled_features: Option<&Vec<&CpuConfigurationInstruction>>,
) -> Option<kvm_msr_entry> {
    if let Register::MSR { addr } = msr_pointer {
        if let Some(msr_features) = msr_enabled_features {
            let mut capabilities: u32 = 0;
            for &feature in msr_features {
                info!(
                    "MSR feature config - [{}] = [{}]",
                    feature.config.name, feature.config.is_enabled
                );
                if feature.config.is_enabled {
                    capabilities = capabilities | feature.feature_mapping.bit_index;
                }
            }

            return Some(kvm_msr_entry {
                index: *addr,
                data: capabilities as u64,
                ..Default::default()
            });
        }
    }

    None
}

/// Type to help demarcate how a given CPU feature must be configured
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CpuRegisterFeatureType {
    /// General purpose CPU feature.
    /// To be configured via normal CPUID interface as per x86 architecture
    GeneralPurpose,
    /// CPU feature that requires configuration via a "special" register
    /// Model specific register or MSR for x86 architecture
    SpecialPurpose,
}

/// Encapsulates information necessary to toggle an arbitrary CPU feature
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CpuFeatureArchMapping {
    pub leaf: Option<u32>,
    pub bit_index: u32,
    pub register: Register,
    pub feature_type: CpuRegisterFeatureType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Register {
    EAX,
    EBX,
    ECX,
    EDX,
    MSR { addr: u32 },
}

#[derive(Clone, Debug, PartialEq)]
struct CpuConfigurationInstruction {
    feature_mapping: CpuFeatureArchMapping,
    config: CpuConfigurationAttribute,
}
