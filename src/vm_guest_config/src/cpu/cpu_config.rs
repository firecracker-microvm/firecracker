// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::fmt::Display;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Contains all CPU feature configuration for CPUID and MSRs (x86) when using KVM.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CpuConfigurationSet {
    /// Arch-general features
    /// TODO Placeholder for General-Purpose CPUID structure
    pub arch_features: Vec<LeafEntry>,
    /// Model-specific registers
    pub model_features: Vec<ModelRegisterValue>,
    /// List of entries for CPU features to be configured for a vCPU.
    pub cpu_features: Vec<CpuConfigurationAttribute>,
}

/// Configuration attribute
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CpuConfigurationAttribute {
    /// Symbolic name of the CPU feature.
    pub name: String,
    /// Flag to specify whether to enable or disable the feature on a vCPU.
    pub is_enabled: bool,
}

/// Model-specific register's key-value pair
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ModelRegisterValue {
    /// Address pointer
    pub register_address: u32,
    /// Value to be written
    pub register_value: u32,
}

/// TODO Placeholder for General-Purpose CPUID structure
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LeafEntry {}

/// Errors associated with configuring the microVM.
#[derive(Debug, PartialEq, Error)]
pub enum CpuConfigError {
    /// Unknown/Undefined CPU feature name
    #[error("Unknown or undefined CPU feature name")]
    UndefinedCpuFeatureName,
}

impl Display for CpuConfigurationSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut cpu_config_entries: String = String::from("CPU Feature Config Entries:\n");
        for config_entry in self.cpu_features.as_slice().into_iter() {
            cpu_config_entries = format!(
                "{}(name: {}, is_enabled:{})\n",
                cpu_config_entries, config_entry.name, config_entry.is_enabled
            );
        }

        write!(f, "{}\n", cpu_config_entries)
    }
}
