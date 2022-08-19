// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;

use cpuid::Cpuid;
use logger::{IncMetric, METRICS};
use serde::{Deserialize, Serialize};

use crate::{deserialize_cpu_features_from_file, GuestConfigurationError};

/// Contains all CPU feature configuration in reference format for a user's request
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCpuConfigurationApiRequest {
    /// File path that contains a full configuration set pf architecture-general features.
    pub base_arch_features_template_path: String,
    /// TODO - base_special_features_template_path currently ignored
    /// File path that contains a full configuration set for "special" registers.
    // pub base_special_features_template_path: String,
    /// List of entries for CPU features to be configured for a vCPU.
    pub cpu_feature_overrides: Vec<CpuConfigurationAttribute>,
}

/// Contains all CPU feature configuration in binary format for CPUID and MSRs (x86).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCpuConfiguration {
    /// Blob for architecture general features (CPUID for x86)
    pub base_arch_features_configuration: Cpuid,
    /// TODO - base_special_features_template_path currently ignored
    /// Blob configuration set for "special" registers. (MSRs for x86)
    // pub base_special_features_configuration: TBD,
    /// List of entries for CPU features to be configured for a vCPU.
    pub cpu_feature_overrides: Vec<CpuConfigurationAttribute>,
}

/// Configuration attribute
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CpuConfigurationAttribute {
    /// Symbolic name of the CPU feature.
    pub name: String,
    /// Flag to specify whether to enable or disable the feature on a vCPU.
    pub is_enabled: bool,
}

impl TryFrom<&[u8]> for CustomCpuConfigurationApiRequest {
    type Error = GuestConfigurationError;

    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        from_json_bytes(item)
    }
}

impl TryFrom<&str> for CustomCpuConfigurationApiRequest {
    type Error = GuestConfigurationError;

    fn try_from(item: &str) -> Result<Self, Self::Error> {
        from_json_bytes(item.as_bytes())
    }
}

impl TryFrom<CustomCpuConfigurationApiRequest> for CustomCpuConfiguration {
    type Error = GuestConfigurationError;

    fn try_from(config_request: CustomCpuConfigurationApiRequest) -> Result<Self, Self::Error> {
        // General features baseline config
        let general_arch_config_result = deserialize_cpu_features_from_file(
            config_request.base_arch_features_template_path.as_str(),
        );

        general_arch_config_result.map(|cpuid| CustomCpuConfiguration {
            base_arch_features_configuration: cpuid,

            // TODO - Special features baseline config

            // CPU feature override config
            cpu_feature_overrides: config_request.cpu_feature_overrides,
        })
    }
}

impl Display for CustomCpuConfigurationApiRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut cpu_config_entries: String = String::from("CPU Feature Override Entries:\n");
        for config_entry in self.cpu_feature_overrides.as_slice().into_iter() {
            cpu_config_entries = format!(
                "{}(name: {}, is_enabled:{})\n",
                cpu_config_entries, config_entry.name, config_entry.is_enabled
            );
        }

        let cpu_base_config = format!(
            "{}\n{}\n",
            "General architecture base configuration template path: ",
            self.base_arch_features_template_path,
        );

        write!(f, "{}\n{}\n", cpu_base_config, cpu_config_entries)
    }
}

fn from_json_bytes(
    config: &[u8],
) -> Result<CustomCpuConfigurationApiRequest, GuestConfigurationError> {
    METRICS.put_api_requests.cpu_cfg_count.inc();
    serde_json::from_slice::<CustomCpuConfigurationApiRequest>(config).map_err(|err| {
        METRICS.put_api_requests.cpu_cfg_fails.inc();
        GuestConfigurationError::JsonError(err)
    })
}
