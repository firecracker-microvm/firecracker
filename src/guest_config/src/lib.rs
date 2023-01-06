// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use cpuid::Cpuid;
use logger::{debug, error, info};
use serde::{Deserialize, Serialize};

/// Contains types used to configure guest vCPUs.
pub mod cpu;

/// Contains all CPU feature configuration in binary format
/// Currently only contains CPUID configuration (x86).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCpuConfiguration {
    /// Blob for architecture general features (CPUID for x86)
    pub base_arch_config: Cpuid,
}

/// Errors associated with processing CPU configuration
#[derive(Debug, thiserror::Error)]
pub enum GuestConfigurationError {
    /// Error while configuring CPU features via CPUID.
    #[error("Failed to configure CPU (CPUID) features \n [{0}]")]
    CpuId(String),
    /// Error while configuration model-specific registers.
    #[error("Error while configuring CPU features via model-specific registers")]
    MSR,
    /// JSON library(serde) error processing JSON data.
    #[error("Error processing guest configuration in JSON format - [{0}]")]
    JsonError(serde_json::Error),
    /// Unsupported CPU platform.
    #[error("Provided CPUID configures CPU [{0}] that is not supported in Firecracker")]
    UnsupportedCpuPlatform(String),
}

/// Converts JSON string of a Cpuid instance to an in-memory instance.
pub fn deserialize_cpu_config(
    cpu_config_str: &str,
) -> Result<CustomCpuConfiguration, GuestConfigurationError> {
    debug!(
        "Deserializing JSON CPU config structure \n{}",
        &cpu_config_str
    );
    match serde_json::from_str(cpu_config_str) {
        Ok(cpu_config) => {
            info!("Parsed JSON CPU config successfully");
            Ok(cpu_config)
        }
        Err(err) => {
            error!("Failed to parse JSON CPU config");
            Err(GuestConfigurationError::JsonError(err))
        }
    }
}

#[cfg(test)]
mod tests {
    use cpuid::{Cpuid, RawCpuid};
    use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    use kvm_ioctls::Kvm;

    use crate::{deserialize_cpu_config, CustomCpuConfiguration};

    #[test]
    fn test_custom_cpu_config_serialization_lifecycle() {
        let default_cpu_config = supported_cpu_config();
        let cpu_config_json_result = serde_json::to_string_pretty(&default_cpu_config);

        let deserialized_cpu_config_json_result =
            deserialize_cpu_config(cpu_config_json_result.unwrap().as_str());
        assert!(
            deserialized_cpu_config_json_result.is_ok(),
            "{}",
            deserialized_cpu_config_json_result.unwrap_err()
        );

        // Check that the CPU config deserialized from JSON is equal to the
        // default supported configuration
        assert_eq!(
            deserialized_cpu_config_json_result.unwrap(),
            default_cpu_config,
        );
    }

    fn supported_cpu_config() -> CustomCpuConfiguration {
        let kvm_result = Kvm::new();
        assert!(kvm_result.is_ok(), "Unable to access KVM");

        // Create descriptor KVM resource's file descriptor
        let vm_fd_result = kvm_result.as_ref().unwrap().create_vm();
        assert!(vm_fd_result.is_ok(), "{}", vm_fd_result.unwrap_err());

        let kvm_cpuid_result = kvm_result
            .unwrap()
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES);
        assert!(
            kvm_cpuid_result.is_ok(),
            "{}",
            kvm_cpuid_result.unwrap_err()
        );
        let kvm_cpuid = kvm_cpuid_result.unwrap();
        let raw_cpuid = RawCpuid::from(kvm_cpuid);
        let cpuid_result = Cpuid::try_from(raw_cpuid);
        assert!(cpuid_result.is_ok(), "{}", cpuid_result.unwrap_err());
        CustomCpuConfiguration {
            base_arch_config: cpuid_result.unwrap(),
        }
    }
}
