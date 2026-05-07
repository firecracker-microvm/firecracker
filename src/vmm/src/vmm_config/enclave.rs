// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enclave-specific configuration for Nitro Enclaves mode.

use serde::{Deserialize, Serialize};

/// Minimal enclave-specific config. Everything else (kernel, initrd, boot_args,
/// vcpu_count, mem_size_mib) is reused from existing `BootSourceConfig` and
/// `MachineConfig`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct EnclaveConfig {
    /// Specific CPU IDs from the NE CPU pool.
    ///
    /// `None` → use NE_ADD_ANY_VCPU (kernel picks from the dynamic pool).
    /// `Some(ids)` → use NE_ADD_VCPU per ID (explicit pinning).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_ids: Option<Vec<u32>>,
    /// Enable debug mode.
    #[serde(default)]
    pub debug_mode: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enclave_config_default() {
        let config = EnclaveConfig::default();
        assert_eq!(config.cpu_ids, None);
        assert!(!config.debug_mode);
    }

    #[test]
    fn test_enclave_config_serde_roundtrip() {
        let config = EnclaveConfig {
            cpu_ids: Some(vec![2, 3]),
            debug_mode: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: EnclaveConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_enclave_config_minimal_json() {
        let json = r#"{"debug_mode": true}"#;
        let config: EnclaveConfig = serde_json::from_str(json).unwrap();
        assert!(config.debug_mode);
        assert_eq!(config.cpu_ids, None);
    }
}
