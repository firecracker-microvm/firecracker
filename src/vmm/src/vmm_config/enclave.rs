// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enclave-specific configuration for Nitro Enclaves mode.

use serde::{Deserialize, Serialize};

/// Default per-device DMB size in MiB, used when `dmb_size_mib` is omitted.
pub const DEFAULT_DMB_SIZE_MIB: u64 = 16;

/// Minimum per-device DMB size in MiB.
const DMB_MIN_MIB: u64 = 2;

/// Maximum per-device DMB size in MiB (the NE driver rejects regions above this).
const DMB_MAX_MIB: u64 = 256;

/// DMB size granularity in MiB. Sizes must be a multiple of this, matching the
/// 2 MiB allocation alignment used for the buffer.
const DMB_GRANULARITY_MIB: u64 = 2;

/// Errors validating an [`EnclaveConfig`].
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum EnclaveConfigError {
    /// dmb_size_mib ({0}) must be a multiple of 2 between 2 and 256 MiB
    InvalidDmbSize(u64),
    /// dmb_size_mib cannot be set in direct mode (no DMB is used)
    DmbSizeInDirectMode,
}

/// Minimal enclave-specific config. Everything else (kernel, initrd, boot_args,
/// vcpu_count, mem_size_mib) is reused from existing `BootSourceConfig` and
/// `MachineConfig`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct EnclaveConfig {
    /// Specific CPU IDs from the NE CPU pool.
    ///
    /// `None` -> use NE_ADD_ANY_VCPU (kernel picks from the dynamic pool).
    /// `Some(ids)` -> use NE_ADD_VCPU per ID (explicit pinning).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_ids: Option<Vec<u32>>,
    /// Enable debug mode.
    #[serde(default)]
    pub debug_mode: bool,
    /// Run the enclave in direct (non-confidential) mode.
    ///
    /// `false` (default) -> confidential mode with per-device DMBs.
    /// `true` -> direct mode, sharing enclave RAM with the parent.
    #[serde(default)]
    pub direct_mode: bool,
    /// Per-device DMB size in MiB for confidential mode.
    ///
    /// `None` -> use the built-in default. Ignored in direct mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dmb_size_mib: Option<u64>,
    /// Enable CPU overcommit mode.
    ///
    /// Host-scheduled (floating) vCPUs sharing the parent's overcommit pool,
    /// instead of dedicated pinned cores from the NE CPU pool.
    #[serde(default)]
    pub cpu_overcommit: bool,
    /// Enable CPU accounting mode.
    ///
    /// Host-side per-vCPU time accounting (Parent-PID visibility): the NE
    /// driver attributes each vCPU's guest time to a parent-side thread.
    #[serde(default)]
    pub cpu_accounting: bool,
}

impl EnclaveConfig {
    /// Validate the config. Rejects a `dmb_size_mib` that is set in direct mode
    /// (where no DMB is used) or that is out of range / misaligned.
    pub fn validate(&self) -> Result<(), EnclaveConfigError> {
        if let Some(size_mib) = self.dmb_size_mib {
            if self.direct_mode {
                return Err(EnclaveConfigError::DmbSizeInDirectMode);
            }
            if !(DMB_MIN_MIB..=DMB_MAX_MIB).contains(&size_mib)
                || size_mib % DMB_GRANULARITY_MIB != 0
            {
                return Err(EnclaveConfigError::InvalidDmbSize(size_mib));
            }
        }
        Ok(())
    }

    /// Resolve the per-device DMB size in MiB for confidential mode.
    ///
    /// Returns `None` in direct mode (no DMB is allocated); otherwise the
    /// configured size, or [`DEFAULT_DMB_SIZE_MIB`] when unset.
    pub fn dmb_size_mib(&self) -> Option<u64> {
        if self.direct_mode {
            None
        } else {
            Some(self.dmb_size_mib.unwrap_or(DEFAULT_DMB_SIZE_MIB))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enclave_config_default() {
        let config = EnclaveConfig::default();
        assert_eq!(config.cpu_ids, None);
        assert!(!config.debug_mode);
        // Confidential is the default mode.
        assert!(!config.direct_mode);
        assert_eq!(config.dmb_size_mib, None);
        assert!(!config.cpu_overcommit);
        assert!(!config.cpu_accounting);
    }

    #[test]
    fn test_enclave_config_serde_roundtrip() {
        let config = EnclaveConfig {
            cpu_ids: Some(vec![2, 3]),
            debug_mode: true,
            direct_mode: true,
            dmb_size_mib: Some(8),
            cpu_overcommit: true,
            cpu_accounting: true,
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
        // Omitted fields default to confidential mode with the built-in DMB size.
        assert!(!config.direct_mode);
        assert_eq!(config.dmb_size_mib, None);
        assert!(!config.cpu_overcommit);
        assert!(!config.cpu_accounting);
    }

    #[test]
    fn test_dmb_size_default_resolution() {
        // Confidential mode with omitted size resolves to the built-in default.
        assert_eq!(
            EnclaveConfig::default().dmb_size_mib(),
            Some(DEFAULT_DMB_SIZE_MIB)
        );
        // An explicit size is returned as-is.
        let config = EnclaveConfig {
            dmb_size_mib: Some(8),
            ..Default::default()
        };
        assert_eq!(config.dmb_size_mib(), Some(8));
        // Direct mode never allocates a DMB.
        let config = EnclaveConfig {
            direct_mode: true,
            ..Default::default()
        };
        assert_eq!(config.dmb_size_mib(), None);
    }

    #[test]
    fn test_dmb_size_validation() {
        let with_size = |size_mib: Option<u64>| EnclaveConfig {
            dmb_size_mib: size_mib,
            ..Default::default()
        };

        // Omitted is valid (uses the default).
        with_size(None).validate().unwrap();
        // Valid: multiples of 2 MiB within [2, 256].
        for ok in [2, 8, 16, 256] {
            with_size(Some(ok)).validate().unwrap();
        }
        // Invalid: zero, below min, odd (misaligned), and above max.
        for bad in [0, 1, 3, 15, 257, 258, 512] {
            assert_eq!(
                with_size(Some(bad)).validate(),
                Err(EnclaveConfigError::InvalidDmbSize(bad)),
                "size {bad} should be rejected"
            );
        }
    }

    #[test]
    fn test_dmb_size_rejected_in_direct_mode() {
        // dmb_size_mib is meaningless in direct mode and must be rejected,
        // even when the size itself would otherwise be valid.
        let config = EnclaveConfig {
            direct_mode: true,
            dmb_size_mib: Some(16),
            ..Default::default()
        };
        assert_eq!(
            config.validate(),
            Err(EnclaveConfigError::DmbSizeInDirectMode)
        );

        // Direct mode without a DMB size is fine.
        let config = EnclaveConfig {
            direct_mode: true,
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn test_enclave_config_cpu_overcommit_json() {
        let json = r#"{"cpu_overcommit": true}"#;
        let config: EnclaveConfig = serde_json::from_str(json).unwrap();
        assert!(config.cpu_overcommit);
    }

    #[test]
    fn test_enclave_config_cpu_accounting_json() {
        let json = r#"{"cpu_accounting": true}"#;
        let config: EnclaveConfig = serde_json::from_str(json).unwrap();
        assert!(config.cpu_accounting);
    }
}
