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

/// Enclave configuration errors.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum EnclaveConfigError {
    /// No enclave has been configured
    NotConfigured,
    /// dmb_size_mib ({0}) must be a multiple of 2 between 2 and 256 MiB
    InvalidDmbSize(u64),
    /// dmb_size_mib cannot be set in direct mode (no DMB is used)
    DmbSizeInDirectMode,
}

/// Validated per-device DMB size in MiB: a multiple of 2 between 2 and 256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u64")]
pub struct DmbSizeMib(u64);

impl DmbSizeMib {
    /// Return the validated size in MiB.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl Default for DmbSizeMib {
    fn default() -> Self {
        Self(DEFAULT_DMB_SIZE_MIB)
    }
}

impl TryFrom<u64> for DmbSizeMib {
    type Error = EnclaveConfigError;

    fn try_from(size_mib: u64) -> Result<Self, Self::Error> {
        if !(DMB_MIN_MIB..=DMB_MAX_MIB).contains(&size_mib)
            || !size_mib.is_multiple_of(DMB_GRANULARITY_MIB)
        {
            return Err(EnclaveConfigError::InvalidDmbSize(size_mib));
        }
        Ok(Self(size_mib))
    }
}

/// Per-parent-NUMA-node placement of a slice of the enclave's vCPUs and memory.
///
/// The `vcpu_count` and `mem_size_mib` sums across all nodes must equal
/// `MachineConfig::vcpu_count` and `MachineConfig::mem_size_mib`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnclaveNumaNode {
    /// Parent NUMA node id to place this slice of vCPUs and memory on.
    pub parent_numa: u16,
    /// Number of vCPUs to place on `parent_numa`.
    pub vcpu_count: u16,
    /// Enclave RAM (MiB) to place on `parent_numa`.
    pub mem_size_mib: usize,
}

/// Minimal enclave-specific config. Everything else (kernel, initrd, boot_args,
/// vcpu_count, mem_size_mib) is reused from existing `BootSourceConfig` and
/// `MachineConfig`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// `false` (default) -> confidential mode with per-device DMBs sized by
    /// each device's `dmb_size_mib`.
    /// `true` -> direct mode, sharing enclave RAM with the parent.
    #[serde(default)]
    pub direct_mode: bool,
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
    /// Enable PCIe hotplug mode.
    /// When set, devices can be attached after start.
    #[serde(default)]
    pub hotplug_mode: bool,
    /// Per-parent-NUMA-node placement of vCPUs and memory.
    ///
    /// Omitting this places all vCPUs and memory on parent NUMA node 0. Otherwise
    /// each entry pins a slice to a parent NUMA node; the `vcpu_count` and
    /// `mem_size_mib` sums must match `MachineConfig`. Always populated on the
    /// reported config, so `GET /enclave` shows the placement in effect.
    #[serde(default)]
    pub numa_nodes: Option<Vec<EnclaveNumaNode>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dmb_size_default_is_valid() {
        assert_eq!(
            DmbSizeMib::try_from(DEFAULT_DMB_SIZE_MIB),
            Ok(DmbSizeMib::default())
        );
    }

    #[test]
    fn test_deserialize_rejects_unknown_field() {
        // A misspelled flag must not be silently ignored.
        serde_json::from_str::<EnclaveConfig>(r#"{"debug": true}"#).unwrap_err();
        serde_json::from_str::<EnclaveConfig>(
            r#"{"numa_nodes":[{"parent_numa":0,"vcpu_count":1,"mem_size_mib":256,"nope":1}]}"#,
        )
        .unwrap_err();
        assert!(
            serde_json::from_str::<EnclaveConfig>(r#"{"debug_mode": true}"#)
                .unwrap()
                .debug_mode
        );
    }

    #[test]
    fn test_enclave_config_default() {
        let config = EnclaveConfig::default();
        assert_eq!(config.cpu_ids, None);
        assert!(!config.debug_mode);
        // Confidential is the default mode.
        assert!(!config.direct_mode);
        assert!(!config.cpu_overcommit);
        assert!(!config.cpu_accounting);
        assert!(!config.hotplug_mode);
        assert_eq!(config.numa_nodes, None);
    }

    #[test]
    fn test_enclave_config_serde_roundtrip() {
        let config = EnclaveConfig {
            cpu_ids: Some(vec![2, 3]),
            debug_mode: true,
            direct_mode: true,
            cpu_overcommit: true,
            cpu_accounting: true,
            hotplug_mode: true,
            numa_nodes: Some(vec![
                EnclaveNumaNode {
                    parent_numa: 0,
                    vcpu_count: 1,
                    mem_size_mib: 256,
                },
                EnclaveNumaNode {
                    parent_numa: 1,
                    vcpu_count: 1,
                    mem_size_mib: 256,
                },
            ]),
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
        // Omitted fields use their defaults.
        assert!(!config.direct_mode);
        assert!(!config.cpu_overcommit);
        assert!(!config.cpu_accounting);
        assert_eq!(config.numa_nodes, None);
    }

    #[test]
    fn test_dmb_size_validation() {
        for valid in [2, 256] {
            assert_eq!(DmbSizeMib::try_from(valid).unwrap().get(), valid);
        }

        for invalid in [0, 1, 3, 255, 258] {
            assert_eq!(
                DmbSizeMib::try_from(invalid),
                Err(EnclaveConfigError::InvalidDmbSize(invalid)),
                "size {invalid} should be rejected"
            );
        }

        let error = serde_json::from_str::<DmbSizeMib>("300")
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be a multiple of 2 between 2 and 256 MiB"));
        assert_eq!(serde_json::from_str::<DmbSizeMib>("32").unwrap().get(), 32);
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
