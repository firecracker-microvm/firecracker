// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::devices::virtio::mem::VIRTIO_MEM_BLOCK_SIZE;

/// Errors associated with memory hotplug configuration.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MemoryHpConfigError {
    /// Total size must be a multiple of virtio-mem block size ({0} MiB).
    InvalidSize(usize),
}

/// Configuration for memory hotplug device.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryHpConfig {
    /// Total memory size in MiB that can be hotplugged.
    pub total_size_mib: usize,
}

/// Configuration for updating memory hotplug device.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryHpUpdateConfig {
    /// Requested memory size in MiB.
    pub requested_size_mib: usize,
}

/// Memory hotplug device status information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryHpStatus {
    /// Block size in MiB.
    pub block_size_mib: usize,
    /// Total memory size in MiB that can be hotplugged.
    pub total_size_mib: usize,
    /// Currently plugged memory size in MiB.
    pub plugged_size_mib: usize,
    /// Requested memory size in MiB.
    pub requested_size_mib: usize,
}

impl MemoryHpConfig {
    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), MemoryHpConfigError> {
        let block_size_mib = (VIRTIO_MEM_BLOCK_SIZE / (1024 * 1024)) as usize;
        if self.total_size_mib % block_size_mib != 0 {
            return Err(MemoryHpConfigError::InvalidSize(block_size_mib));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_hp_config_validation() {
        let block_size_mib = (VIRTIO_MEM_BLOCK_SIZE / (1024 * 1024)) as u64;

        // Valid size (multiple of block size)
        let config = MemoryHpConfig {
            total_size_mib: block_size_mib * 2,
        };
        assert!(config.validate().is_ok());

        // Invalid size (not a multiple of block size)
        let config = MemoryHpConfig {
            total_size_mib: block_size_mib + 1,
        };
        assert!(config.validate().is_err());
    }
}
