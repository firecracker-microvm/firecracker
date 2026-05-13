// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::devices::virtio::pmem::device::PmemError;
use crate::vmm_config::RateLimiterConfig;

/// Errors associated wit the operations allowed on a pmem device
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PmemConfigError {
    /// Attempt to add pmem as a root device while the root device defined as a block device
    AddingSecondRootDevice,
    /// A root pmem device already exist
    RootPmemDeviceAlreadyExist,
    /// Unable to create the virtio-pmem device: {0}
    CreateDevice(#[from] PmemError),
    /// Error accessing underlying file: {0}
    File(std::io::Error),
    /// Unable to patch the pmem device: {0} Please verify the request arguments.
    DeviceUpdate(crate::VmmError),
}

/// Configuration for updating a pmem device at runtime.
/// Only the rate limiter can be updated.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PmemDeviceUpdateConfig {
    /// The pmem device ID.
    pub id: String,
    /// New rate limiter config.
    pub rate_limiter: Option<RateLimiterConfig>,
}

/// Use this structure to setup a Pmem device before boothing the kernel.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PmemConfig {
    /// Unique identifier of the device.
    pub id: String,
    /// Path of the drive.
    pub path_on_host: String,
    /// Use this pmem device for rootfs
    #[serde(default)]
    pub root_device: bool,
    /// Map the file as read only
    #[serde(default)]
    pub read_only: bool,
    /// Rate Limiter for flush operations.
    pub rate_limiter: Option<RateLimiterConfig>,
}

/// Wrapper for the collection that holds all the Pmem device configs.
#[derive(Debug, Default)]
pub struct PmemBuilder {
    /// The list of pmem device configs
    pub configs: Vec<PmemConfig>,
}

impl PmemBuilder {
    /// Specifies whether there is a root block device already present in the list.
    pub fn has_root_device(&self) -> bool {
        self.configs.iter().any(|c| c.root_device)
    }

    /// Add or replace a config, validating root device constraints.
    pub fn build(
        &mut self,
        config: PmemConfig,
        has_block_root: bool,
    ) -> Result<(), PmemConfigError> {
        if config.root_device && has_block_root {
            return Err(PmemConfigError::AddingSecondRootDevice);
        }
        let position = self.configs.iter().position(|c| c.id == config.id);
        if let Some(index) = position {
            if !self.configs[index].root_device && config.root_device && self.has_root_device() {
                return Err(PmemConfigError::RootPmemDeviceAlreadyExist);
            }
            self.configs[index] = config;
        } else {
            if config.root_device && self.has_root_device() {
                return Err(PmemConfigError::RootPmemDeviceAlreadyExist);
            }
            self.configs.push(config);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pmem_builder_build() {
        let mut builder = PmemBuilder::default();

        let mut config = PmemConfig {
            id: "1".into(),
            path_on_host: "/dummy".into(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        builder.build(config.clone(), false).unwrap();
        assert_eq!(builder.configs.len(), 1);
        assert!(builder.has_root_device());

        // First device got replaced with new one
        config.root_device = false;
        builder.build(config, false).unwrap();
        assert_eq!(builder.configs.len(), 1);
        assert!(!builder.has_root_device());
    }

    #[test]
    fn test_pmem_builder_build_seconde_root() {
        let mut builder = PmemBuilder::default();

        let mut config = PmemConfig {
            id: "1".into(),
            path_on_host: "/dummy".into(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        builder.build(config.clone(), false).unwrap();

        config.id = "2".into();
        assert!(matches!(
            builder.build(config.clone(), false).unwrap_err(),
            PmemConfigError::RootPmemDeviceAlreadyExist,
        ));
    }

    #[test]
    fn test_pmem_builder_build_root_with_block_already_a_root() {
        let mut builder = PmemBuilder::default();

        let config = PmemConfig {
            id: "1".into(),
            path_on_host: "/dummy".into(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        assert!(matches!(
            builder.build(config, true).unwrap_err(),
            PmemConfigError::AddingSecondRootDevice,
        ));
    }
}
