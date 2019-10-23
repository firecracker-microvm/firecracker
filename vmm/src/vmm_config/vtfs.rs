// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::result;

type Result<T> = result::Result<T, VtfsError>;

/// This struct represents the strongly typed equivalent of the json body
/// from vtfs related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VtfsDeviceConfig {
    /// ID of the vtfs device.
    pub drive_id: String,
    /// Path of the drive.
    pub path_on_host: PathBuf,
}

/// Errors associated with `VtfsDeviceConfig`.
#[derive(Debug)]
pub enum VtfsError {
    /// The update is not allowed after booting the microvm.
    UpdateNotAllowedPostBoot,
}

impl Display for VtfsError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::VtfsError::*;
        match *self {
            UpdateNotAllowedPostBoot => {
                write!(f, "The update operation is not allowed after boot.",)
            }
        }
    }
}

/// A list with all the vtfs devices.
#[derive(Default)]
pub struct VtfsDeviceConfigs {
    /// A list of `VtfsDeviceConfig` objects.
    pub configs: Vec<VtfsDeviceConfig>,
}

impl VtfsDeviceConfigs {
    /// Creates an empty list of NetworkInterfaceConfig.
    pub fn new() -> Self {
        VtfsDeviceConfigs {
            configs: Vec::new(),
        }
    }

    /// Gets the index of the device with the specified `drive_id` if it exists in the list.
    pub fn get_index_of_drive_id(&self, drive_id: &str) -> Option<usize> {
        self.configs
            .iter()
            .position(|cfg| cfg.drive_id.eq(drive_id))
    }

    // Update a vtfs device config
    fn update(&mut self, index: usize, new_config: VtfsDeviceConfig) -> Result<()> {
        self.configs[index] = new_config;
        Ok(())
    }

    // Create a vtfs device config
    fn create(&mut self, vtfs_config: VtfsDeviceConfig) -> Result<()> {
        self.configs.push(vtfs_config);
        Ok(())
    }

    /// Inserts `block_device_config` in the block device configuration list.
    /// If an entry with the same id already exists, it will attempt to update
    /// the existing entry.
    /// Inserting a secondary root block device will fail.
    pub fn insert(&mut self, vtfs_config: VtfsDeviceConfig) -> Result<()> {
        // If the id of the drive already exists in the list, the operation is update.
        match self.get_index_of_drive_id(&vtfs_config.drive_id) {
            Some(index) => self.update(index, vtfs_config),
            None => self.create(vtfs_config),
        }
    }
}
