// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::devices::virtio::pmem::device::{Pmem, PmemError};

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
}

/// Wrapper for the collection that holds all the Pmem devices.
#[derive(Debug, Default)]
pub struct PmemBuilder {
    /// The list of pmem devices
    pub devices: Vec<Arc<Mutex<Pmem>>>,
}

impl PmemBuilder {
    /// Specifies whether there is a root block device already present in the list.
    pub fn has_root_device(&self) -> bool {
        self.devices
            .iter()
            .any(|d| d.lock().unwrap().config.root_device)
    }

    /// Build a device from the config
    pub fn build(
        &mut self,
        config: PmemConfig,
        has_block_root: bool,
    ) -> Result<(), PmemConfigError> {
        if config.root_device && has_block_root {
            return Err(PmemConfigError::AddingSecondRootDevice);
        }
        let position = self
            .devices
            .iter()
            .position(|d| d.lock().unwrap().config.id == config.id);
        if let Some(index) = position {
            if !self.devices[index].lock().unwrap().config.root_device
                && config.root_device
                && self.has_root_device()
            {
                return Err(PmemConfigError::RootPmemDeviceAlreadyExist);
            }
            let pmem = Pmem::new(config)?;
            let pmem = Arc::new(Mutex::new(pmem));
            self.devices[index] = pmem;
        } else {
            if config.root_device && self.has_root_device() {
                return Err(PmemConfigError::RootPmemDeviceAlreadyExist);
            }
            let pmem = Pmem::new(config)?;
            let pmem = Arc::new(Mutex::new(pmem));
            self.devices.push(pmem);
        }
        Ok(())
    }

    /// Adds an existing pmem device in the builder. This function should
    /// only be used during snapshot restoration process and should add
    /// devices in the same order as they were in the original VM.
    pub fn add_device(&mut self, device: Arc<Mutex<Pmem>>) {
        self.devices.push(device);
    }

    /// Returns a vec with the structures used to configure the devices.
    pub fn configs(&self) -> Vec<PmemConfig> {
        self.devices
            .iter()
            .map(|b| b.lock().unwrap().config.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_pmem_builder_build() {
        let mut builder = PmemBuilder::default();

        let dummy_file = TempFile::new().unwrap();
        dummy_file.as_file().set_len(Pmem::ALIGNMENT).unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let mut config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path,
            root_device: true,
            read_only: false,
        };
        builder.build(config.clone(), false).unwrap();
        assert_eq!(builder.devices.len(), 1);
        assert!(builder.has_root_device());

        // First device got replaced with new one
        config.root_device = false;
        builder.build(config, false).unwrap();
        assert_eq!(builder.devices.len(), 1);
        assert!(!builder.has_root_device());
    }

    #[test]
    fn test_pmem_builder_build_seconde_root() {
        let mut builder = PmemBuilder::default();

        let dummy_file = TempFile::new().unwrap();
        dummy_file.as_file().set_len(Pmem::ALIGNMENT).unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let mut config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path,
            root_device: true,
            read_only: false,
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

        let dummy_file = TempFile::new().unwrap();
        dummy_file.as_file().set_len(Pmem::ALIGNMENT).unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path,
            root_device: true,
            read_only: false,
        };
        assert!(matches!(
            builder.build(config, true).unwrap_err(),
            PmemConfigError::AddingSecondRootDevice,
        ));
    }
}
