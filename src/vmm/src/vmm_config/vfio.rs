// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Errors for VFIO device configuration.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VfioConfigError {
    /// Cannot verify path to the VFIO device
    PathDoesNotExist,
}

/// Config for VFIO device
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct VfioConfig {
    /// ID of the device
    pub id: String,
    /// Path to the device
    pub path_on_host: String,
}

/// Config for VFIO passthrough devices
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct VfioConfigs {
    /// VFIO configs
    pub configs: Vec<VfioConfig>,
}

impl VfioConfigs {
    /// Add config to the set. Overwrite existing one if
    /// ids are same.
    pub fn add(&mut self, config: VfioConfig) -> Result<(), VfioConfigError> {
        // A simple sanity check. This does not guarantee that the device will be successfully
        // initialized later on.
        if !Path::new(&config.path_on_host).exists() {
            return Err(VfioConfigError::PathDoesNotExist);
        }
        if let Some(old_config) = self.configs.iter_mut().find(|b| b.id == config.id) {
            old_config.path_on_host = config.path_on_host;
        } else {
            self.configs.push(config);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    #[test]
    fn test_add_vfio_config_and_overwrite() {
        let dir = TempDir::new().unwrap();
        let path1 = dir.as_path().join("dev1");
        let path2 = dir.as_path().join("dev2");
        std::fs::write(&path1, b"").unwrap();
        std::fs::write(&path2, b"").unwrap();

        let mut configs = VfioConfigs::default();
        configs
            .add(VfioConfig {
                id: "dev0".to_string(),
                path_on_host: path1.to_str().unwrap().to_string(),
            })
            .unwrap();
        assert_eq!(configs.configs.len(), 1);
        assert_eq!(configs.configs[0].path_on_host, path1.to_str().unwrap());
        configs
            .add(VfioConfig {
                id: "dev0".to_string(),
                path_on_host: path2.to_str().unwrap().to_string(),
            })
            .unwrap();
        assert_eq!(configs.configs.len(), 1);
        assert_eq!(configs.configs[0].path_on_host, path2.to_str().unwrap());
    }

    #[test]
    fn test_add_vfio_config_empty_path() {
        let mut configs = VfioConfigs::default();
        let err = configs
            .add(VfioConfig {
                id: "dev0".to_string(),
                path_on_host: String::new(),
            })
            .unwrap_err();
        assert!(matches!(err, VfioConfigError::PathDoesNotExist));
    }
}
