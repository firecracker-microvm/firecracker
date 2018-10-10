// Copyright 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
use std::collections::LinkedList;
use std::path::PathBuf;
use std::result;

use vm::RateLimiterDescription;

type Result<T> = result::Result<T, DriveError>;

#[derive(Debug, PartialEq)]
pub enum DriveError {
    CannotOpenBlockDevice,
    InvalidBlockDeviceID,
    InvalidBlockDevicePath,
    BlockDevicePathAlreadyExists,
    BlockDeviceUpdateFailed,
    BlockDeviceUpdateNotAllowed,
    NotImplemented,
    OperationNotAllowedPreBoot,
    UpdateNotAllowedPostBoot,
    RootBlockDeviceAlreadyAdded,
    SerdeJson,
}

/// Use this structure to set up the Block Device before booting the kernel
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDeviceConfig {
    pub drive_id: String,
    pub path_on_host: PathBuf,
    pub is_root_device: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partuuid: Option<String>,
    pub is_read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiterDescription>,
}

impl BlockDeviceConfig {
    pub fn get_partuuid(&self) -> Option<&String> {
        self.partuuid.as_ref()
    }

    pub fn is_read_only(&self) -> bool {
        self.is_read_only
    }

    pub fn path_on_host(&self) -> &PathBuf {
        &self.path_on_host
    }
}

// Wrapper for the collection that holds all the Block Devices Configs
pub struct BlockDeviceConfigs {
    pub config_list: LinkedList<BlockDeviceConfig>,
    has_root_block: bool,
    has_partuuid_root: bool,
    read_only_root: bool,
}

impl BlockDeviceConfigs {
    pub fn new() -> BlockDeviceConfigs {
        BlockDeviceConfigs {
            config_list: LinkedList::<BlockDeviceConfig>::new(),
            has_root_block: false,
            has_partuuid_root: false,
            read_only_root: false,
        }
    }

    pub fn has_root_block_device(&self) -> bool {
        return self.has_root_block;
    }

    pub fn has_read_only_root(&self) -> bool {
        self.read_only_root
    }

    pub fn has_partuuid_root(&self) -> bool {
        self.has_partuuid_root
    }

    pub fn contains_drive_path(&self, drive_path: PathBuf) -> bool {
        for drive_config in self.config_list.iter() {
            if drive_config.path_on_host == drive_path {
                return true;
            }
        }
        return false;
    }

    pub fn contains_drive_id(&self, drive_id: String) -> bool {
        for drive_config in self.config_list.iter() {
            if drive_config.drive_id == drive_id {
                return true;
            }
        }
        return false;
    }

    /// This function adds a Block Device Config to the list. The root block device is always
    /// added to the beginning of the list. Only one root block device can be added.
    pub fn add(&mut self, block_device_config: BlockDeviceConfig) -> Result<()> {
        // check if the path exists
        if !block_device_config.path_on_host.exists() {
            return Err(DriveError::InvalidBlockDevicePath);
        }

        if self.contains_drive_path(block_device_config.path_on_host.clone()) {
            return Err(DriveError::BlockDevicePathAlreadyExists);
        }

        // check whether the Device Config belongs to a root device
        // we need to satisfy the condition by which a VMM can only have on root device
        if block_device_config.is_root_device {
            if self.has_root_block {
                return Err(DriveError::RootBlockDeviceAlreadyAdded);
            } else {
                self.has_root_block = true;
                self.read_only_root = block_device_config.is_read_only;
                self.has_partuuid_root = block_device_config.partuuid.is_some();
                // Root Device should be the first in the list whether or not PARTUUID is specified
                // in order to avoid bugs in case of switching from partuuid boot scenarios to
                // /dev/vda boot type.
                self.config_list.push_front(block_device_config);
            }
        } else {
            self.config_list.push_back(block_device_config);
        }

        Ok(())
    }

    fn get_root_id(&self) -> Option<String> {
        if !self.has_root_block {
            return None;
        } else {
            for cfg in self.config_list.iter() {
                if cfg.is_root_device {
                    return Some(cfg.drive_id.clone());
                }
            }
        }
        None
    }

    pub fn get_block_device_config(&self, id: &String) -> Result<BlockDeviceConfig> {
        for drive_config in self.config_list.iter() {
            if drive_config.drive_id.eq(id) {
                return Ok(drive_config.clone());
            }
        }
        Err(DriveError::InvalidBlockDeviceID)
    }

    /// This function updates a Block Device Config. The update fails if it would result in two
    /// root block devices. Full updates are allowed via PUT prior to the guest boot. Partial
    /// updates on path_on_host are allowed via PATCH both before and after boot.
    pub fn update(&mut self, block_device_config: &BlockDeviceConfig) -> Result<()> {
        // Check if the path exists
        if !block_device_config.path_on_host.exists() {
            return Err(DriveError::InvalidBlockDevicePath);
        }

        let root_id = self.get_root_id();
        for cfg in self.config_list.iter_mut() {
            if cfg.drive_id == block_device_config.drive_id {
                if cfg.is_root_device {
                    // Check if the root block device is being updated.
                    self.has_root_block = block_device_config.is_root_device;
                    self.read_only_root =
                        block_device_config.is_root_device && block_device_config.is_read_only;
                    self.has_partuuid_root = block_device_config.partuuid.is_some();
                } else if block_device_config.is_root_device {
                    // Check if a second root block device is being added.
                    if root_id.is_some() {
                        return Err(DriveError::RootBlockDeviceAlreadyAdded);
                    } else {
                        // One of the non-root blocks is becoming root.
                        self.has_root_block = true;
                        self.read_only_root = block_device_config.is_read_only;
                        self.has_partuuid_root = block_device_config.partuuid.is_some();
                    }
                }
                cfg.is_root_device = block_device_config.is_root_device;
                cfg.path_on_host = block_device_config.path_on_host.clone();
                cfg.is_read_only = block_device_config.is_read_only;
                cfg.rate_limiter = block_device_config.rate_limiter.clone();
                cfg.partuuid = block_device_config.partuuid.clone();

                return Ok(());
            }
        }

        Err(DriveError::BlockDeviceUpdateFailed)
    }
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use self::tempfile::NamedTempFile;
    use super::*;

    #[test]
    fn test_create_block_devices_configs() {
        let block_devices_configs = BlockDeviceConfigs::new();
        assert_eq!(block_devices_configs.has_root_block_device(), false);
        assert_eq!(block_devices_configs.config_list.len(), 0);
    }

    #[test]
    fn test_add_non_root_block_device() {
        let dummy_file = NamedTempFile::new().unwrap();
        let dummy_path = dummy_file.path().to_path_buf();
        let dummy_id = String::from("1");
        let dummy_block_device = BlockDeviceConfig {
            path_on_host: dummy_path.clone(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: dummy_id.clone(),
            rate_limiter: None,
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(
            block_devices_configs
                .add(dummy_block_device.clone())
                .is_ok()
        );

        assert_eq!(block_devices_configs.has_root_block, false);
        assert_eq!(block_devices_configs.config_list.len(), 1);

        let dev_config = block_devices_configs.config_list.iter().next().unwrap();
        assert_eq!(dev_config, &dummy_block_device);
        assert!(block_devices_configs.contains_drive_path(dummy_path));
        assert!(block_devices_configs.contains_drive_id(dummy_id));
    }

    #[test]
    fn test_add_one_root_block_device() {
        let dummy_file = NamedTempFile::new().unwrap();
        let dummy_path = dummy_file.path().to_path_buf();

        let dummy_block_device = BlockDeviceConfig {
            path_on_host: dummy_path,
            is_root_device: true,
            partuuid: None,
            is_read_only: true,
            drive_id: String::from("1"),
            rate_limiter: None,
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(
            block_devices_configs
                .add(dummy_block_device.clone())
                .is_ok()
        );

        assert_eq!(block_devices_configs.has_root_block, true);
        assert_eq!(block_devices_configs.config_list.len(), 1);
        let dev_config = block_devices_configs.config_list.iter().next().unwrap();
        assert_eq!(dev_config, &dummy_block_device);
        assert_eq!(block_devices_configs.has_read_only_root(), true);
    }

    #[test]
    fn test_add_two_root_block_devices_configs() {
        let dummy_file_1 = NamedTempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.path().to_path_buf();
        let root_block_device_1 = BlockDeviceConfig {
            path_on_host: dummy_path_1,
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("1"),
            rate_limiter: None,
        };

        let dummy_file_2 = NamedTempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.path().to_path_buf();
        let root_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2,
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("2"),
            rate_limiter: None,
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(block_devices_configs.add(root_block_device_1).is_ok());
        assert_eq!(
            block_devices_configs.add(root_block_device_2).unwrap_err(),
            DriveError::RootBlockDeviceAlreadyAdded
        );
    }

    #[test]
    // Test BlockDevicesConfigs::add when you first add the root device and then the other devices.
    fn test_add_root_block_device_first() {
        let dummy_file_1 = NamedTempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.path().to_path_buf();
        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path_1,
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("1"),
            rate_limiter: None,
        };

        let dummy_file_2 = NamedTempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.path().to_path_buf();
        let dummy_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2,
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("2"),
            rate_limiter: None,
        };

        let dummy_file_3 = NamedTempFile::new().unwrap();
        let dummy_path_3 = dummy_file_3.path().to_path_buf();
        let dummy_block_device_3 = BlockDeviceConfig {
            path_on_host: dummy_path_3,
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("3"),
            rate_limiter: None,
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(block_devices_configs.add(root_block_device.clone()).is_ok());
        assert!(
            block_devices_configs
                .add(dummy_block_device_2.clone())
                .is_ok()
        );
        assert!(
            block_devices_configs
                .add(dummy_block_device_3.clone())
                .is_ok()
        );

        assert_eq!(block_devices_configs.has_root_block_device(), true);
        assert_eq!(block_devices_configs.has_partuuid_root(), false);
        assert_eq!(block_devices_configs.config_list.len(), 3);

        let mut block_dev_iter = block_devices_configs.config_list.iter();
        assert_eq!(block_dev_iter.next().unwrap(), &root_block_device);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_2);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_3);
    }

    #[test]
    // Test BlockDevicesConfigs::add when you add other devices first and then the root device.
    fn test_root_block_device_add_last() {
        let dummy_file_1 = NamedTempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.path().to_path_buf();
        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path_1.clone(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("1"),
            rate_limiter: None,
        };

        let dummy_file_2 = NamedTempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.path().to_path_buf();
        let dummy_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2,
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("2"),
            rate_limiter: None,
        };

        let dummy_file_3 = NamedTempFile::new().unwrap();
        let dummy_path_3 = dummy_file_3.path().to_path_buf();
        let dummy_block_device_3 = BlockDeviceConfig {
            path_on_host: dummy_path_3,
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("3"),
            rate_limiter: None,
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(
            block_devices_configs
                .add(dummy_block_device_2.clone())
                .is_ok()
        );
        assert!(
            block_devices_configs
                .add(dummy_block_device_3.clone())
                .is_ok()
        );
        assert!(block_devices_configs.add(root_block_device.clone()).is_ok());

        assert_eq!(block_devices_configs.has_root_block_device(), true);
        assert_eq!(block_devices_configs.has_partuuid_root(), false);
        assert_eq!(block_devices_configs.config_list.len(), 3);

        let mut block_dev_iter = block_devices_configs.config_list.iter();
        // The root device should be first in the list no matter of the order in
        // which the devices were added.
        assert_eq!(block_dev_iter.next().unwrap(), &root_block_device);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_2);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_3);
    }

    #[test]
    fn test_update() {
        let dummy_file_1 = NamedTempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.path().to_path_buf();
        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path_1.clone(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("1"),
            rate_limiter: None,
        };

        let dummy_file_2 = NamedTempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.path().to_path_buf();
        let mut dummy_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2.clone(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("2"),
            rate_limiter: None,
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();

        // Add 2 block devices
        assert!(block_devices_configs.add(root_block_device.clone()).is_ok());
        assert!(
            block_devices_configs
                .add(dummy_block_device_2.clone())
                .is_ok()
        );

        // Get OK
        assert!(
            block_devices_configs
                .get_block_device_config(&String::from("1"))
                .eq(&Ok(root_block_device))
        );

        // Get with invalid ID
        assert!(
            block_devices_configs
                .get_block_device_config(&String::from("foo"))
                .is_err()
        );

        // Update OK
        dummy_block_device_2.is_read_only = true;
        assert!(block_devices_configs.update(&dummy_block_device_2).is_ok());

        // Update with invalid path
        let dummy_filename_3 = String::from("test_update_3");
        let dummy_path_3 = PathBuf::from(dummy_filename_3.clone());
        dummy_block_device_2.path_on_host = dummy_path_3;
        assert!(block_devices_configs.update(&dummy_block_device_2).is_err());

        // Update with 2 root block devices
        dummy_block_device_2.path_on_host = dummy_path_2.clone();
        dummy_block_device_2.is_root_device = true;
        assert!(block_devices_configs.update(&dummy_block_device_2).is_err());

        // Switch roots and add a PARTUUID for the new one  .
        let root_block_device_old = BlockDeviceConfig {
            path_on_host: dummy_path_1,
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("1"),
            rate_limiter: None,
        };
        let root_block_device_new = BlockDeviceConfig {
            path_on_host: dummy_path_2,
            is_root_device: true,
            partuuid: Some("0eaa91a0-01".to_string()),
            is_read_only: false,
            drive_id: String::from("2"),
            rate_limiter: None,
        };
        assert!(&block_devices_configs.update(&root_block_device_old).is_ok());
        assert!(&block_devices_configs.update(&root_block_device_new).is_ok());
        assert!(block_devices_configs.has_partuuid_root);
    }
}
