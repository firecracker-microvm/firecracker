// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::io;
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Mutex};

use super::RateLimiterConfig;
use devices::virtio::Block;

type Result<T> = result::Result<T, DriveError>;

/// Errors associated with the operations allowed on a drive.
#[derive(Debug)]
pub enum DriveError {
    /// Cannot update the block device.
    BlockDeviceUpdateFailed,
    /// Unable to seek the block device backing file due to invalid permissions or
    /// the file was corrupted.
    CreateBlockDevice(io::Error),
    /// Failed to create a `RateLimiter` object.
    CreateRateLimiter(io::Error),
    /// The block device ID is invalid.
    InvalidBlockDeviceID,
    /// The block device path is invalid.
    InvalidBlockDevicePath,
    /// Cannot open block device due to invalid permissions or path.
    OpenBlockDevice(io::Error),
    /// A root block device was already added.
    RootBlockDeviceAlreadyAdded,
}

impl Display for DriveError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::DriveError::*;
        match *self {
            CreateBlockDevice(ref e) => write!(
                f,
                "Unable to seek the block device backing file due to invalid permissions or \
                 the file was corrupted. Error number: {}",
                e
            ),
            BlockDeviceUpdateFailed => write!(f, "The update operation failed!"),
            CreateRateLimiter(ref e) => write!(f, "Cannot create RateLimiter: {}", e),
            InvalidBlockDeviceID => write!(f, "Invalid block device ID!"),
            InvalidBlockDevicePath => write!(f, "Invalid block device path!"),
            OpenBlockDevice(ref e) => write!(
                f,
                "Cannot open block device. Invalid permission/path: {}",
                e
            ),
            RootBlockDeviceAlreadyAdded => write!(f, "A root block device already exists!"),
        }
    }
}

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BlockDeviceConfig {
    /// Unique identifier of the drive.
    pub drive_id: String,
    /// Path of the drive.
    pub path_on_host: String,
    /// If set to true, it makes the current device the root block device.
    /// Setting this flag to true will mount the block device in the
    /// guest under /dev/vda unless the partuuid is present.
    pub is_root_device: bool,
    /// Part-UUID. Represents the unique id of the boot partition of this device. It is
    /// optional and it will be used only if the `is_root_device` field is true.
    pub partuuid: Option<String>,
    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_read_only: bool,
    /// Rate Limiter for I/O operations.
    pub rate_limiter: Option<RateLimiterConfig>,
}

/// Wrapper for the collection that holds all the Block Devices
#[derive(Default)]
pub struct BlockBuilder {
    /// The list of block devices.
    /// There can be at most one root block device and it would be the first in the list.
    // Root Device should be the first in the list whether or not PARTUUID is
    // specified in order to avoid bugs in case of switching from partuuid boot
    // scenarios to /dev/vda boot type.
    pub list: VecDeque<Arc<Mutex<Block>>>,
}

impl BlockBuilder {
    /// Constructor for BlockDevices. It initializes an empty LinkedList.
    pub fn new() -> Self {
        Self {
            list: VecDeque::<Arc<Mutex<Block>>>::new(),
        }
    }

    /// Specifies whether there is a root block device already present in the list.
    fn has_root_device(&self) -> bool {
        // If there is a root device, it would be at the top of the list.
        if let Some(block) = self.list.get(0) {
            block.lock().unwrap().is_root_device()
        } else {
            false
        }
    }

    /// Gets the index of the device with the specified `drive_id` if it exists in the list.
    fn get_index_of_drive_id(&self, drive_id: &str) -> Option<usize> {
        self.list
            .iter()
            .position(|b| b.lock().unwrap().id().eq(drive_id))
    }

    /// Inserts a `Block` in the block devices list using the specified configuration.
    /// If a block with the same id already exists, it will overwrite it.
    /// Inserting a secondary root block device will fail.
    pub fn insert(&mut self, config: BlockDeviceConfig) -> Result<()> {
        let is_root_device = config.is_root_device;
        let position = self.get_index_of_drive_id(&config.drive_id);
        let has_root_block = self.has_root_device();

        // Don't allow adding a second root block device.
        // If the new device cfg is root and not an update to the existing root, fail fast.
        if is_root_device && has_root_block && position != Some(0) {
            return Err(DriveError::RootBlockDeviceAlreadyAdded);
        }

        let block_dev = Arc::new(Mutex::new(Self::create_block(config)?));
        // If the id of the drive already exists in the list, the operation is update/overwrite.
        match position {
            // New block device.
            None => {
                if is_root_device {
                    self.list.push_front(block_dev);
                } else {
                    self.list.push_back(block_dev);
                }
            }
            // Update existing block device.
            Some(index) => {
                // Update the slot with the new block.
                self.list[index] = block_dev;
                // Check if the root block device is being updated.
                if index != 0 && is_root_device {
                    // Make sure the root device is on the first position.
                    self.list.swap(0, index);
                }
            }
        }
        Ok(())
    }

    /// Creates a Block device from a BlockDeviceConfig.
    pub fn create_block(block_device_config: BlockDeviceConfig) -> Result<Block> {
        // check if the path exists
        let path_on_host = PathBuf::from(&block_device_config.path_on_host);
        if !path_on_host.exists() {
            return Err(DriveError::InvalidBlockDevicePath);
        }

        let rate_limiter = block_device_config
            .rate_limiter
            .map(super::RateLimiterConfig::try_into)
            .transpose()
            .map_err(DriveError::CreateRateLimiter)?;

        // Create and return the Block device
        devices::virtio::Block::new(
            block_device_config.drive_id,
            block_device_config.partuuid,
            block_device_config.path_on_host,
            block_device_config.is_read_only,
            block_device_config.is_root_device,
            rate_limiter.unwrap_or_default(),
        )
        .map_err(DriveError::CreateBlockDevice)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use utils::tempfile::TempFile;

    impl PartialEq for DriveError {
        fn eq(&self, other: &DriveError) -> bool {
            self.to_string() == other.to_string()
        }
    }

    // This implementation is used only in tests.
    // We cannot directly derive clone because RateLimiter does not implement clone.
    impl Clone for BlockDeviceConfig {
        fn clone(&self) -> Self {
            BlockDeviceConfig {
                path_on_host: self.path_on_host.clone(),
                is_root_device: self.is_root_device,
                partuuid: self.partuuid.clone(),
                is_read_only: self.is_read_only,
                drive_id: self.drive_id.clone(),
                rate_limiter: None,
            }
        }
    }

    #[test]
    fn test_create_block_devs() {
        let block_devs = BlockBuilder::new();
        assert_eq!(block_devs.list.len(), 0);
    }

    #[test]
    fn test_add_non_root_block_device() {
        let dummy_file = TempFile::new().unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let dummy_id = String::from("1");
        let dummy_block_device = BlockDeviceConfig {
            path_on_host: dummy_path.clone(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: dummy_id.clone(),
            rate_limiter: None,
        };

        let mut block_devs = BlockBuilder::new();
        assert!(block_devs.insert(dummy_block_device.clone()).is_ok());

        assert!(!block_devs.has_root_device());
        assert_eq!(block_devs.list.len(), 1);

        {
            let block = block_devs.list[0].lock().unwrap();
            assert_eq!(block.id(), &dummy_block_device.drive_id);
            assert_eq!(block.partuuid(), dummy_block_device.partuuid.as_ref());
            assert_eq!(block.is_read_only(), dummy_block_device.is_read_only);
        }
        assert_eq!(block_devs.get_index_of_drive_id(&dummy_id), Some(0));
    }

    #[test]
    fn test_add_one_root_block_device() {
        let dummy_file = TempFile::new().unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();

        let dummy_block_device = BlockDeviceConfig {
            path_on_host: dummy_path,
            is_root_device: true,
            partuuid: None,
            is_read_only: true,
            drive_id: String::from("1"),
            rate_limiter: None,
        };

        let mut block_devs = BlockBuilder::new();
        assert!(block_devs.insert(dummy_block_device.clone()).is_ok());

        assert!(block_devs.has_root_device());
        assert_eq!(block_devs.list.len(), 1);
        {
            let block = block_devs.list[0].lock().unwrap();
            assert_eq!(block.id(), &dummy_block_device.drive_id);
            assert_eq!(block.partuuid(), dummy_block_device.partuuid.as_ref());
            assert_eq!(block.is_read_only(), dummy_block_device.is_read_only);
        }
    }

    #[test]
    fn test_add_two_root_block_devs() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device_1 = BlockDeviceConfig {
            path_on_host: dummy_path_1,
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("1"),
            rate_limiter: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let root_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2,
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("2"),
            rate_limiter: None,
        };

        let mut block_devs = BlockBuilder::new();
        assert!(block_devs.insert(root_block_device_1).is_ok());
        assert_eq!(
            block_devs.insert(root_block_device_2).unwrap_err(),
            DriveError::RootBlockDeviceAlreadyAdded
        );
    }

    #[test]
    // Test BlockDevicesConfigs::add when you first add the root device and then the other devices.
    fn test_add_root_block_device_first() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path_1,
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("1"),
            rate_limiter: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2,
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("2"),
            rate_limiter: None,
        };

        let dummy_file_3 = TempFile::new().unwrap();
        let dummy_path_3 = dummy_file_3.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_3 = BlockDeviceConfig {
            path_on_host: dummy_path_3,
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("3"),
            rate_limiter: None,
        };

        let mut block_devs = BlockBuilder::new();
        assert!(block_devs.insert(dummy_block_dev_2.clone()).is_ok());
        assert!(block_devs.insert(dummy_block_dev_3.clone()).is_ok());
        assert!(block_devs.insert(root_block_device.clone()).is_ok());

        assert_eq!(block_devs.list.len(), 3);

        let mut block_iter = block_devs.list.iter();
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            &root_block_device.drive_id
        );
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            &dummy_block_dev_2.drive_id
        );
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            &dummy_block_dev_3.drive_id
        );
    }

    #[test]
    // Test BlockDevicesConfigs::add when you add other devices first and then the root device.
    fn test_root_block_device_add_last() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path_1.clone(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("1"),
            rate_limiter: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2,
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("2"),
            rate_limiter: None,
        };

        let dummy_file_3 = TempFile::new().unwrap();
        let dummy_path_3 = dummy_file_3.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_3 = BlockDeviceConfig {
            path_on_host: dummy_path_3,
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("3"),
            rate_limiter: None,
        };

        let mut block_devs = BlockBuilder::new();
        assert!(block_devs.insert(dummy_block_dev_2.clone()).is_ok());
        assert!(block_devs.insert(dummy_block_dev_3.clone()).is_ok());
        assert!(block_devs.insert(root_block_device.clone()).is_ok());

        assert_eq!(block_devs.list.len(), 3);

        let mut block_iter = block_devs.list.iter();
        // The root device should be first in the list no matter of the order in
        // which the devices were added.
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            &root_block_device.drive_id
        );
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            &dummy_block_dev_2.drive_id
        );
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            &dummy_block_dev_3.drive_id
        );
    }

    #[test]
    fn test_update() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path_1.clone(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("1"),
            rate_limiter: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let mut dummy_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2.clone(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("2"),
            rate_limiter: None,
        };

        let mut block_devs = BlockBuilder::new();

        // Add 2 block devices.
        assert!(block_devs.insert(root_block_device.clone()).is_ok());
        assert!(block_devs.insert(dummy_block_device_2.clone()).is_ok());

        // Get index zero.
        assert_eq!(
            block_devs.get_index_of_drive_id(&String::from("1")),
            Some(0)
        );

        // Get None.
        assert!(block_devs
            .get_index_of_drive_id(&String::from("foo"))
            .is_none());

        // Test several update cases using dummy_block_device_2.
        // Validate `dummy_block_device_2` is already in the list
        assert!(block_devs
            .get_index_of_drive_id(&dummy_block_device_2.drive_id)
            .is_some());
        // Update OK.
        dummy_block_device_2.is_read_only = true;
        assert!(block_devs.insert(dummy_block_device_2.clone()).is_ok());

        let index = block_devs
            .get_index_of_drive_id(&dummy_block_device_2.drive_id)
            .unwrap();
        // Validate update was successful.
        assert!(block_devs.list[index].lock().unwrap().is_read_only());

        // Update with invalid path.
        let dummy_filename_3 = String::from("test_update_3");
        let dummy_path_3 = dummy_filename_3;
        dummy_block_device_2.path_on_host = dummy_path_3;
        assert_eq!(
            block_devs.insert(dummy_block_device_2.clone()),
            Err(DriveError::InvalidBlockDevicePath)
        );

        // Update with 2 root block devices.
        dummy_block_device_2.path_on_host = dummy_path_2.clone();
        dummy_block_device_2.is_root_device = true;
        assert_eq!(
            block_devs.insert(dummy_block_device_2.clone()),
            Err(DriveError::RootBlockDeviceAlreadyAdded)
        );

        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path_1.clone(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            drive_id: String::from("1"),
            rate_limiter: None,
        };
        // Switch roots and add a PARTUUID for the new one.
        let mut root_block_device_old = root_block_device;
        root_block_device_old.is_root_device = false;
        let root_block_device_new = BlockDeviceConfig {
            path_on_host: dummy_path_2,
            is_root_device: true,
            partuuid: Some("0eaa91a0-01".to_string()),
            is_read_only: false,
            drive_id: String::from("2"),
            rate_limiter: None,
        };
        assert!(block_devs.insert(root_block_device_old).is_ok());
        let root_block_id = root_block_device_new.drive_id.clone();
        assert!(block_devs.insert(root_block_device_new).is_ok());
        assert!(block_devs.has_root_device());
        // Verify it's been moved to the first position.
        assert_eq!(block_devs.list[0].lock().unwrap().id(), &root_block_id);
    }

    #[test]
    fn test_block_config() {
        let dummy_block_file = TempFile::new().unwrap();
        let expected_partuuid = "0eaa91a0-01".to_string();
        let expected_is_read_only = true;

        let block_config = BlockDeviceConfig {
            drive_id: "dummy_drive".to_string(),
            path_on_host: dummy_block_file.as_path().to_str().unwrap().to_string(),
            is_root_device: false,
            partuuid: Some("0eaa91a0-01".to_string()),
            is_read_only: true,
            rate_limiter: None,
        };

        assert_eq!(
            block_config.partuuid.as_ref().unwrap().to_string(),
            expected_partuuid
        );
        assert_eq!(
            block_config.path_on_host,
            dummy_block_file.as_path().to_str().unwrap().to_string()
        );
        assert_eq!(block_config.is_read_only, expected_is_read_only);
    }
}
