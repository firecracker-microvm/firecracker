// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::convert::TryInto;
use std::io;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::RateLimiterConfig;
pub use crate::devices::virtio::block::file::device::FileEngineType;
use crate::devices::virtio::block::file::{BlockFile, BlockFileError};
use crate::devices::virtio::block::vhost_user::{BlockVhostUser, BlockVhostUserError};
pub use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::Disk;
use crate::VmmError;

/// Errors associated with the operations allowed on a drive.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DriveError {
    /// Unable to create the host-file-backed block device: {0:?}
    CreateBlockFileDevice(BlockFileError),
    /// Could not create a vhost-user-backed Block Device.
    CreateBlockVhostUserDevice(BlockVhostUserError),
    /// Cannot create RateLimiter: {0}
    CreateRateLimiter(io::Error),
    /// Unable to patch the block device: {0}
    DeviceUpdate(VmmError),
    /// Invalid block device path: {0}
    InvalidBlockDevicePath(String),
    /// The readonly is missing.
    MissingReadOnly,
    /// A root block device already exists!
    RootBlockDeviceAlreadyAdded,
    /// Mutliple block device configurations provided.
    MultipleConfigsProvided,
    /// The vhost user socket is invalid: {0}
    InvalidVhostUserSocket(String),
}

/// Configuration for the host-file-backed block device.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Path of the drive.
    pub path_on_host: String,
    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_read_only: bool,
    /// Rate Limiter for I/O operations.
    pub rate_limiter: Option<RateLimiterConfig>,
    /// The type of IO engine used by the device.
    #[serde(default)]
    #[serde(rename = "io_engine")]
    pub file_engine_type: FileEngineType,
}

/// Configuration for the vhost-user-backed block device.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostUserConfig {
    /// Socket path for vhost user
    pub socket: String,
}

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDeviceConfig {
    /// Unique identifier of the drive.
    pub drive_id: String,
    /// Path of the drive.
    pub path_on_host: Option<String>,
    /// If set to true, it makes the current device the root block device.
    /// Setting this flag to true will mount the block device in the
    /// guest under /dev/vda unless the partuuid is present.
    pub is_root_device: bool,
    /// Part-UUID. Represents the unique id of the boot partition of this device. It is
    /// optional and it will be used only if the `is_root_device` field is true.
    pub partuuid: Option<String>,
    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_read_only: Option<bool>,
    /// If set to true, the drive will ignore flush requests coming from
    /// the guest driver.
    #[serde(default)]
    pub cache_type: CacheType,
    /// Rate Limiter for I/O operations.
    pub rate_limiter: Option<RateLimiterConfig>,
    /// The type of IO engine used by the device.
    #[serde(default)]
    #[serde(rename = "io_engine")]
    pub file_engine_type: FileEngineType,
    /// Configuration for the host-file-backed block device.
    pub file: Option<FileConfig>,
    /// Configuration for the vhost-user-backed block device.
    pub vhost_user: Option<VhostUserConfig>,
}

impl From<&BlockFile> for BlockDeviceConfig {
    fn from(block: &BlockFile) -> Self {
        let rl: RateLimiterConfig = block.rate_limiter().into();
        BlockDeviceConfig {
            drive_id: block.id().clone(),
            path_on_host: Some(block.file_path().clone()),
            is_root_device: block.is_root_device(),
            partuuid: block.partuuid().cloned(),
            is_read_only: Some(block.is_read_only()),
            cache_type: block.cache_type(),
            rate_limiter: rl.into_option(),
            file_engine_type: block.file_engine_type(),
            file: Some(FileConfig {
                path_on_host: block.file_path().clone(),
                is_read_only: block.is_read_only(),
                rate_limiter: rl.into_option(),
                file_engine_type: block.file_engine_type(),
            }),
            vhost_user: None,
        }
    }
}

impl From<&BlockVhostUser> for BlockDeviceConfig {
    fn from(block: &BlockVhostUser) -> Self {
        BlockDeviceConfig {
            drive_id: block.id().clone(),
            path_on_host: None,
            is_root_device: block.is_root_device(),
            partuuid: block.partuuid().cloned(),
            is_read_only: Some(block.is_read_only()),
            cache_type: block.cache_type(),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: Some(VhostUserConfig {
                socket: block.socket().clone(),
            }),
        }
    }
}

/// New configuration for the host-file-backed block device.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileUpdateConfig {
    /// Path of the drive.
    pub path_on_host: Option<String>,
    /// Rate Limiter for I/O operations.
    pub rate_limiter: Option<RateLimiterConfig>,
}

/// Only provided fields will be updated. I.e. if any optional fields
/// are missing, they will not be updated.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDeviceUpdateConfig {
    /// The drive ID, as provided by the user at creation time.
    pub drive_id: String,
    /// New block file path on the host. Only provided data will be updated.
    pub path_on_host: Option<String>,
    /// New rate limiter config.
    pub rate_limiter: Option<RateLimiterConfig>,
    /// New configuration for the host-file-backed block device.
    pub file: Option<FileUpdateConfig>,
}

/// Enum to combine all block device types.
/// We have to preserve the order of the devices across all types,
/// so we keep them in a single list.
/// This data structure represents the element of the list.
#[derive(Debug)]
pub enum Block {
    /// Host-file-backed block device.
    FileBacked(Arc<Mutex<BlockFile>>),
    /// Vhost-user-backed block device.
    VhostUserBacked(Arc<Mutex<BlockVhostUser>>),
}

/// Wrapper for the collection that holds all the Block Devices
#[derive(Debug, Default)]
pub struct BlockBuilder {
    /// The list of block devices.
    /// There can be at most one root block device and it would be the first in the list.
    // Root Device should be the first in the list whether or not PARTUUID is
    // specified in order to avoid bugs in case of switching from partuuid boot
    // scenarios to /dev/vda boot type.
    pub list: VecDeque<Block>,
}

impl BlockBuilder {
    /// Constructor for BlockDevices. It initializes an empty LinkedList.
    pub fn new() -> Self {
        Self {
            list: VecDeque::<Block>::new(),
        }
    }

    /// Specifies whether there is a root block device already present in the list.
    fn has_root_device(&self) -> bool {
        // If there is a root device, it would be at the top of the list.
        if let Some(block) = self.list.get(0) {
            match block {
                Block::FileBacked(block) => block.lock().expect("Poisoned lock").is_root_device(),
                Block::VhostUserBacked(block) => {
                    block.lock().expect("Poisoned lock").is_root_device()
                }
            }
        } else {
            false
        }
    }

    /// Gets the index of the device with the specified `drive_id` if it exists in the list.
    fn get_index_of_drive_id(&self, drive_id: &str) -> Option<usize> {
        self.list.iter().position(|b| match b {
            Block::FileBacked(b) => b.lock().expect("Poisoned lock").id().eq(drive_id),
            Block::VhostUserBacked(b) => b.lock().expect("Poisoned lock").id().eq(drive_id),
        })
    }

    /// Inserts an existing block device.
    pub fn add_device(&mut self, block_device: Arc<Mutex<BlockFile>>) {
        if block_device.lock().expect("Poisoned lock").is_root_device() {
            self.list.push_front(Block::FileBacked(block_device));
        } else {
            self.list.push_back(Block::FileBacked(block_device));
        }
    }

    /// Inserts an existing block device.
    pub fn add_vhost_user_device(&mut self, block_device: Arc<Mutex<BlockVhostUser>>) {
        if block_device.lock().expect("Poisoned lock").is_root_device() {
            self.list.push_front(Block::VhostUserBacked(block_device));
        } else {
            self.list.push_back(Block::VhostUserBacked(block_device));
        }
    }

    /// Inserts a `Block` in the block devices list using the specified configuration.
    /// If a block with the same id already exists, it will overwrite it.
    /// Inserting a secondary root block device will fail.
    pub fn insert(&mut self, config: BlockDeviceConfig) -> Result<(), DriveError> {
        let is_root_device = config.is_root_device;
        let position = self.get_index_of_drive_id(&config.drive_id);
        let has_root_block = self.has_root_device();

        // Don't allow adding a second root block device.
        // If the new device cfg is root and not an update to the existing root, fail fast.
        if is_root_device && has_root_block && position != Some(0) {
            return Err(DriveError::RootBlockDeviceAlreadyAdded);
        }

        let block_dev = match (&config.file, &config.vhost_user) {
            (Some(_), Some(_)) => return Err(DriveError::MultipleConfigsProvided),
            (None, Some(_)) => {
                Block::VhostUserBacked(Arc::new(Mutex::new(Self::create_block_vhost_user(config)?)))
            }
            (_, None) => Block::FileBacked(Arc::new(Mutex::new(Self::create_block_file(config)?))),
        };

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

    /// Creates a host-file-backed Block device from a BlockDeviceConfig.
    /// Creates a Block device from a BlockDeviceConfig.
    fn create_block_file(block_device_config: BlockDeviceConfig) -> Result<BlockFile, DriveError> {
        // Give priority to the file configuration and fall back to the legacy parameters.
        let (path_on_host, read_only, rate_limiter, file_engine_type) =
            match block_device_config.file {
                Some(file) => (
                    file.path_on_host,
                    file.is_read_only,
                    file.rate_limiter,
                    file.file_engine_type,
                ),
                None => (
                    block_device_config
                        .path_on_host
                        .ok_or(DriveError::InvalidBlockDevicePath("".to_string()))?,
                    block_device_config
                        .is_read_only
                        .ok_or(DriveError::MissingReadOnly)?,
                    block_device_config.rate_limiter,
                    block_device_config.file_engine_type,
                ),
            };

        // check if the path exists
        if !PathBuf::from(&path_on_host).exists() {
            return Err(DriveError::InvalidBlockDevicePath(path_on_host));
        }

        let rate_limiter = rate_limiter
            .map(super::RateLimiterConfig::try_into)
            .transpose()
            .map_err(DriveError::CreateRateLimiter)?;

        // Create and return the Block device
        BlockFile::new(
            block_device_config.drive_id,
            block_device_config.partuuid,
            block_device_config.cache_type,
            path_on_host,
            read_only,
            block_device_config.is_root_device,
            rate_limiter.unwrap_or_default(),
            file_engine_type,
        )
        .map_err(DriveError::CreateBlockFileDevice)
    }

    /// Creates a vhost-user-backed Block device from a BlockDeviceConfig.
    fn create_block_vhost_user(
        block_device_config: BlockDeviceConfig,
    ) -> Result<BlockVhostUser, DriveError> {
        let socket = match block_device_config.vhost_user {
            Some(vhost_user) => vhost_user.socket,
            None => return Err(DriveError::InvalidVhostUserSocket("".to_string())),
        };

        // Check if the socket exists
        if !PathBuf::from(&socket).exists() {
            return Err(DriveError::InvalidVhostUserSocket(socket));
        }

        // Create and return the Block device
        BlockVhostUser::new(
            block_device_config.drive_id,
            block_device_config.partuuid,
            block_device_config.cache_type,
            block_device_config.is_root_device,
            &socket,
        )
        .map_err(DriveError::CreateBlockVhostUserDevice)
    }

    /// Returns a vec with the structures used to configure the devices.
    pub fn configs(&self) -> Vec<BlockDeviceConfig> {
        let mut ret = vec![];
        for block in &self.list {
            match block {
                Block::FileBacked(block) => {
                    ret.push(BlockDeviceConfig::from(block.lock().unwrap().deref()));
                }
                Block::VhostUserBacked(block) => {
                    ret.push(BlockDeviceConfig::from(block.lock().unwrap().deref()));
                }
            }
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use utils::tempfile::TempFile;

    use super::*;
    use crate::rate_limiter::RateLimiter;

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
                cache_type: self.cache_type,
                is_read_only: self.is_read_only,
                drive_id: self.drive_id.clone(),
                rate_limiter: None,
                file_engine_type: FileEngineType::default(),
                file: self.file.as_ref().map(|self_file| FileConfig {
                    path_on_host: self_file.path_on_host.clone(),
                    is_read_only: self_file.is_read_only,
                    rate_limiter: None,
                    file_engine_type: FileEngineType::default(),
                }),
                vhost_user: None,
            }
        }
    }

    #[test]
    fn test_create_block_devs() {
        let block_devs = BlockBuilder::new();
        assert_eq!(block_devs.list.len(), 0);
    }

    #[test]
    fn test_old_new_put_api() {
        // Test equivalence of the old and new PUT APIs
        let host_file = TempFile::new().unwrap();
        let path = host_file.as_path().to_str().unwrap().to_string();
        let id = String::from("1");
        let engine = FileEngineType::Async;
        let cache = CacheType::Writeback;

        // Configure `path_on_host` and `file_engine_type` via the old API
        let old_api_block_device = BlockDeviceConfig {
            path_on_host: Some(path.clone()),
            is_root_device: false,
            partuuid: None,
            cache_type: cache,
            is_read_only: Some(false),
            drive_id: id.clone(),
            rate_limiter: None,
            file_engine_type: engine,
            file: None,
            vhost_user: None,
        };

        let mut old_api_block_devs = BlockBuilder::new();
        #[allow(clippy::redundant_clone)]
        let res = old_api_block_devs.insert(old_api_block_device.clone());
        assert!(res.is_ok());

        // Configure `path_on_host` and `file_engine_type` via the new API (`file` object)
        let new_api_block_device = BlockDeviceConfig {
            path_on_host: None,
            is_root_device: false,
            partuuid: None,
            cache_type: cache,
            is_read_only: Some(false),
            drive_id: id,
            rate_limiter: None,
            file_engine_type: FileEngineType::Sync, /* make this different to check that it is
                                                     * properly ignored if the `file` object is
                                                     * present */
            file: Some(FileConfig {
                path_on_host: path,
                is_read_only: false,
                rate_limiter: None,
                file_engine_type: FileEngineType::Async,
            }),
            vhost_user: None,
        };

        let mut new_api_block_devs = BlockBuilder::new();
        #[allow(clippy::redundant_clone)]
        let res = new_api_block_devs.insert(new_api_block_device.clone());
        assert!(res.is_ok());

        // Check that configs produces by both APIs are the same
        assert_eq!(old_api_block_devs.configs(), new_api_block_devs.configs());
    }

    #[test]
    fn test_add_non_root_block_device() {
        let dummy_file = TempFile::new().unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let dummy_id = String::from("1");
        let dummy_block_device = BlockDeviceConfig {
            path_on_host: Some(dummy_path),
            is_root_device: false,
            partuuid: None,
            cache_type: CacheType::Writeback,
            is_read_only: Some(false),
            drive_id: dummy_id.clone(),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let mut block_devs = BlockBuilder::new();
        assert!(block_devs.insert(dummy_block_device.clone()).is_ok());

        assert!(!block_devs.has_root_device());
        assert_eq!(block_devs.list.len(), 1);

        {
            let block = &block_devs.list[0];
            match block {
                Block::FileBacked(block) => {
                    let block = block.lock().unwrap();
                    assert_eq!(block.id(), &dummy_block_device.drive_id);
                    assert_eq!(block.partuuid(), dummy_block_device.partuuid.as_ref());
                    assert_eq!(
                        block.is_read_only(),
                        dummy_block_device.is_read_only.unwrap()
                    );
                }
                Block::VhostUserBacked(_) => todo!(),
            }
        }
        assert_eq!(block_devs.get_index_of_drive_id(&dummy_id), Some(0));
    }

    #[test]
    fn test_add_one_root_block_device() {
        let dummy_file = TempFile::new().unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();

        let dummy_block_device = BlockDeviceConfig {
            path_on_host: Some(dummy_path),
            is_root_device: true,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(true),
            drive_id: String::from("1"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let mut block_devs = BlockBuilder::new();
        assert!(block_devs.insert(dummy_block_device.clone()).is_ok());

        assert!(block_devs.has_root_device());
        assert_eq!(block_devs.list.len(), 1);
        {
            let block = &block_devs.list[0];
            match block {
                Block::FileBacked(block) => {
                    let block = block.lock().unwrap();
                    assert_eq!(block.id(), &dummy_block_device.drive_id);
                    assert_eq!(block.partuuid(), dummy_block_device.partuuid.as_ref());
                    assert_eq!(
                        block.is_read_only(),
                        dummy_block_device.is_read_only.unwrap()
                    );
                }
                Block::VhostUserBacked(_) => todo!(),
            }
        }
    }

    #[test]
    fn test_add_two_root_block_devs() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device_1 = BlockDeviceConfig {
            path_on_host: Some(dummy_path_1),
            is_root_device: true,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("1"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let root_block_device_2 = BlockDeviceConfig {
            path_on_host: Some(dummy_path_2),
            is_root_device: true,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("2"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
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
            path_on_host: Some(dummy_path_1),
            is_root_device: true,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("1"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_2 = BlockDeviceConfig {
            path_on_host: Some(dummy_path_2),
            is_root_device: false,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("2"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let dummy_file_3 = TempFile::new().unwrap();
        let dummy_path_3 = dummy_file_3.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_3 = BlockDeviceConfig {
            path_on_host: Some(dummy_path_3),
            is_root_device: false,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("3"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let mut block_devs = BlockBuilder::new();
        assert!(block_devs.insert(dummy_block_dev_2.clone()).is_ok());
        assert!(block_devs.insert(dummy_block_dev_3.clone()).is_ok());
        assert!(block_devs.insert(root_block_device.clone()).is_ok());

        assert_eq!(block_devs.list.len(), 3);

        let mut block_iter = block_devs.list.iter();
        let block = block_iter.next().unwrap();

        match block {
            Block::FileBacked(block) => {
                assert_eq!(block.lock().unwrap().id(), &root_block_device.drive_id);
            }
            Block::VhostUserBacked(_) => todo!(),
        }

        let block = block_iter.next().unwrap();
        match block {
            Block::FileBacked(block) => {
                assert_eq!(block.lock().unwrap().id(), &dummy_block_dev_2.drive_id);
            }
            Block::VhostUserBacked(_) => todo!(),
        }

        let block = block_iter.next().unwrap();
        match block {
            Block::FileBacked(block) => {
                assert_eq!(block.lock().unwrap().id(), &dummy_block_dev_3.drive_id);
            }
            Block::VhostUserBacked(_) => todo!(),
        }
    }

    #[test]
    // Test BlockDevicesConfigs::add when you add other devices first and then the root device.
    fn test_root_block_device_add_last() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device = BlockDeviceConfig {
            path_on_host: Some(dummy_path_1),
            is_root_device: true,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("1"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_2 = BlockDeviceConfig {
            path_on_host: Some(dummy_path_2),
            is_root_device: false,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("2"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let dummy_file_3 = TempFile::new().unwrap();
        let dummy_path_3 = dummy_file_3.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_3 = BlockDeviceConfig {
            path_on_host: Some(dummy_path_3),
            is_root_device: false,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("3"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let mut block_devs = BlockBuilder::new();
        assert!(block_devs.insert(dummy_block_dev_2.clone()).is_ok());
        assert!(block_devs.insert(dummy_block_dev_3.clone()).is_ok());
        assert!(block_devs.insert(root_block_device.clone()).is_ok());

        assert_eq!(block_devs.list.len(), 3);

        let mut block_iter = block_devs.list.iter();
        // The root device should be first in the list no matter of the order in
        // which the devices were added.
        let block = block_iter.next().unwrap();
        match block {
            Block::FileBacked(block) => {
                assert_eq!(block.lock().unwrap().id(), &root_block_device.drive_id);
            }
            Block::VhostUserBacked(_) => todo!(),
        }

        let block = block_iter.next().unwrap();
        match block {
            Block::FileBacked(block) => {
                assert_eq!(block.lock().unwrap().id(), &dummy_block_dev_2.drive_id);
            }
            Block::VhostUserBacked(_) => todo!(),
        }

        let block = block_iter.next().unwrap();
        match block {
            Block::FileBacked(block) => {
                assert_eq!(block.lock().unwrap().id(), &dummy_block_dev_3.drive_id);
            }
            Block::VhostUserBacked(_) => todo!(),
        }
    }

    #[test]
    fn test_update() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device = BlockDeviceConfig {
            path_on_host: Some(dummy_path_1.clone()),
            is_root_device: true,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("1"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let mut dummy_block_device_2 = BlockDeviceConfig {
            path_on_host: Some(dummy_path_2.clone()),
            is_root_device: false,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("2"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let mut block_devs = BlockBuilder::new();

        // Add 2 block devices.
        assert!(block_devs.insert(root_block_device).is_ok());
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
        dummy_block_device_2.is_read_only = Some(true);
        assert!(block_devs.insert(dummy_block_device_2.clone()).is_ok());

        let index = block_devs
            .get_index_of_drive_id(&dummy_block_device_2.drive_id)
            .unwrap();
        // Validate update was successful.
        let block = &block_devs.list[index];
        match block {
            Block::FileBacked(block) => {
                assert!(block.lock().unwrap().is_read_only());
            }
            Block::VhostUserBacked(_) => todo!(),
        }

        // Update with invalid path.
        let dummy_path_3 = String::from("test_update_3");
        dummy_block_device_2.path_on_host = Some(dummy_path_3.clone());
        assert_eq!(
            block_devs.insert(dummy_block_device_2.clone()),
            Err(DriveError::InvalidBlockDevicePath(dummy_path_3))
        );

        // Update with 2 root block devices.
        dummy_block_device_2.path_on_host = Some(dummy_path_2.clone());
        dummy_block_device_2.is_root_device = true;
        assert_eq!(
            block_devs.insert(dummy_block_device_2),
            Err(DriveError::RootBlockDeviceAlreadyAdded)
        );

        let root_block_device = BlockDeviceConfig {
            path_on_host: Some(dummy_path_1),
            is_root_device: true,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("1"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };
        // Switch roots and add a PARTUUID for the new one.
        let mut root_block_device_old = root_block_device;
        root_block_device_old.is_root_device = false;
        let root_block_device_new = BlockDeviceConfig {
            path_on_host: Some(dummy_path_2),
            is_root_device: true,
            partuuid: Some("0eaa91a0-01".to_string()),
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            drive_id: String::from("2"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };
        assert!(block_devs.insert(root_block_device_old).is_ok());
        let root_block_id = root_block_device_new.drive_id.clone();
        assert!(block_devs.insert(root_block_device_new).is_ok());
        assert!(block_devs.has_root_device());
        // Verify it's been moved to the first position.
        let block = &block_devs.list[0];
        match block {
            Block::FileBacked(block) => {
                assert_eq!(block.lock().unwrap().id(), &root_block_id);
            }
            Block::VhostUserBacked(_) => todo!(),
        }
    }

    #[test]
    fn test_block_config() {
        let dummy_file = TempFile::new().unwrap();

        let dummy_block_device = BlockDeviceConfig {
            path_on_host: Some(dummy_file.as_path().to_str().unwrap().to_string()),
            is_root_device: true,
            partuuid: None,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(true),
            drive_id: String::from("1"),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            file: None,
            vhost_user: None,
        };

        let mut block_devs = BlockBuilder::new();
        assert!(block_devs.insert(dummy_block_device.clone()).is_ok());

        let file = FileConfig {
            path_on_host: dummy_file.as_path().to_str().unwrap().to_string(),
            is_read_only: true,
            ..Default::default()
        };
        let dummy_block_device_with_file = BlockDeviceConfig {
            file: Some(file),
            ..dummy_block_device
        };

        let configs = block_devs.configs();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs.first().unwrap(), &dummy_block_device_with_file);
    }

    #[test]
    fn test_add_device() {
        let mut block_devs = BlockBuilder::new();
        let backing_file = TempFile::new().unwrap();
        let block_id = "test_id";
        let block = BlockFile::new(
            block_id.to_string(),
            None,
            CacheType::default(),
            backing_file.as_path().to_str().unwrap().to_string(),
            true,
            true,
            RateLimiter::default(),
            FileEngineType::default(),
        )
        .unwrap();

        block_devs.add_device(Arc::new(Mutex::new(block)));
        assert_eq!(block_devs.list.len(), 1);

        let block = block_devs.list.pop_back().unwrap();
        match block {
            Block::FileBacked(block) => {
                assert_eq!(block.lock().unwrap().deref().id(), block_id)
            }
            Block::VhostUserBacked(_) => todo!(),
        }
    }
}
