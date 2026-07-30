// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring block devices.

use device::ConfigSpace;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use vmm_sys_util::eventfd::EventFd;

use super::device::{ActiveBlock, BlockResources, BlockState, DiskProperties};
use super::*;
use crate::devices::virtio::block::persist::BlockConstructorArgs;
use crate::devices::virtio::block::virtio::device::{FileEngineType, VirtioBlockConfig};
use crate::devices::virtio::block::virtio::metrics::BlockMetricsPerDevice;
use crate::devices::virtio::device::VirtioDeviceType;
use crate::devices::virtio::generated::virtio_blk::VIRTIO_BLK_F_RO;
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::persist::RateLimiterState;
use crate::snapshot::Persist;
use crate::vmm_config::RateLimiterConfig;

/// Holds info about block's file engine type. Gets saved in snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileEngineTypeState {
    /// Sync File Engine.
    // If the snap version does not contain the `FileEngineType`, it must have been snapshotted
    // on a VM using the Sync backend.
    #[default]
    Sync,
    /// Async File Engine.
    Async,
}

impl From<FileEngineType> for FileEngineTypeState {
    fn from(file_engine_type: FileEngineType) -> Self {
        match file_engine_type {
            FileEngineType::Sync => FileEngineTypeState::Sync,
            FileEngineType::Async => FileEngineTypeState::Async,
        }
    }
}

impl From<FileEngineTypeState> for FileEngineType {
    fn from(file_engine_type_state: FileEngineTypeState) -> Self {
        match file_engine_type_state {
            FileEngineTypeState::Sync => FileEngineType::Sync,
            FileEngineTypeState::Async => FileEngineType::Async,
        }
    }
}

/// Holds info about the block device. Gets saved in snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioBlockState {
    id: String,
    partuuid: Option<String>,
    cache_type: CacheType,
    root_device: bool,
    disk_path: String,
    pub virtio_state: VirtioDeviceState,
    rate_limiter_state: RateLimiterState,
    file_engine_type: FileEngineTypeState,
    #[serde(default)]
    threaded: bool,
}

impl Persist<'_> for VirtioBlock {
    type State = VirtioBlockState;
    type ConstructorArgs = BlockConstructorArgs;
    type Error = VirtioBlockError;

    fn save(&self) -> Self::State {
        let virtio_state = if let BlockState::Active(ActiveBlock::Threaded(active)) = &self.state {
            VirtioDeviceState {
                device_type: VirtioDeviceType::Block,
                avail_features: self.avail_features,
                acked_features: self.acked_features,
                queues: active.worker_handle.get_queue_states(),
                activated: true,
            }
        } else {
            VirtioDeviceState::from_device(self, &self.resources().queues)
        };

        VirtioBlockState {
            id: self.config.drive_id.clone(),
            partuuid: self.config.partuuid.clone(),
            cache_type: self.config.cache_type,
            root_device: self.config.is_root_device,
            disk_path: self.config.path_on_host.clone(),
            virtio_state,
            rate_limiter_state: self.rate_limiter().save(),
            file_engine_type: FileEngineTypeState::from(self.file_engine_type()),
            threaded: self.config.threaded,
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let is_read_only = state.virtio_state.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0;
        let rate_limiter = RateLimiter::restore((), &state.rate_limiter_state)
            .map_err(VirtioBlockError::RateLimiter)?;
        let rate_limiter_config: RateLimiterConfig = (&rate_limiter).into();
        let config = VirtioBlockConfig {
            drive_id: state.id.clone(),
            partuuid: state.partuuid.clone(),
            is_root_device: state.root_device,
            cache_type: state.cache_type,
            is_read_only,
            threaded: state.threaded,
            path_on_host: state.disk_path.clone(),
            rate_limiter: rate_limiter_config.into_option(),
            file_engine_type: state.file_engine_type.into(),
        };

        let disk_properties = DiskProperties::new(
            state.disk_path.clone(),
            is_read_only,
            state.file_engine_type.into(),
        )?;

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?];

        let queues = state
            .virtio_state
            .build_queues_checked(
                &constructor_args.mem,
                VirtioDeviceType::Block,
                BLOCK_NUM_QUEUES,
                FIRECRACKER_MAX_QUEUE_SIZE,
            )
            .map_err(VirtioBlockError::Persist)?;

        let avail_features = state.virtio_state.avail_features;
        let acked_features = state.virtio_state.acked_features;

        let config_space = ConfigSpace {
            capacity: disk_properties.nsectors.to_le(),
        };
        let resources = BlockResources {
            queues,
            queue_evts,
            disk: disk_properties,
            is_io_engine_throttled: false,
        };

        Ok(VirtioBlock {
            avail_features,
            acked_features,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,

            config,
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
            state: BlockState::Configuring(resources, None),
            metrics: BlockMetricsPerDevice::alloc(state.id.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::block::virtio::test_utils::{default_block_with_path, set_queue};
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::vstate::memory::GuestAddress;

    #[test]
    fn test_cache_semantic_ser() {
        // We create the backing file here so that it exists for the whole lifetime of the test.
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();

        let config = VirtioBlockConfig {
            drive_id: "test".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            threaded: false,
            cache_type: CacheType::Writeback,
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
        };

        let block = VirtioBlock::new(config).unwrap();

        // Save the block device.
        let block_state = block.save();
        let _serialized_data = bitcode::serialize(&block_state).unwrap();
    }

    #[test]
    fn test_file_engine_type() {
        // Test conversions between FileEngineType and FileEngineTypeState.
        assert_eq!(
            FileEngineTypeState::Async,
            FileEngineTypeState::from(FileEngineType::Async)
        );
        assert_eq!(
            FileEngineTypeState::Sync,
            FileEngineTypeState::from(FileEngineType::Sync)
        );
        assert_eq!(FileEngineType::Async, FileEngineTypeState::Async.into());
        assert_eq!(FileEngineType::Sync, FileEngineTypeState::Sync.into());
        // Test default impl.
        assert_eq!(FileEngineTypeState::default(), FileEngineTypeState::Sync);
    }

    #[test]
    fn test_persistence() {
        // We create the backing file here so that it exists for the whole lifetime of the test.
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();

        let config = VirtioBlockConfig {
            drive_id: "test".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            threaded: false,
            cache_type: CacheType::Unsafe,
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
        };

        let block = VirtioBlock::new(config).unwrap();
        let guest_mem = default_mem();

        // Save the block device.
        let block_state = block.save();
        let serialized_data = bitcode::serialize(&block_state).unwrap();

        // Restore the block device.
        let restored_state = bitcode::deserialize(&serialized_data).unwrap();
        let restored_block =
            VirtioBlock::restore(BlockConstructorArgs { mem: guest_mem }, &restored_state).unwrap();

        // Test that virtio specific fields are the same.
        assert_eq!(restored_block.device_type(), VirtioDeviceType::Block);
        assert_eq!(restored_block.avail_features(), block.avail_features());
        assert_eq!(restored_block.acked_features(), block.acked_features());
        assert_eq!(restored_block.resources().queues, block.resources().queues);
        assert!(!block.is_activated());
        assert!(!restored_block.is_activated());

        // Test that block specific fields are the same.
        assert_eq!(restored_block.disk().file_path, block.disk().file_path);
    }

    #[test]
    fn test_threaded_persistence() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let disk = TempFile::new().unwrap();
            disk.as_file().set_len(0x1000).unwrap();
            let mut block =
                default_block_with_path(disk.as_path().to_str().unwrap().to_string(), engine);
            block.config.threaded = true;
            block.spawn_worker(Arc::new(vec![])).unwrap();
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, BLOCK_QUEUE_SIZES[0]);
            set_queue(&mut block, 0, vq.create_queue());
            block.set_acked_features(block.avail_features());
            block.activate(mem.clone(), default_interrupt()).unwrap();
            // Pause the worker for snapshotting
            block.prepare_save();

            let state = block.save();
            let serialized = bitcode::serialize(&state).unwrap();
            let restored_state = bitcode::deserialize(&serialized).unwrap();
            let restored =
                VirtioBlock::restore(BlockConstructorArgs { mem }, &restored_state).unwrap();

            assert!(state.threaded);
            assert!(state.virtio_state.activated);
            assert!(restored.config().threaded);
            assert!(!restored.is_activated());
            assert_eq!(restored.acked_features(), block.acked_features());
            assert_eq!(restored.queue_config(0), block.queue_config(0));
            assert_eq!(restored.file_engine_type(), engine);
        }
    }
}
