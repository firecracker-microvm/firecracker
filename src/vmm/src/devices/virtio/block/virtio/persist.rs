// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring block devices.

use device::ConfigSpace;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use vmm_sys_util::eventfd::EventFd;

use super::device::{ActiveBlock, BlockResources, BlockState, DiskProperties};
use super::worker::WorkerHandle;
use super::*;
use crate::devices::virtio::block::persist::BlockConstructorArgs;
use crate::devices::virtio::block::virtio::device::{
    FileEngineType, VirtioBlkTopology, VirtioBlockConfig,
};
use crate::devices::virtio::block::virtio::metrics::BlockMetricsPerDevice;
use crate::devices::virtio::device::VirtioDeviceType;
use crate::devices::virtio::generated::virtio_blk::{
    VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO,
};
use crate::devices::virtio::persist::{PersistError, VirtioDeviceState};
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
    blk_size: u32,
    topology: VirtioBlkTopology,
    discard_sector_alignment: u32,
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
                queues: active
                    .worker_handles
                    .iter()
                    .map(WorkerHandle::get_queue_state)
                    .collect(),
                activated: true,
            }
        } else {
            VirtioDeviceState::from_device(self, self.resources().iter().map(|r| &r.queue))
        };

        VirtioBlockState {
            id: self.config.drive_id.clone(),
            partuuid: self.config.partuuid.clone(),
            cache_type: self.config.cache_type,
            root_device: self.config.is_root_device,
            disk_path: self.config.path_on_host.clone(),
            virtio_state,
            rate_limiter_state: self.lock_rate_limiter().save(),
            file_engine_type: FileEngineTypeState::from(self.file_engine_type()),
            blk_size: self.config_space.blk_size,
            topology: self.config_space.topology,
            discard_sector_alignment: self.config_space.discard_sector_alignment,
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
        let num_queues = u16::try_from(state.virtio_state.queues.len())
            .map_err(|_| VirtioBlockError::Persist(PersistError::InvalidInput))?;
        let config = VirtioBlockConfig {
            drive_id: state.id.clone(),
            partuuid: state.partuuid.clone(),
            is_root_device: state.root_device,
            cache_type: state.cache_type,
            is_read_only,
            discard: state.virtio_state.avail_features & (1u64 << VIRTIO_BLK_F_DISCARD) != 0,
            threaded: state.threaded,
            num_queues,
            path_on_host: state.disk_path.clone(),
            rate_limiter: rate_limiter_config.into_option(),
            file_engine_type: state.file_engine_type.into(),
            blk_size: Some(state.blk_size),
            topology: Some(state.topology),
        };
        config.validate_queue_count()?;
        let mq_offered = state.virtio_state.avail_features & (1u64 << VIRTIO_BLK_F_MQ) != 0;
        if mq_offered != (num_queues > 1) {
            return Err(VirtioBlockError::Persist(PersistError::InvalidInput));
        }

        let queues = state
            .virtio_state
            .build_queues_checked(
                &constructor_args.mem,
                VirtioDeviceType::Block,
                usize::from(num_queues),
                FIRECRACKER_MAX_QUEUE_SIZE,
            )
            .map_err(VirtioBlockError::Persist)?;
        let mut resources = Vec::with_capacity(usize::from(num_queues));
        for (queue_idx, queue) in (0..num_queues).zip(queues) {
            resources.push(BlockResources {
                queue,
                queue_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,
                queue_idx,
                disk: DiskProperties::new(
                    state.disk_path.clone(),
                    is_read_only,
                    state.file_engine_type.into(),
                )?,
                is_io_engine_throttled: false,
            });
        }

        let config_space = ConfigSpace {
            capacity: resources[0].disk.nsectors.to_le(),
            blk_size: state.blk_size,
            topology: state.topology,
            discard_sector_alignment: state.discard_sector_alignment,
            num_queues: num_queues.to_le(),
            ..Default::default()
        };

        Ok(VirtioBlock {
            avail_features: state.virtio_state.avail_features,
            acked_features: state.virtio_state.acked_features,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,

            config,
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
            state: BlockState::Configuring(resources, Vec::new()),
            metrics: BlockMetricsPerDevice::alloc(state.id.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::block::virtio::test_utils::{
        default_block_with_path, default_config, set_queue,
    };
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
            discard: false,
            threaded: false,
            num_queues: 1,
            cache_type: CacheType::Writeback,
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            blk_size: None,
            topology: None,
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
            discard: false,
            threaded: false,
            num_queues: 1,
            cache_type: CacheType::Unsafe,
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            blk_size: None,
            topology: None,
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
        assert_eq!(
            restored_block.resources()[0].queue,
            block.resources()[0].queue
        );
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
            let vq = VirtQueue::new(GuestAddress(0), &mem, BLOCK_QUEUE_SIZE);
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

    #[test]
    fn test_mq_persistence() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let disk = TempFile::new().unwrap();
            disk.as_file().set_len(0x1000).unwrap();
            let disk_path = disk.as_path().to_str().unwrap().to_owned();
            let mut config = default_config(disk_path, engine);
            config.threaded = true;
            config.num_queues = 2;
            let mut block = VirtioBlock::new(config).unwrap();
            block.spawn_worker(Arc::new(vec![])).unwrap();
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, BLOCK_QUEUE_SIZE);
            set_queue(&mut block, 0, vq.create_queue());
            block.set_acked_features(block.avail_features());
            block.activate(mem.clone(), default_interrupt()).unwrap();
            assert!(!block.queue_config(1).unwrap().ready);

            // Unused queues stay idle through the worker and snapshot lifecycle.
            block.kick();
            block.prepare_save();
            block.mark_queue_memory_dirty(&mem).unwrap();

            let state = block.save();
            let serialized = bitcode::serialize(&state).unwrap();
            let restored_state = bitcode::deserialize(&serialized).unwrap();
            let restored =
                VirtioBlock::restore(BlockConstructorArgs { mem }, &restored_state).unwrap();

            assert_eq!(state.virtio_state.queues.len(), 2);
            assert_eq!(restored.num_queues(), 2);
            assert_eq!(restored.config().num_queues, 2);
            assert_eq!(u16::from_le(restored.config_space.num_queues), 2);
            assert_eq!(restored.avail_features(), block.avail_features());
            assert_eq!(restored.acked_features(), block.acked_features());
            for idx in 0..2 {
                assert_eq!(
                    restored.resources()[idx].queue_idx,
                    u16::try_from(idx).unwrap()
                );
                assert_eq!(restored.queue_config(idx), block.queue_config(idx));
            }
        }
    }
}
