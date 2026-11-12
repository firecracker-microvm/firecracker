// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring block devices.

use device::ConfigSpace;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use vmm_sys_util::eventfd::EventFd;

use super::device::{BlockResources, BlockRuntimeState, DiskProperties};
use super::io::DiskImageFormat;
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
    num_queues: Option<NonZeroU16>,
    #[serde(default)]
    disk_image_format: DiskImageFormat,
    #[serde(default)]
    backing_path_on_host: Option<String>,
}

impl Persist<'_> for VirtioBlock {
    type State = VirtioBlockState;
    type ConstructorArgs = BlockConstructorArgs;
    type Error = VirtioBlockError;

    fn save(&self) -> Self::State {
        let virtio_state = if let BlockRuntimeState::Threaded(active) = &self.state {
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
            num_queues: self.config.num_queues,
            disk_image_format: self.config.image_format,
            backing_path_on_host: self.config.backing_path_on_host.clone(),
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
        let num_queues = state
            .num_queues
            .map_or(DEFAULT_BLOCK_NUM_QUEUES, NonZeroU16::get);
        let mq_offered = state.virtio_state.avail_features & (1u64 << VIRTIO_BLK_F_MQ) != 0;
        if num_queues > 1 && !mq_offered {
            return Err(VirtioBlockError::Persist(PersistError::InvalidInput));
        }
        if state.disk_image_format == DiskImageFormat::Qcow2
            && (!is_read_only || state.file_engine_type == FileEngineTypeState::Async)
            && num_queues > 1
        {
            return Err(VirtioBlockError::FileEngine(
                super::io::BlockIoError::Qcow2(super::io::Qcow2IoError::MultiQueueNotSupported),
            ));
        }
        let config = VirtioBlockConfig {
            drive_id: state.id.clone(),
            partuuid: state.partuuid.clone(),
            is_root_device: state.root_device,
            cache_type: state.cache_type,
            dmb_size_mib: None,
            is_read_only,
            discard: state.virtio_state.avail_features & (1u64 << VIRTIO_BLK_F_DISCARD) != 0,
            num_queues: state.num_queues,
            path_on_host: state.disk_path.clone(),
            rate_limiter: rate_limiter_config.into_option(),
            file_engine_type: state.file_engine_type.into(),
            image_format: state.disk_image_format,
            backing_path_on_host: state.backing_path_on_host.clone(),
            blk_size: Some(state.blk_size),
            topology: Some(state.topology),
        };
        if config.discard && config.is_read_only {
            return Err(VirtioBlockError::DiscardReadOnlyUnsupported);
        }
        if config.discard
            && config.file_engine_type == FileEngineType::Async
            && config.image_format != DiskImageFormat::Qcow2
        {
            return Err(VirtioBlockError::DiscardAsyncUnsupported);
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
                    &state.disk_path,
                    is_read_only,
                    state.file_engine_type.into(),
                    state.disk_image_format,
                    state.backing_path_on_host.as_deref(),
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
            dmb_size_mib: None,
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
            state: BlockRuntimeState::Configuring(resources, Vec::new()),
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
    use crate::vmm_config::enclave::DmbSizeMib;
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
            num_queues: None,
            cache_type: CacheType::Writeback,
            dmb_size_mib: None,
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            image_format: DiskImageFormat::Raw,
            backing_path_on_host: None,
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
    fn test_qcow2_explicit_backing_restore_and_update() {
        use crate::devices::virtio::block::virtio::io::FileEngine;
        use crate::devices::virtio::block::virtio::test_utils::create_test_qcow2;
        use crate::vstate::memory::{Bytes, GuestAddress};
        use std::os::unix::fs::FileExt;

        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(2 * 1024 * 1024).unwrap();
        backing.as_file().write_at(&[0x5a; 4096], 0).unwrap();
        let file = create_test_qcow2();
        let mut config = default_config(
            file.as_path().to_str().unwrap().to_owned(),
            FileEngineType::Sync,
        );
        config.image_format = DiskImageFormat::Qcow2;
        config.backing_path_on_host = Some(backing.as_path().to_str().unwrap().to_owned());
        let mut block = VirtioBlock::new(config).unwrap();
        let mem = default_mem();
        let FileEngine::Qcow2(engine) = &mut block.resources_mut()[0].disk.file_engine else {
            panic!("QCOW2 engine expected")
        };
        let mut bytes = [0; 4096];
        mem.write_slice(&[0xa6; 512], GuestAddress(0)).unwrap();
        engine.write(512, &mem, GuestAddress(0), 512).unwrap();
        engine.flush().unwrap();
        let state = bitcode::serialize(&block.save()).unwrap();
        drop(block);
        let mut restored = VirtioBlock::restore(
            BlockConstructorArgs { mem: mem.clone() },
            &bitcode::deserialize(&state).unwrap(),
        )
        .unwrap();
        assert_eq!(
            restored.config().backing_path_on_host.as_deref(),
            backing.as_path().to_str()
        );
        let FileEngine::Qcow2(engine) = &mut restored.resources_mut()[0].disk.file_engine else {
            panic!("QCOW2 engine expected")
        };
        engine.read(0, &mem, GuestAddress(0), 4096).unwrap();
        mem.read_slice(&mut bytes, GuestAddress(0)).unwrap();
        assert_eq!(&bytes[..512], &[0x5a; 512]);
        assert_eq!(&bytes[512..1024], &[0xa6; 512]);
        assert_eq!(&bytes[1024..], &[0x5a; 3072]);
        let replacement = create_test_qcow2();
        restored
            .update_disk_image(replacement.as_path().to_str().unwrap().to_owned())
            .unwrap();
        let FileEngine::Qcow2(engine) = &mut restored.resources_mut()[0].disk.file_engine else {
            panic!("QCOW2 engine expected")
        };
        engine.read(0, &mem, GuestAddress(0), 4096).unwrap();
        mem.read_slice(&mut bytes, GuestAddress(0)).unwrap();
        assert_eq!(bytes, [0x5a; 4096]);
    }

    #[test]
    fn test_qcow2_rejects_invalid_snapshot_config() {
        use crate::devices::virtio::block::virtio::test_utils::create_test_qcow2;

        let file = create_test_qcow2();
        let mut config = default_config(
            file.as_path().to_str().unwrap().to_string(),
            FileEngineType::Sync,
        );
        config.image_format = DiskImageFormat::Qcow2;
        config.is_read_only = true;
        config.num_queues = NonZeroU16::new(2);
        let block = VirtioBlock::new(config).unwrap();
        let state = block.save();
        drop(block);
        for (engine, read_only, discard) in [
            (FileEngineType::Sync, false, false),
            (FileEngineType::Async, true, false),
            (FileEngineType::Sync, true, true),
        ] {
            let mut invalid = state.clone();
            invalid.file_engine_type = engine.into();
            if !read_only {
                invalid.virtio_state.avail_features &= !(1u64 << VIRTIO_BLK_F_RO);
            }
            if discard {
                invalid.virtio_state.avail_features |= 1u64 << VIRTIO_BLK_F_DISCARD;
            }
            let serialized = bitcode::serialize(&invalid).unwrap();
            let result = VirtioBlock::restore(
                BlockConstructorArgs { mem: default_mem() },
                &bitcode::deserialize(&serialized).unwrap(),
            );
            if discard {
                assert!(matches!(
                    result,
                    Err(VirtioBlockError::DiscardReadOnlyUnsupported)
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(VirtioBlockError::FileEngine(
                        super::io::BlockIoError::Qcow2(
                            super::io::Qcow2IoError::MultiQueueNotSupported
                        )
                    ))
                ));
            }
        }
    }

    #[test]
    fn test_qcow2_discard_negotiation() {
        use crate::devices::virtio::block::virtio::test_utils::{
            RequestDescriptorChain, create_test_qcow2, simulate_queue_event,
        };
        use crate::devices::virtio::generated::virtio_blk::{
            VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP, VIRTIO_BLK_T_DISCARD,
        };
        use crate::devices::virtio::queue::VIRTQ_DESC_F_NEXT;
        use crate::vstate::memory::Bytes;

        let file = create_test_qcow2();
        for negotiated in [false, true] {
            let mut config = default_config(
                file.as_path().to_str().unwrap().to_string(),
                FileEngineType::Sync,
            );
            config.image_format = DiskImageFormat::Qcow2;
            config.discard = true;
            let mut block = VirtioBlock::new(config).unwrap();
            if negotiated {
                block.set_acked_features(1u64 << VIRTIO_BLK_F_DISCARD);
            }
            let state = block.save();
            drop(block);
            let serialized = bitcode::serialize(&state).unwrap();
            let restored_state = bitcode::deserialize(&serialized).unwrap();
            let mem = default_mem();
            let mut restored =
                VirtioBlock::restore(BlockConstructorArgs { mem: mem.clone() }, &restored_state)
                    .unwrap();
            assert!(restored.config().discard);
            assert_eq!(restored.avail_features(), state.virtio_state.avail_features);
            assert_eq!(restored.acked_features(), state.virtio_state.acked_features);

            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut restored, 0, vq.create_queue());
            let chain = RequestDescriptorChain::new(&vq);
            chain.set_header(RequestHeader::new(VIRTIO_BLK_T_DISCARD, 0));
            chain.data_desc.flags.set(VIRTQ_DESC_F_NEXT);
            chain.data_desc.len.set(16);
            let mut range = [0u8; 16];
            range[8..12].copy_from_slice(&1u32.to_le_bytes());
            mem.write_slice(&range, GuestAddress(chain.data_desc.addr.get()))
                .unwrap();
            restored.activate(mem.clone(), default_interrupt()).unwrap();
            simulate_queue_event(&mut restored, Some(true));
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().len, 1);
            let expected = if negotiated {
                VIRTIO_BLK_S_OK
            } else {
                VIRTIO_BLK_S_UNSUPP
            };
            assert_eq!(
                mem.read_obj::<u8>(GuestAddress(chain.status_desc.addr.get()))
                    .unwrap(),
                u8::try_from(expected).unwrap()
            );
        }
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
            num_queues: None,
            cache_type: CacheType::Unsafe,
            dmb_size_mib: Some(DmbSizeMib::try_from(32).unwrap()),
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
            image_format: DiskImageFormat::Raw,
            backing_path_on_host: None,
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
            restored_block.resources()[0].queue.save(),
            block.resources()[0].queue.save()
        );
        assert!(!block.is_activated());
        assert!(!restored_block.is_activated());

        assert_eq!(restored_block.dmb_size_mib(), None);
        // Test that block specific fields are the same.
        assert_eq!(
            restored_block.config().path_on_host,
            block.config().path_on_host
        );
    }

    #[test]
    fn test_threaded_persistence() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let disk = TempFile::new().unwrap();
            disk.as_file().set_len(0x1000).unwrap();
            let mut block =
                default_block_with_path(disk.as_path().to_str().unwrap().to_string(), engine);
            block.config.num_queues = NonZeroU16::new(1);
            block.spawn_worker(Arc::new(vec![])).unwrap();
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, BLOCK_QUEUE_SIZE);
            set_queue(&mut block, 0, vq.create_queue());
            block.set_acked_features(block.avail_features());
            block.activate(mem.clone(), default_interrupt()).unwrap();
            // Pause the worker for snapshotting
            block.prepare_save().unwrap();

            let state = block.save();
            let serialized = bitcode::serialize(&state).unwrap();
            let restored_state = bitcode::deserialize(&serialized).unwrap();
            let restored =
                VirtioBlock::restore(BlockConstructorArgs { mem }, &restored_state).unwrap();

            assert_eq!(state.num_queues, NonZeroU16::new(1));
            assert!(state.virtio_state.activated);
            assert_eq!(restored.config().num_queues, NonZeroU16::new(1));
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
            config.num_queues = NonZeroU16::new(2);
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
            block.prepare_save().unwrap();
            block.commit_dirty();

            let state = block.save();
            let serialized = bitcode::serialize(&state).unwrap();
            let restored_state = bitcode::deserialize(&serialized).unwrap();
            let restored =
                VirtioBlock::restore(BlockConstructorArgs { mem }, &restored_state).unwrap();

            assert_eq!(state.virtio_state.queues.len(), 2);
            assert_eq!(restored.num_queues(), 2);
            assert_eq!(restored.config().num_queues, NonZeroU16::new(2));
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
