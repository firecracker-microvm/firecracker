// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring block devices.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use snapshot::Persist;
use utils::vm_memory::GuestMemoryMmap;
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;
use virtio_gen::virtio_blk::VIRTIO_BLK_F_RO;

use super::*;
use crate::devices::virtio::block::device::FileEngineType;
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::devices::virtio::{DeviceState, FIRECRACKER_MAX_QUEUE_SIZE, TYPE_BLOCK};
use crate::logger::warn;
use crate::rate_limiter::persist::RateLimiterState;
use crate::rate_limiter::RateLimiter;

/// Holds info about block's cache type. Gets saved in snapshot.
// NOTICE: Any changes to this structure require a snapshot version bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Versionize)]
pub enum CacheTypeState {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

impl From<CacheType> for CacheTypeState {
    fn from(cache_type: CacheType) -> Self {
        match cache_type {
            CacheType::Unsafe => CacheTypeState::Unsafe,
            CacheType::Writeback => CacheTypeState::Writeback,
        }
    }
}

impl From<CacheTypeState> for CacheType {
    fn from(cache_type_state: CacheTypeState) -> Self {
        match cache_type_state {
            CacheTypeState::Unsafe => CacheType::Unsafe,
            CacheTypeState::Writeback => CacheType::Writeback,
        }
    }
}

/// Holds info about block's file engine type. Gets saved in snapshot.
// NOTICE: Any changes to this structure require a snapshot version bump.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Versionize)]
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
// NOTICE: Any changes to this structure require a snapshot version bump.
#[derive(Debug, Clone, Versionize)]
pub struct BlockState {
    id: String,
    partuuid: Option<String>,
    #[version(
        start = 2,
        ser_fn = "block_cache_type_ser",
        default_fn = "default_cache_type_flush"
    )]
    cache_type: CacheTypeState,
    root_device: bool,
    disk_path: String,
    virtio_state: VirtioDeviceState,
    rate_limiter_state: RateLimiterState,
    #[version(start = 3)]
    // We don't need to specify a `ser_fn` for the `file_engine_type` since snapshots created in
    // v1.0 are incompatible with older FC versions (due to incompatible notification suppression
    // feature).
    file_engine_type: FileEngineTypeState,
}

impl BlockState {
    fn block_cache_type_ser(&mut self, target_version: u16) -> VersionizeResult<()> {
        if target_version < 3 && self.cache_type != CacheTypeState::Unsafe {
            warn!(
                "Target version does not implement the current cache type. Defaulting to \
                 \"unsafe\" mode."
            );
        }

        Ok(())
    }

    fn default_cache_type_flush(_source_version: u16) -> CacheTypeState {
        CacheTypeState::Unsafe
    }
}

/// Auxiliary structure for creating a device when resuming from a snapshot.
#[derive(Debug)]
pub struct BlockConstructorArgs {
    /// Pointer to guest memory.
    pub mem: GuestMemoryMmap,
}

impl Persist<'_> for Block {
    type State = BlockState;
    type ConstructorArgs = BlockConstructorArgs;
    type Error = BlockError;

    fn save(&self) -> Self::State {
        // Save device state.
        BlockState {
            id: self.id.clone(),
            partuuid: self.partuuid.clone(),
            cache_type: CacheTypeState::from(self.cache_type()),
            root_device: self.root_device,
            disk_path: self.disk.file_path().clone(),
            virtio_state: VirtioDeviceState::from_device(self),
            rate_limiter_state: self.rate_limiter.save(),
            file_engine_type: FileEngineTypeState::from(self.file_engine_type()),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let is_disk_read_only = state.virtio_state.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0;
        let rate_limiter =
            RateLimiter::restore((), &state.rate_limiter_state).map_err(BlockError::RateLimiter)?;

        let mut block = Block::new(
            state.id.clone(),
            state.partuuid.clone(),
            state.cache_type.into(),
            state.disk_path.clone(),
            is_disk_read_only,
            state.root_device,
            rate_limiter,
            state.file_engine_type.into(),
        )
        .or_else(|err| match err {
            BlockError::FileEngine(io::BlockIoError::UnsupportedEngine(FileEngineType::Async)) => {
                // If the kernel does not support `Async`, fallback to `Sync`.
                warn!(
                    "The \"Async\" io_engine is supported for kernels starting with {}. \
                     Defaulting to \"Sync\" mode.",
                    utils::kernel_version::min_kernel_version_for_io_uring()
                );

                let rate_limiter = RateLimiter::restore((), &state.rate_limiter_state)
                    .map_err(BlockError::RateLimiter)?;
                Block::new(
                    state.id.clone(),
                    state.partuuid.clone(),
                    state.cache_type.into(),
                    state.disk_path.clone(),
                    is_disk_read_only,
                    state.root_device,
                    rate_limiter,
                    FileEngineType::Sync,
                )
            }
            other_err => Err(other_err),
        })?;

        block.queues = state
            .virtio_state
            .build_queues_checked(
                &constructor_args.mem,
                TYPE_BLOCK,
                BLOCK_NUM_QUEUES,
                FIRECRACKER_MAX_QUEUE_SIZE,
            )
            .map_err(BlockError::Persist)?;
        block.irq_trigger.irq_status =
            Arc::new(AtomicUsize::new(state.virtio_state.interrupt_status));
        block.avail_features = state.virtio_state.avail_features;
        block.acked_features = state.virtio_state.acked_features;

        if state.virtio_state.activated {
            block.device_state = DeviceState::Activated(constructor_args.mem);
        }

        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use utils::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::test_utils::default_mem;

    #[test]
    fn test_cache_type_state_from() {
        assert_eq!(
            CacheTypeState::Unsafe,
            CacheTypeState::from(CacheType::Unsafe)
        );
        assert_eq!(
            CacheTypeState::Writeback,
            CacheTypeState::from(CacheType::Writeback)
        );
    }

    #[test]
    fn test_cache_type_state_into() {
        assert_eq!(CacheType::Unsafe, CacheTypeState::Unsafe.into());
        assert_eq!(CacheType::Writeback, CacheTypeState::Writeback.into());
    }

    #[test]
    fn test_default_cache_type_flush() {
        assert_eq!(
            BlockState::default_cache_type_flush(2),
            CacheTypeState::Unsafe
        );
        assert_eq!(
            BlockState::default_cache_type_flush(3),
            CacheTypeState::Unsafe
        );
    }

    #[test]
    fn test_cache_semantic_ser() {
        // We create the backing file here so that it exists for the whole lifetime of the test.
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();

        let id = "test".to_string();
        let block = Block::new(
            id,
            None,
            CacheType::Writeback,
            f.as_path().to_str().unwrap().to_string(),
            false,
            false,
            RateLimiter::default(),
            FileEngineType::default(),
        )
        .unwrap();

        // Save the block device.
        let mut mem = vec![0; 4096];
        let version_map = VersionMap::new();

        assert!(<Block as Persist>::save(&block)
            .serialize(&mut mem.as_mut_slice(), &version_map, 2)
            .is_ok());

        assert!(<Block as Persist>::save(&block)
            .serialize(&mut mem.as_mut_slice(), &version_map, 3)
            .is_ok());
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

        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        let mut version_map = VersionMap::new();
        version_map
            .new_version()
            .set_type_version(BlockState::type_id(), 3);

        if !FileEngineType::Async.is_supported().unwrap() {
            // Test what happens when restoring an Async engine on a kernel that does not support
            // it.

            let block = Block::new(
                "test".to_string(),
                None,
                CacheType::Unsafe,
                f.as_path().to_str().unwrap().to_string(),
                false,
                false,
                RateLimiter::default(),
                // Need to use Sync because it will otherwise return an error.
                // We'll overwrite the state instead.
                FileEngineType::Sync,
            )
            .unwrap();

            // Save the block device.
            let mut mem = vec![0; 4096];

            let mut block_state = <Block as Persist>::save(&block);
            // Overwrite the engine type state with Async.
            block_state.file_engine_type = FileEngineTypeState::Async;

            block_state
                .serialize(&mut mem.as_mut_slice(), &version_map, 2)
                .unwrap();

            // Restore the block device.
            let restored_block = Block::restore(
                BlockConstructorArgs { mem: default_mem() },
                &BlockState::deserialize(&mut mem.as_slice(), &version_map, 2).unwrap(),
            )
            .unwrap();

            // On kernels that don't support io_uring, the restore() function will catch the
            // `UnsupportedEngine` error and default to Sync.
            assert_eq!(restored_block.file_engine_type(), FileEngineType::Sync);
        }
    }

    #[test]
    fn test_persistence() {
        // We create the backing file here so that it exists for the whole lifetime of the test.
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();

        let id = "test".to_string();
        let block = Block::new(
            id,
            None,
            CacheType::Unsafe,
            f.as_path().to_str().unwrap().to_string(),
            false,
            false,
            RateLimiter::default(),
            FileEngineType::default(),
        )
        .unwrap();
        let guest_mem = default_mem();

        // Save the block device.
        let mut mem = vec![0; 4096];
        let version_map = VersionMap::new();

        <Block as Persist>::save(&block)
            .serialize(&mut mem.as_mut_slice(), &version_map, 1)
            .unwrap();

        // Restore the block device.
        let restored_block = Block::restore(
            BlockConstructorArgs { mem: guest_mem },
            &BlockState::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap(),
        )
        .unwrap();

        // Test that virtio specific fields are the same.
        assert_eq!(restored_block.device_type(), TYPE_BLOCK);
        assert_eq!(restored_block.avail_features(), block.avail_features());
        assert_eq!(restored_block.acked_features(), block.acked_features());
        assert_eq!(restored_block.queues(), block.queues());
        assert_eq!(
            restored_block.interrupt_status().load(Ordering::Relaxed),
            block.interrupt_status().load(Ordering::Relaxed)
        );
        assert_eq!(restored_block.is_activated(), block.is_activated());

        // Test that block specific fields are the same.
        assert_eq!(restored_block.disk.file_path(), block.disk.file_path());
    }
}
