// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring block devices.

use std::io::{self, Write};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use logger::{error, warn};
use rate_limiter::{persist::RateLimiterState, RateLimiter};
use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;
use virtio_gen::virtio_blk::VIRTIO_BLK_F_RO;
use vm_memory::GuestMemoryMmap;

use super::*;

use crate::virtio::persist::VirtioDeviceState;
use crate::virtio::{DeviceState, TYPE_BLOCK};

#[derive(Clone, Copy, Debug, Versionize, PartialEq)]
// NOTICE: Any changes to this structure require a snapshot version bump.
pub enum CacheTypeState {
    Unsafe,
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

#[derive(Clone, Versionize)]
// NOTICE: Any changes to this structure require a snapshot version bump.
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
}

impl BlockState {
    fn block_cache_type_ser(&mut self, target_version: u16) -> VersionizeResult<()> {
        if target_version < 3 && self.cache_type != CacheTypeState::Unsafe {
            warn!(
                "Target version does not implement the current cache type. \
                Defaulting to \"unsafe\" mode."
            );
        }

        Ok(())
    }

    fn default_cache_type_flush(_source_version: u16) -> CacheTypeState {
        CacheTypeState::Unsafe
    }
}

pub struct BlockConstructorArgs {
    pub mem: GuestMemoryMmap,
}

impl Persist<'_> for Block {
    type State = BlockState;
    type ConstructorArgs = BlockConstructorArgs;
    type Error = io::Error;

    fn save(&self) -> Self::State {
        if let Err(e) = self.disk.file().flush() {
            error!("Failed to flush block data on serialization. Error: {}", e);
        }
        // Sync data out to backing file on host.
        if let Err(e) = self.disk.file().sync_all() {
            error!("Failed to sync block data on serialization. Error: {}", e);
        }
        // Save device state.
        BlockState {
            id: self.id.clone(),
            partuuid: self.partuuid.clone(),
            cache_type: CacheTypeState::from(self.cache_type()),
            root_device: self.root_device,
            disk_path: self.disk.file_path().clone(),
            virtio_state: VirtioDeviceState::from_device(self),
            rate_limiter_state: self.rate_limiter.save(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let is_disk_read_only = state.virtio_state.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0;
        let rate_limiter = RateLimiter::restore((), &state.rate_limiter_state)?;

        let mut block = Block::new(
            state.id.clone(),
            state.partuuid.clone(),
            state.cache_type.into(),
            state.disk_path.clone(),
            is_disk_read_only,
            state.root_device,
            rate_limiter,
        )?;

        block.queues = state
            .virtio_state
            .build_queues_checked(&constructor_args.mem, TYPE_BLOCK, NUM_QUEUES, QUEUE_SIZE)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        block.interrupt_status = Arc::new(AtomicUsize::new(state.virtio_state.interrupt_status));
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
    use super::*;
    use crate::virtio::device::VirtioDevice;
    use utils::tempfile::TempFile;

    use crate::virtio::test_utils::default_mem;
    use std::sync::atomic::Ordering;

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
