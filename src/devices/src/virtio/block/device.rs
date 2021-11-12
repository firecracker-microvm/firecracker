// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use logger::{error, warn, IncMetric, METRICS};
use rate_limiter::{BucketUpdate, RateLimiter};
use utils::eventfd::EventFd;
use utils::kernel_version::KernelVersion;
use virtio_gen::virtio_blk::*;
use vm_memory::GuestMemoryMmap;

use super::io as block_io;
use super::io::async_io;
use super::{
    super::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_BLOCK},
    request::*,
    Error, CONFIG_SPACE_SIZE, QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE,
};
use crate::virtio::{IrqTrigger, IrqType};
use block_io::FileEngine;
use serde::{Deserialize, Serialize};
use virtio_gen::virtio_ring::VIRTIO_RING_F_EVENT_IDX;

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum CacheType {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

impl Default for CacheType {
    fn default() -> CacheType {
        CacheType::Unsafe
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum FileEngineType {
    /// Use an Async engine, based on io_uring.
    Async,
    /// Use a Sync engine, based on blocking system calls.
    Sync,
}

impl Default for FileEngineType {
    fn default() -> Self {
        Self::Sync
    }
}

impl FileEngineType {
    pub fn is_supported(&self) -> result::Result<bool, utils::kernel_version::Error> {
        match self {
            Self::Async if KernelVersion::get()? < KernelVersion::new(5, 10, 0) => Ok(false),
            _ => Ok(true),
        }
    }
}

/// Helper object for setting up all `Block` fields derived from its backing file.
pub(crate) struct DiskProperties {
    cache_type: CacheType,
    file_path: String,
    file_engine: FileEngine<PendingRequest>,
    nsectors: u64,
    image_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
}

impl DiskProperties {
    pub fn new(
        disk_image_path: String,
        is_disk_read_only: bool,
        cache_type: CacheType,
        file_engine_type: FileEngineType,
    ) -> result::Result<Self, Error> {
        let mut disk_image = OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))
            .map_err(Error::BackingFile)?;
        let disk_size = disk_image
            .seek(SeekFrom::End(0))
            .map_err(Error::BackingFile)? as u64;

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if disk_size % SECTOR_SIZE != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; \
                 the remainder will not be visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }

        Ok(Self {
            cache_type,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: Self::build_disk_image_id(&disk_image),
            file_path: disk_image_path,
            file_engine: FileEngine::from_file(disk_image, file_engine_type)
                .map_err(Error::FileEngine)?,
        })
    }

    pub fn file_engine(&self) -> &FileEngine<PendingRequest> {
        &self.file_engine
    }

    pub fn file_engine_mut(&mut self) -> &mut FileEngine<PendingRequest> {
        &mut self.file_engine
    }

    pub fn file(&self) -> &File {
        &self.file_engine.file()
    }

    pub fn nsectors(&self) -> u64 {
        self.nsectors
    }

    pub fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn build_device_id(disk_file: &File) -> result::Result<String, Error> {
        let blk_metadata = disk_file.metadata().map_err(Error::GetFileMetadata)?;
        // This is how kvmtool does it.
        let device_id = format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        );
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File) -> [u8; VIRTIO_BLK_ID_BYTES as usize] {
        let mut default_id = [0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(disk_id_string) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = disk_id_string.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].copy_from_slice(&disk_id[..bytes_to_copy]);
            }
        }
        default_id
    }

    /// Backing file path.
    pub fn file_path(&self) -> &String {
        &self.file_path
    }

    /// Provides vec containing the virtio block configuration space
    /// buffer. The config space is populated with the disk size based
    /// on the backing file size.
    pub fn virtio_block_config_space(&self) -> Vec<u8> {
        // The config space is little endian.
        let mut config = Vec::with_capacity(CONFIG_SPACE_SIZE);
        for i in 0..CONFIG_SPACE_SIZE {
            config.push((self.nsectors >> (8 * i)) as u8);
        }
        config
    }

    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    // Host file and properties.
    pub(crate) disk: DiskProperties,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config_space: Vec<u8>,
    pub(crate) activate_evt: EventFd,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: [EventFd; 1],
    pub(crate) device_state: DeviceState,
    pub(crate) irq_trigger: IrqTrigger,

    // Implementation specific fields.
    pub(crate) id: String,
    pub(crate) partuuid: Option<String>,
    pub(crate) root_device: bool,
    pub(crate) rate_limiter: RateLimiter,
    is_io_engine_throttled: bool,
}

macro_rules! unwrap_async_file_engine_or_return {
    ($file_engine: expr) => {
        match $file_engine {
            FileEngine::Async(engine) => engine,
            FileEngine::Sync(_) => {
                error!("The block device doesn't use an async IO engine");
                return;
            }
        };
    };
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_image_path: String,
        is_disk_read_only: bool,
        is_disk_root: bool,
        rate_limiter: RateLimiter,
        file_engine_type: FileEngineType,
    ) -> result::Result<Block, Error> {
        let disk_properties = DiskProperties::new(
            disk_image_path,
            is_disk_read_only,
            cache_type,
            file_engine_type,
        )?;

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if cache_type == CacheType::Writeback {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?];

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        Ok(Block {
            id,
            root_device: is_disk_root,
            partuuid,
            rate_limiter,
            config_space: disk_properties.virtio_block_config_space(),
            disk: disk_properties,
            avail_features,
            acked_features: 0u64,
            queue_evts,
            queues,
            device_state: DeviceState::Inactive,
            irq_trigger: IrqTrigger::new().map_err(Error::IrqTrigger)?,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            is_io_engine_throttled: false,
        })
    }

    pub(crate) fn process_queue_event(&mut self) {
        METRICS.block.queue_event_count.inc();
        if let Err(e) = self.queue_evts[0].read() {
            error!("Failed to get queue event: {:?}", e);
            METRICS.block.event_fails.inc();
        } else if self.rate_limiter.is_blocked() {
            METRICS.block.rate_limiter_throttled_events.inc();
        } else if self.is_io_engine_throttled {
            METRICS.block.io_engine_throttled_events.inc();
        } else {
            self.process_virtio_queues();
        }
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) {
        self.process_queue(0);
    }

    pub(crate) fn process_rate_limiter_event(&mut self) {
        METRICS.block.rate_limiter_event_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        if self.rate_limiter.event_handler().is_ok() {
            self.process_queue(0);
        }
    }

    fn add_used_descriptor(
        queue: &mut Queue,
        index: u16,
        len: u32,
        mem: &GuestMemoryMmap,
        irq_trigger: &IrqTrigger,
    ) {
        queue
            .add_used(mem, index, len)
            .unwrap_or_else(|e| error!("Failed to add available descriptor head {}: {}", index, e));

        if queue.prepare_kick(mem) {
            irq_trigger.trigger_irq(IrqType::Vring).unwrap_or_else(|_| {
                METRICS.block.event_fails.inc();
            });
        }
    }

    pub fn process_queue(&mut self, queue_index: usize) {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();

        let queue = &mut self.queues[queue_index];
        let mut used_any = false;

        while let Some(head) = queue.pop_or_enable_notification(mem) {
            let processing_result = match Request::parse(&head, mem, self.disk.nsectors()) {
                Ok(request) => {
                    if request.rate_limit(&mut self.rate_limiter) {
                        // Stop processing the queue and return this descriptor chain to the
                        // avail ring, for later processing.
                        queue.undo_pop();
                        METRICS.block.rate_limiter_throttled_events.inc();
                        break;
                    }

                    used_any = true;
                    request.process(&mut self.disk, head.index, mem)
                }
                Err(e) => {
                    error!("Failed to parse available descriptor chain: {:?}", e);
                    METRICS.block.execute_fails.inc();
                    ProcessingResult::Executed(FinishedRequest {
                        num_bytes_to_mem: 0,
                        desc_idx: head.index,
                    })
                }
            };

            match processing_result {
                ProcessingResult::Submitted => {}
                ProcessingResult::Throttled => {
                    queue.undo_pop();
                    self.is_io_engine_throttled = true;
                    break;
                }
                ProcessingResult::Executed(finished) => {
                    Self::add_used_descriptor(
                        queue,
                        head.index,
                        finished.num_bytes_to_mem,
                        mem,
                        &self.irq_trigger,
                    );
                }
            }
        }

        if let FileEngine::Async(engine) = self.disk.file_engine_mut() {
            if let Err(e) = engine.kick_submission_queue() {
                error!("Error submitting pending block requests: {:?}", e);
            }
        }

        if !used_any {
            METRICS.block.no_avail_buffer.inc();
        }
    }

    fn process_async_completion_queue(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.disk.file_engine);

        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();
        let queue = &mut self.queues[0];

        loop {
            match engine.pop(mem) {
                Err(error) => {
                    error!("Failed to read completed io_uring entry: {:?}", error);
                    break;
                }
                Ok(None) => break,
                Ok(Some(cqe)) => {
                    let res = cqe.result();
                    let user_data = cqe.user_data();

                    let (pending, res) = match res {
                        Ok(count) => (user_data, Ok(count)),
                        Err(error) => (
                            user_data,
                            Err(IoErr::FileEngine(block_io::Error::Async(
                                async_io::Error::IO(error),
                            ))),
                        ),
                    };
                    let finished = pending.finish(mem, res);

                    Self::add_used_descriptor(
                        queue,
                        finished.desc_idx,
                        finished.num_bytes_to_mem,
                        mem,
                        &self.irq_trigger,
                    );
                }
            }
        }
    }

    pub fn process_async_completion_event(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.disk.file_engine);

        if let Err(e) = engine.completion_evt().read() {
            error!("Failed to get async completion event: {:?}", e);
            return;
        }

        self.process_async_completion_queue();

        if self.is_io_engine_throttled {
            self.is_io_engine_throttled = false;
            self.process_queue(0);
        }
    }

    /// Update the backing file and the config space of the block device.
    pub fn update_disk_image(&mut self, disk_image_path: String) -> result::Result<(), Error> {
        let disk_properties = DiskProperties::new(
            disk_image_path,
            self.is_read_only(),
            self.cache_type(),
            self.file_engine_type(),
        )?;
        self.disk = disk_properties;
        self.config_space = self.disk.virtio_block_config_space();

        // Kick the driver to pick up the changes.
        self.irq_trigger.trigger_irq(IrqType::Config).unwrap();

        METRICS.block.update_count.inc();
        Ok(())
    }

    /// Updates the parameters for the rate limiter
    pub fn update_rate_limiter(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        self.rate_limiter.update_buckets(bytes, ops);
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides backing file path of this block device.
    pub fn file_path(&self) -> &String {
        self.disk.file_path()
    }

    /// Provides the PARTUUID of this block device.
    pub fn partuuid(&self) -> Option<&String> {
        self.partuuid.as_ref()
    }

    /// Specifies if this block device is read only.
    pub fn is_read_only(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0
    }

    /// Specifies if this block device is read only.
    pub fn is_root_device(&self) -> bool {
        self.root_device
    }

    /// Specifies block device cache type.
    pub fn cache_type(&self) -> CacheType {
        self.disk.cache_type()
    }

    /// Provides non-mutable reference to this device's rate limiter.
    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }

    pub fn file_engine_type(&self) -> FileEngineType {
        match self.disk.file_engine() {
            FileEngine::Sync(_) => FileEngineType::Sync,
            FileEngine::Async(_) => FileEngineType::Async,
        }
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.irq_trigger.irq_evt
    }

    /// Returns the current device interrupt status.
    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.irq_trigger.irq_status.clone()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            METRICS.block.cfg_fails.inc();
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_len = self.config_space.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            METRICS.block.cfg_fails.inc();
            return;
        }

        self.config_space[offset as usize..(offset + data_len) as usize].copy_from_slice(data);
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        let event_idx = self.has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX));
        if event_idx {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        if self.activate_evt.write(1).is_err() {
            error!("Block: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        let flush = match self.disk.cache_type {
            CacheType::Unsafe => false,
            CacheType::Writeback => true,
        };
        if let Err(e) = self.disk.file_engine_mut().drain(flush) {
            error!("Failed to drain ops and flush block data on drop: {:?}", e);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::metadata;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::thread;
    use std::time::Duration;
    use std::u32;

    use super::*;
    use crate::virtio::queue::tests::*;
    use rate_limiter::TokenType;
    use utils::skip_if_kernel_lt_5_10;
    use utils::tempfile::TempFile;
    use vm_memory::{Address, Bytes, GuestAddress};

    use crate::check_metric_after_block;
    use crate::virtio::block::test_utils::{
        default_block, default_engine_type_for_kv, set_queue, set_rate_limiter,
        simulate_async_completion_event, simulate_queue_and_async_completion_events,
        simulate_queue_event,
    };
    use crate::virtio::test_utils::{default_mem, initialize_virtqueue, VirtQueue};
    use crate::virtio::IO_URING_NUM_ENTRIES;

    #[test]
    fn test_disk_backing_file_helper() {
        let num_sectors = 2;
        let f = TempFile::new().unwrap();
        let size = SECTOR_SIZE * num_sectors;
        f.as_file().set_len(size).unwrap();

        let disk_properties = DiskProperties::new(
            String::from(f.as_path().to_str().unwrap()),
            true,
            CacheType::Unsafe,
            default_engine_type_for_kv(),
        )
        .unwrap();

        assert_eq!(size, SECTOR_SIZE * num_sectors);
        assert_eq!(disk_properties.nsectors, num_sectors);
        let cfg = disk_properties.virtio_block_config_space();
        assert_eq!(cfg.len(), CONFIG_SPACE_SIZE);
        for (i, byte) in cfg.iter().enumerate() {
            assert_eq!(*byte, (num_sectors >> (8 * i)) as u8);
        }
        // Testing `backing_file.virtio_block_disk_image_id()` implies
        // duplicating that logic in tests, so skipping it.

        assert!(DiskProperties::new(
            "invalid-disk-path".to_string(),
            true,
            CacheType::Unsafe,
            default_engine_type_for_kv(),
        )
        .is_err());
    }

    #[test]
    fn test_virtio_features() {
        let mut block = default_block(default_engine_type_for_kv());

        assert_eq!(block.device_type(), TYPE_BLOCK);

        let features: u64 = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        assert_eq!(block.avail_features_by_page(0), features as u32);
        assert_eq!(block.avail_features_by_page(1), (features >> 32) as u32);

        for i in 2..10 {
            assert_eq!(block.avail_features_by_page(i), 0u32);
        }

        for i in 0..10 {
            block.ack_features_by_page(i, u32::MAX);
        }
        assert_eq!(block.acked_features, features);
    }

    #[test]
    fn test_virtio_read_config() {
        let block = default_block(default_engine_type_for_kv());

        let mut actual_config_space = [0u8; CONFIG_SPACE_SIZE];
        block.read_config(0, &mut actual_config_space);
        // This will read the number of sectors.
        // The block's backing file size is 0x1000, so there are 8 (4096/512) sectors.
        // The config space is little endian.
        let expected_config_space: [u8; CONFIG_SPACE_SIZE] =
            [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(actual_config_space, expected_config_space);

        // Invalid read.
        let expected_config_space: [u8; CONFIG_SPACE_SIZE] =
            [0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf];
        actual_config_space = expected_config_space;
        block.read_config(CONFIG_SPACE_SIZE as u64 + 1, &mut actual_config_space);

        // Validate read failed (the config space was not updated).
        assert_eq!(actual_config_space, expected_config_space);
    }

    #[test]
    fn test_virtio_write_config() {
        let mut block = default_block(default_engine_type_for_kv());

        let expected_config_space: [u8; CONFIG_SPACE_SIZE] =
            [0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        block.write_config(0, &expected_config_space);

        let mut actual_config_space = [0u8; CONFIG_SPACE_SIZE];
        block.read_config(0, &mut actual_config_space);
        assert_eq!(actual_config_space, expected_config_space);

        // If priviledged user writes to `/dev/mem`, in block config space - byte by byte.
        let expected_config_space = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x11];
        for i in 0..expected_config_space.len() {
            block.write_config(i as u64, &expected_config_space[i..=i]);
        }
        block.read_config(0, &mut actual_config_space);
        assert_eq!(actual_config_space, expected_config_space);

        // Invalid write.
        let new_config_space = [0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf];
        block.write_config(5, &new_config_space);
        // Make sure nothing got written.
        block.read_config(0, &mut actual_config_space);
        assert_eq!(actual_config_space, expected_config_space);
    }

    #[test]
    fn test_invalid_request() {
        let mut block = default_block(default_engine_type_for_kv());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

        // Request is invalid because the first descriptor is write-only.
        vq.dtable[0]
            .flags
            .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
        mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
            .unwrap();

        simulate_queue_event(&mut block, Some(true));

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 0);
    }

    #[test]
    fn test_addr_out_of_bounds() {
        let mut block = default_block(default_engine_type_for_kv());
        // Default mem size is 0x10000
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);
        vq.dtable[1].set(0xff00, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

        // Mark the next available descriptor.
        vq.avail.idx.set(1);
        // Read.
        {
            vq.used.idx.set(0);

            mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                .unwrap();
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

            check_metric_after_block!(
                &METRICS.block.invalid_reqs_count,
                1,
                simulate_queue_event(&mut block, Some(true))
            );
        }
    }

    #[test]
    fn test_request_parse_failures() {
        let mut block = default_block(default_engine_type_for_kv());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

        {
            // First descriptor no longer writable.
            vq.dtable[0].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);

            // Generate a seek execute error caused by a very large sector number.
            let request_header = RequestHeader::new(VIRTIO_BLK_T_OUT, 0x000f_ffff_ffff);
            mem.write_obj::<RequestHeader>(request_header, request_type_addr)
                .unwrap();

            simulate_queue_event(&mut block, Some(true));

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
        }

        {
            // Reset the queue to reuse descriptors and memory.
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());

            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            // Set sector to a valid number large enough that the full 0x1000 read will fail.
            let request_header = RequestHeader::new(VIRTIO_BLK_T_IN, 10);
            mem.write_obj::<RequestHeader>(request_header, request_type_addr)
                .unwrap();

            simulate_queue_event(&mut block, Some(true));

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
        }
    }

    #[test]
    fn test_unsupported_request_type() {
        let mut block = default_block(default_engine_type_for_kv());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        // Currently only VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
        // VIRTIO_BLK_T_FLUSH and VIRTIO_BLK_T_GET_ID  are supported.
        // Generate an unsupported request.
        let request_header = RequestHeader::new(42, 0);
        mem.write_obj::<RequestHeader>(request_header, request_type_addr)
            .unwrap();

        simulate_queue_event(&mut block, Some(true));

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 1);
        assert_eq!(
            mem.read_obj::<u32>(status_addr).unwrap(),
            VIRTIO_BLK_S_UNSUPP
        );
    }
    #[test]
    fn test_end_of_region() {
        let mut block = default_block(default_engine_type_for_kv());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);
        vq.dtable[1].set(0xf000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        vq.used.idx.set(0);

        mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
            .unwrap();
        vq.dtable[1]
            .flags
            .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

        check_metric_after_block!(
            &METRICS.block.read_count,
            1,
            simulate_queue_and_async_completion_events(&mut block, true)
        );

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        // Added status byte length.
        assert_eq!(vq.used.ring[0].get().len, vq.dtable[1].len.get() + 1);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
    }

    #[test]
    fn test_read_write() {
        let mut block = default_block(default_engine_type_for_kv());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        let empty_data = vec![0; 512];
        let rand_data = utils::rand::rand_alphanumerics(1024).as_bytes().to_vec();

        // Write with invalid data len (not a multiple of 512).
        {
            mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                .unwrap();
            // Make data read only, 512 bytes in len, and set the actual value to be written.
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(511);
            mem.write_slice(&rand_data[..511], data_addr).unwrap();

            simulate_queue_and_async_completion_events(&mut block, true);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);

            // Check that the data wasn't written to the file
            let mut buf = [0u8; 512];
            block.disk.file().seek(SeekFrom::Start(0)).unwrap();
            block.disk.file().read_exact(&mut buf).unwrap();
            assert_eq!(buf, empty_data.as_slice());
        }

        // Write.
        {
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());

            mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                .unwrap();
            // Make data read only, 512 bytes in len, and set the actual value to be written.
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(512);
            mem.write_slice(&rand_data[..512], data_addr).unwrap();

            check_metric_after_block!(
                &METRICS.block.write_count,
                1,
                simulate_queue_and_async_completion_events(&mut block, true)
            );

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }

        // Read with invalid data len (not a multiple of 512).
        {
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());

            mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                .unwrap();
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            vq.dtable[1].len.set(511);
            mem.write_slice(empty_data.as_slice(), data_addr).unwrap();

            simulate_queue_and_async_completion_events(&mut block, true);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            // The descriptor should have been discarded.
            assert_eq!(vq.used.ring[0].get().len, 0);

            // Check that no data was read.
            let mut buf = [0u8; 512];
            mem.read_slice(&mut buf, data_addr).unwrap();
            assert_eq!(buf, empty_data.as_slice());
        }

        // Read.
        {
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());

            mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                .unwrap();
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            vq.dtable[1].len.set(512);
            mem.write_slice(empty_data.as_slice(), data_addr).unwrap();

            check_metric_after_block!(
                &METRICS.block.read_count,
                1,
                simulate_queue_and_async_completion_events(&mut block, true)
            );

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            // Added status byte length.
            assert_eq!(vq.used.ring[0].get().len, vq.dtable[1].len.get() + 1);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

            // Check that the data is the same that we wrote before
            let mut buf = [0u8; 512];
            mem.read_slice(&mut buf, data_addr).unwrap();
            assert_eq!(buf, &rand_data[..512]);
        }

        // Read with error.
        {
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());

            mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                .unwrap();
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            mem.write_slice(empty_data.as_slice(), data_addr).unwrap();

            let size = block.disk.file().seek(SeekFrom::End(0)).unwrap();
            block.disk.file().set_len(size / 2).unwrap();
            mem.write_obj(10, GuestAddress(request_type_addr.0 + 8))
                .unwrap();

            simulate_queue_and_async_completion_events(&mut block, true);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            // The descriptor should have been discarded.
            assert_eq!(vq.used.ring[0].get().len, 0);

            // Check that no data was read.
            let mut buf = [0u8; 512];
            mem.read_slice(&mut buf, data_addr).unwrap();
            assert_eq!(buf, empty_data.as_slice());
        }

        // Partial buffer error on read.
        {
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());

            mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                .unwrap();
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

            let size = block.disk.file().seek(SeekFrom::End(0)).unwrap();
            block.disk.file().set_len(size / 2).unwrap();
            // Update sector number: stored at `request_type_addr.0 + 8`
            mem.write_obj(5, GuestAddress(request_type_addr.0 + 8))
                .unwrap();

            // This will attempt to read past end of file.
            simulate_queue_and_async_completion_events(&mut block, true);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);

            // No data since can't read past end of file, only status byte length.
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(
                mem.read_obj::<u32>(status_addr).unwrap(),
                VIRTIO_BLK_S_IOERR
            );

            // Check that no data was read since we can't read past the end of the file.
            let mut buf = [0u8; 512];
            mem.read_slice(&mut buf, data_addr).unwrap();
            assert_eq!(buf, empty_data.as_slice());
        }

        {
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());

            mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                .unwrap();
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            vq.dtable[1].len.set(1024);

            mem.write_obj(1, GuestAddress(request_type_addr.0 + 8))
                .unwrap();

            block.disk.file().seek(SeekFrom::Start(512)).unwrap();
            block.disk.file().write_all(&rand_data[512..]).unwrap();

            simulate_queue_and_async_completion_events(&mut block, true);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);

            // File has 2 sectors and we try to read from the second sector, which means we will
            // read 512 bytes (instead of 1024).
            assert_eq!(vq.used.ring[0].get().len, 513);
            assert_eq!(
                mem.read_obj::<u32>(status_addr).unwrap(),
                VIRTIO_BLK_S_IOERR
            );

            // Check that we correctly read the second file sector.
            let mut buf = [0u8; 512];
            mem.read_slice(&mut buf, data_addr).unwrap();
            assert_eq!(buf, rand_data[512..]);
        }
    }

    #[test]
    fn test_flush() {
        let mut block = default_block(default_engine_type_for_kv());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        // Flush completes successfully without a data descriptor.
        {
            vq.dtable[0].next.set(2);

            mem.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, request_type_addr)
                .unwrap();

            simulate_queue_and_async_completion_events(&mut block, true);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }

        // Flush completes successfully even with a data descriptor.
        {
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());
            vq.dtable[0].next.set(1);

            mem.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, request_type_addr)
                .unwrap();

            simulate_queue_and_async_completion_events(&mut block, true);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            // status byte length.
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_get_device_id() {
        let mut block = default_block(default_engine_type_for_kv());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());
        let blk_metadata = block.disk.file().metadata();

        // Test that the driver receives the correct device id.
        {
            vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES);

            mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
                .unwrap();

            simulate_queue_event(&mut block, Some(true));
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 21);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

            assert!(blk_metadata.is_ok());
            let blk_meta = blk_metadata.unwrap();
            let expected_device_id = format!(
                "{}{}{}",
                blk_meta.st_dev(),
                blk_meta.st_rdev(),
                blk_meta.st_ino()
            );

            let mut buf = [0; VIRTIO_BLK_ID_BYTES as usize];
            assert!(mem.read_slice(&mut buf, data_addr).is_ok());
            let chars_to_trim: &[char] = &['\u{0}'];
            let received_device_id = String::from_utf8(buf.to_ascii_lowercase())
                .unwrap()
                .trim_matches(chars_to_trim)
                .to_string();
            assert_eq!(received_device_id, expected_device_id);
        }

        // Test that a device ID request will be discarded, if it fails to provide enough buffer space.
        {
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());
            vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES - 1);

            mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
                .unwrap();

            simulate_queue_event(&mut block, Some(true));
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
        }
    }

    fn add_flush_requests_batch(
        block: &mut Block,
        mem: &GuestMemoryMmap,
        vq: &VirtQueue,
        count: u16,
    ) {
        vq.avail.idx.set(0);
        vq.used.idx.set(0);
        set_queue(block, 0, vq.create_queue());

        let hdr_addr = vq
            .end()
            .checked_align_up(std::mem::align_of::<RequestHeader>() as u64)
            .unwrap();
        // Write request header. All requests will use the same header.
        mem.write_obj(RequestHeader::new(VIRTIO_BLK_T_FLUSH, 0), hdr_addr)
            .unwrap();

        let mut status_addr = hdr_addr
            .checked_add(std::mem::size_of::<RequestHeader>() as u64)
            .unwrap()
            .checked_align_up(4)
            .unwrap();

        for i in 0..count {
            let idx = i * 2;

            let hdr_desc = &vq.dtable[idx as usize];
            hdr_desc.addr.set(hdr_addr.0);
            hdr_desc.flags.set(VIRTQ_DESC_F_NEXT);
            hdr_desc.next.set(idx + 1);

            let status_desc = &vq.dtable[idx as usize + 1];
            status_desc.addr.set(status_addr.0);
            status_desc.flags.set(VIRTQ_DESC_F_WRITE);
            status_desc.len.set(4);
            status_addr = status_addr.checked_add(4).unwrap();

            vq.avail.ring[i as usize].set(idx);
            vq.avail.idx.set(i + 1);
        }
    }

    fn check_flush_requests_batch(count: u16, mem: &GuestMemoryMmap, vq: &VirtQueue) {
        let used_idx = vq.used.idx.get();
        assert_eq!(used_idx, count);

        for i in 0..count {
            let used = vq.used.ring[i as usize].get();
            let status_addr = vq.dtable[used.id as usize + 1].addr.get();
            assert_eq!(used.len, 1);
            assert_eq!(
                mem.read_obj::<u8>(GuestAddress(status_addr)).unwrap(),
                VIRTIO_BLK_S_OK as u8
            );
        }
    }

    #[test]
    fn test_io_engine_throttling() {
        // skip this test if kernel < 5.10 since in this case the sync engine will be used.
        skip_if_kernel_lt_5_10!();

        let mut block = default_block(FileEngineType::Async);

        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, IO_URING_NUM_ENTRIES * 4);
        block.activate(mem.clone()).unwrap();

        // Run scenario that doesn't trigger FullSq Error: Add sq_size flush requests.
        add_flush_requests_batch(&mut block, &mem, &vq, IO_URING_NUM_ENTRIES);
        simulate_queue_event(&mut block, Some(false));
        assert_eq!(block.is_io_engine_throttled, false);
        simulate_async_completion_event(&mut block, true);
        check_flush_requests_batch(IO_URING_NUM_ENTRIES, &mem, &vq);

        // Run scenario that triggers FullSqError : Add sq_size + 10 flush requests.
        add_flush_requests_batch(&mut block, &mem, &vq, IO_URING_NUM_ENTRIES + 10);
        simulate_queue_event(&mut block, Some(false));
        assert_eq!(block.is_io_engine_throttled, true);
        // When the async_completion_event is triggered:
        // 1. sq_size requests should be processed processed.
        // 2. is_io_engine_throttled should be set back to false.
        // 3. process_queue() should be called again.
        simulate_async_completion_event(&mut block, true);
        assert_eq!(block.is_io_engine_throttled, false);
        check_flush_requests_batch(IO_URING_NUM_ENTRIES, &mem, &vq);
        // check that process_queue() was called again resulting in the processing of the
        // remaining 10 ops.
        simulate_async_completion_event(&mut block, true);
        assert_eq!(block.is_io_engine_throttled, false);
        check_flush_requests_batch(IO_URING_NUM_ENTRIES + 10, &mem, &vq);
    }

    #[test]
    fn test_bandwidth_rate_limiter() {
        let mut block = default_block(default_engine_type_for_kv());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        // Create bandwidth rate limiter that allows only 5120 bytes/s with bucket size of 8 bytes.
        let mut rl = RateLimiter::new(512, 0, 100, 0, 0, 0).unwrap();
        // Use up the budget.
        assert!(rl.consume(512, TokenType::Bytes));

        set_rate_limiter(&mut block, rl);

        mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
            .unwrap();
        // Make data read only, 512 bytes in len, and set the actual value to be written
        vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
        vq.dtable[1].len.set(512);
        mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

        // Following write procedure should fail because of bandwidth rate limiting.
        {
            // Trigger the attempt to write.
            check_metric_after_block!(
                &METRICS.block.rate_limiter_throttled_events,
                1,
                simulate_queue_event(&mut block, Some(false))
            );

            // Assert that limiter is blocked.
            assert!(block.rate_limiter.is_blocked());
            // Make sure the data is still queued for processing.
            assert_eq!(vq.used.idx.get(), 0);
        }

        // Wait for 100ms to give the rate-limiter timer a chance to replenish.
        // Wait for an extra 50ms to make sure the timerfd event makes its way from the kernel.
        thread::sleep(Duration::from_millis(150));

        // Following write procedure should succeed because bandwidth should now be available.
        {
            check_metric_after_block!(
                &METRICS.block.rate_limiter_throttled_events,
                0,
                block.process_rate_limiter_event()
            );
            // Validate the rate_limiter is no longer blocked.
            assert!(!block.rate_limiter.is_blocked());
            // Complete async IO ops if needed
            simulate_async_completion_event(&mut block, true);

            // Make sure the data queue advanced.
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_ops_rate_limiter() {
        let mut block = default_block(default_engine_type_for_kv());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        // Create ops rate limiter that allows only 10 ops/s with bucket size of 1 ops.
        let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 100).unwrap();
        // Use up the budget.
        assert!(rl.consume(1, TokenType::Ops));

        set_rate_limiter(&mut block, rl);

        mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
            .unwrap();
        // Make data read only, 512 bytes in len, and set the actual value to be written.
        vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
        vq.dtable[1].len.set(512);
        mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

        // Following write procedure should fail because of ops rate limiting.
        {
            // Trigger the attempt to write.
            check_metric_after_block!(
                &METRICS.block.rate_limiter_throttled_events,
                1,
                simulate_queue_event(&mut block, Some(false))
            );

            // Assert that limiter is blocked.
            assert!(block.rate_limiter.is_blocked());
            // Make sure the data is still queued for processing.
            assert_eq!(vq.used.idx.get(), 0);
        }

        // Do a second write that still fails but this time on the fast path.
        {
            // Trigger the attempt to write.
            check_metric_after_block!(
                &METRICS.block.rate_limiter_throttled_events,
                1,
                simulate_queue_event(&mut block, Some(false))
            );

            // Assert that limiter is blocked.
            assert!(block.rate_limiter.is_blocked());
            // Make sure the data is still queued for processing.
            assert_eq!(vq.used.idx.get(), 0);
        }

        // Wait for 100ms to give the rate-limiter timer a chance to replenish.
        // Wait for an extra 50ms to make sure the timerfd event makes its way from the kernel.
        thread::sleep(Duration::from_millis(150));

        // Following write procedure should succeed because ops budget should now be available.
        {
            check_metric_after_block!(
                &METRICS.block.rate_limiter_throttled_events,
                0,
                block.process_rate_limiter_event()
            );
            // Validate the rate_limiter is no longer blocked.
            assert!(!block.rate_limiter.is_blocked());
            // Complete async IO ops if needed
            simulate_async_completion_event(&mut block, true);

            // Make sure the data queue advanced.
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_update_disk_image() {
        let mut block = default_block(default_engine_type_for_kv());
        let f = TempFile::new().unwrap();
        let path = f.as_path();
        let mdata = metadata(&path).unwrap();
        let mut id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        let str_id = format!("{}{}{}", mdata.st_dev(), mdata.st_rdev(), mdata.st_ino());
        let part_id = str_id.as_bytes();
        id[..cmp::min(part_id.len(), VIRTIO_BLK_ID_BYTES as usize)]
            .clone_from_slice(&part_id[..cmp::min(part_id.len(), VIRTIO_BLK_ID_BYTES as usize)]);

        block
            .update_disk_image(String::from(path.to_str().unwrap()))
            .unwrap();

        assert_eq!(
            block.disk.file().metadata().unwrap().st_ino(),
            mdata.st_ino()
        );
        assert_eq!(block.disk.image_id, id.as_slice());
    }
}
