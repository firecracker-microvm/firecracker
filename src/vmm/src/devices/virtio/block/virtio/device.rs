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
use std::sync::Arc;

use block_io::FileEngine;
use serde::{Deserialize, Serialize};
use utils::eventfd::EventFd;
use utils::u64_to_usize;

use super::io::async_io;
use super::request::*;
use super::{
    io as block_io, VirtioBlockError, BLOCK_CONFIG_SPACE_SIZE, BLOCK_QUEUE_SIZES, SECTOR_SHIFT,
    SECTOR_SIZE,
};
use crate::devices::virtio::block::virtio::metrics::{BlockDeviceMetrics, BlockMetricsPerDevice};
use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::device::{DeviceState, IrqTrigger, IrqType, VirtioDevice};
use crate::devices::virtio::gen::virtio_blk::{
    VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_BLK_ID_BYTES, VIRTIO_F_VERSION_1,
};
use crate::devices::virtio::gen::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::{ActivateError, TYPE_BLOCK};
use crate::logger::{error, warn, IncMetric};
use crate::rate_limiter::{BucketUpdate, RateLimiter};
use crate::vmm_config::drive::BlockDeviceConfig;
use crate::vmm_config::RateLimiterConfig;
use crate::vstate::memory::GuestMemoryMmap;

/// The engine file type, either Sync or Async (through io_uring).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileEngineType {
    /// Use an Async engine, based on io_uring.
    Async,
    /// Use a Sync engine, based on blocking system calls.
    #[default]
    Sync,
}

/// Helper object for setting up all `Block` fields derived from its backing file.
#[derive(Debug)]
pub struct DiskProperties {
    pub file_path: String,
    pub file_engine: FileEngine<PendingRequest>,
    pub nsectors: u64,
    pub image_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
}

impl DiskProperties {
    // Helper function that opens the file with the proper access permissions
    fn open_file(disk_image_path: &str, is_disk_read_only: bool) -> Result<File, VirtioBlockError> {
        OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))
            .map_err(|x| VirtioBlockError::BackingFile(x, disk_image_path.to_string()))
    }

    // Helper function that gets the size of the file
    fn file_size(disk_image_path: &str, disk_image: &mut File) -> Result<u64, VirtioBlockError> {
        let disk_size = disk_image
            .seek(SeekFrom::End(0))
            .map_err(|x| VirtioBlockError::BackingFile(x, disk_image_path.to_string()))?;

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if disk_size % u64::from(SECTOR_SIZE) != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; the remainder will not be \
                 visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }

        Ok(disk_size)
    }

    /// Create a new file for the block device using a FileEngine
    pub fn new(
        disk_image_path: String,
        is_disk_read_only: bool,
        file_engine_type: FileEngineType,
    ) -> Result<Self, VirtioBlockError> {
        let mut disk_image = Self::open_file(&disk_image_path, is_disk_read_only)?;
        let disk_size = Self::file_size(&disk_image_path, &mut disk_image)?;
        let image_id = Self::build_disk_image_id(&disk_image);

        Ok(Self {
            file_path: disk_image_path,
            file_engine: FileEngine::from_file(disk_image, file_engine_type)
                .map_err(VirtioBlockError::FileEngine)?,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id,
        })
    }

    /// Update the path to the file backing the block device
    pub fn update(
        &mut self,
        disk_image_path: String,
        is_disk_read_only: bool,
    ) -> Result<(), VirtioBlockError> {
        let mut disk_image = Self::open_file(&disk_image_path, is_disk_read_only)?;
        let disk_size = Self::file_size(&disk_image_path, &mut disk_image)?;

        self.image_id = Self::build_disk_image_id(&disk_image);
        self.file_engine
            .update_file_path(disk_image)
            .map_err(VirtioBlockError::FileEngine)?;
        self.nsectors = disk_size >> SECTOR_SHIFT;
        self.file_path = disk_image_path;

        Ok(())
    }

    fn build_device_id(disk_file: &File) -> Result<String, VirtioBlockError> {
        let blk_metadata = disk_file
            .metadata()
            .map_err(VirtioBlockError::GetFileMetadata)?;
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

    /// Provides vec containing the virtio block configuration space
    /// buffer. The config space is populated with the disk size based
    /// on the backing file size.
    pub fn virtio_block_config_space(&self) -> Vec<u8> {
        // The config space is little endian.
        let mut config = Vec::with_capacity(BLOCK_CONFIG_SPACE_SIZE);
        for i in 0..BLOCK_CONFIG_SPACE_SIZE {
            config.push(((self.nsectors >> (8 * i)) & 0xff) as u8);
        }
        config
    }
}

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VirtioBlockConfig {
    /// Unique identifier of the drive.
    pub drive_id: String,
    /// Part-UUID. Represents the unique id of the boot partition of this device. It is
    /// optional and it will be used only if the `is_root_device` field is true.
    pub partuuid: Option<String>,
    /// If set to true, it makes the current device the root block device.
    /// Setting this flag to true will mount the block device in the
    /// guest under /dev/vda unless the partuuid is present.
    pub is_root_device: bool,
    /// If set to true, the drive will ignore flush requests coming from
    /// the guest driver.
    #[serde(default)]
    pub cache_type: CacheType,

    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_read_only: bool,
    /// Path of the backing file on the host
    pub path_on_host: String,
    /// Rate Limiter for I/O operations.
    pub rate_limiter: Option<RateLimiterConfig>,
    /// The type of IO engine used by the device.
    #[serde(default)]
    #[serde(rename = "io_engine")]
    pub file_engine_type: FileEngineType,
}

impl TryFrom<&BlockDeviceConfig> for VirtioBlockConfig {
    type Error = VirtioBlockError;

    fn try_from(value: &BlockDeviceConfig) -> Result<Self, Self::Error> {
        if value.path_on_host.is_some() && value.socket.is_none() {
            Ok(Self {
                drive_id: value.drive_id.clone(),
                partuuid: value.partuuid.clone(),
                is_root_device: value.is_root_device,
                cache_type: value.cache_type,

                is_read_only: value.is_read_only.unwrap_or(false),
                path_on_host: value.path_on_host.as_ref().unwrap().clone(),
                rate_limiter: value.rate_limiter,
                file_engine_type: value.file_engine_type.unwrap_or_default(),
            })
        } else {
            Err(VirtioBlockError::Config)
        }
    }
}

impl From<VirtioBlockConfig> for BlockDeviceConfig {
    fn from(value: VirtioBlockConfig) -> Self {
        Self {
            drive_id: value.drive_id,
            partuuid: value.partuuid,
            is_root_device: value.is_root_device,
            cache_type: value.cache_type,

            is_read_only: Some(value.is_read_only),
            path_on_host: Some(value.path_on_host),
            rate_limiter: value.rate_limiter,
            file_engine_type: Some(value.file_engine_type),

            socket: None,
        }
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
#[derive(Debug)]
pub struct VirtioBlock {
    // Virtio fields.
    pub avail_features: u64,
    pub acked_features: u64,
    pub config_space: Vec<u8>,
    pub activate_evt: EventFd,

    // Transport related fields.
    pub queues: Vec<Queue>,
    pub queue_evts: [EventFd; 1],
    pub device_state: DeviceState,
    pub irq_trigger: IrqTrigger,

    // Implementation specific fields.
    pub id: String,
    pub partuuid: Option<String>,
    pub cache_type: CacheType,
    pub root_device: bool,
    pub read_only: bool,

    // Host file and properties.
    pub disk: DiskProperties,
    pub rate_limiter: RateLimiter,
    pub is_io_engine_throttled: bool,
    pub metrics: Arc<BlockDeviceMetrics>,
}

macro_rules! unwrap_async_file_engine_or_return {
    ($file_engine: expr) => {
        match $file_engine {
            FileEngine::Async(engine) => engine,
            FileEngine::Sync(_) => {
                error!("The block device doesn't use an async IO engine");
                return;
            }
        }
    };
}

impl VirtioBlock {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(config: VirtioBlockConfig) -> Result<VirtioBlock, VirtioBlockError> {
        let disk_properties = DiskProperties::new(
            config.path_on_host,
            config.is_read_only,
            config.file_engine_type,
        )?;

        let rate_limiter = config
            .rate_limiter
            .map(RateLimiterConfig::try_into)
            .transpose()
            .map_err(VirtioBlockError::RateLimiter)?
            .unwrap_or_default();

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if config.cache_type == CacheType::Writeback {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if config.is_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?];

        let queues = BLOCK_QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        Ok(VirtioBlock {
            avail_features,
            acked_features: 0u64,
            config_space: disk_properties.virtio_block_config_space(),
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,

            queues,
            queue_evts,
            device_state: DeviceState::Inactive,
            irq_trigger: IrqTrigger::new().map_err(VirtioBlockError::IrqTrigger)?,

            id: config.drive_id.clone(),
            partuuid: config.partuuid,
            cache_type: config.cache_type,
            root_device: config.is_root_device,
            read_only: config.is_read_only,

            disk: disk_properties,
            rate_limiter,
            is_io_engine_throttled: false,
            metrics: BlockMetricsPerDevice::alloc(config.drive_id),
        })
    }

    /// Returns a copy of a device config
    pub fn config(&self) -> VirtioBlockConfig {
        let rl: RateLimiterConfig = (&self.rate_limiter).into();
        VirtioBlockConfig {
            drive_id: self.id.clone(),
            path_on_host: self.disk.file_path.clone(),
            is_root_device: self.root_device,
            partuuid: self.partuuid.clone(),
            is_read_only: self.read_only,
            cache_type: self.cache_type,
            rate_limiter: rl.into_option(),
            file_engine_type: self.file_engine_type(),
        }
    }

    /// Process a single event in the Virtio queue.
    ///
    /// This function is called by the event manager when the guest notifies us
    /// about new buffers in the queue.
    pub(crate) fn process_queue_event(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.queue_evts[0].read() {
            error!("Failed to get queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if self.rate_limiter.is_blocked() {
            self.metrics.rate_limiter_throttled_events.inc();
        } else if self.is_io_engine_throttled {
            self.metrics.io_engine_throttled_events.inc();
        } else {
            self.process_virtio_queues();
        }
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) {
        self.process_queue(0);
    }

    pub(crate) fn process_rate_limiter_event(&mut self) {
        self.metrics.rate_limiter_event_count.inc();
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
        block_metrics: &BlockDeviceMetrics,
    ) {
        queue.add_used(mem, index, len).unwrap_or_else(|err| {
            error!("Failed to add available descriptor head {}: {}", index, err)
        });

        if queue.prepare_kick(mem) {
            irq_trigger.trigger_irq(IrqType::Vring).unwrap_or_else(|_| {
                block_metrics.event_fails.inc();
            });
        }
    }

    /// Device specific function for peaking inside a queue and processing descriptors.
    pub fn process_queue(&mut self, queue_index: usize) {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();

        let queue = &mut self.queues[queue_index];
        let mut used_any = false;

        while let Some(head) = queue.pop_or_enable_notification(mem) {
            self.metrics.remaining_reqs_count.add(queue.len(mem).into());
            let processing_result = match Request::parse(&head, mem, self.disk.nsectors) {
                Ok(request) => {
                    if request.rate_limit(&mut self.rate_limiter) {
                        // Stop processing the queue and return this descriptor chain to the
                        // avail ring, for later processing.
                        queue.undo_pop();
                        self.metrics.rate_limiter_throttled_events.inc();
                        break;
                    }

                    used_any = true;
                    request.process(&mut self.disk, head.index, mem, &self.metrics)
                }
                Err(err) => {
                    error!("Failed to parse available descriptor chain: {:?}", err);
                    self.metrics.execute_fails.inc();
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
                        &self.metrics,
                    );
                }
            }
        }

        if let FileEngine::Async(ref mut engine) = self.disk.file_engine {
            if let Err(err) = engine.kick_submission_queue() {
                error!("BlockError submitting pending block requests: {:?}", err);
            }
        }

        if !used_any {
            self.metrics.no_avail_buffer.inc();
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
                            Err(IoErr::FileEngine(block_io::BlockIoError::Async(
                                async_io::AsyncIoError::IO(error),
                            ))),
                        ),
                    };
                    let finished = pending.finish(mem, res, &self.metrics);

                    Self::add_used_descriptor(
                        queue,
                        finished.desc_idx,
                        finished.num_bytes_to_mem,
                        mem,
                        &self.irq_trigger,
                        &self.metrics,
                    );
                }
            }
        }
    }

    pub fn process_async_completion_event(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.disk.file_engine);

        if let Err(err) = engine.completion_evt().read() {
            error!("Failed to get async completion event: {:?}", err);
        } else {
            self.process_async_completion_queue();

            if self.is_io_engine_throttled {
                self.is_io_engine_throttled = false;
                self.process_queue(0);
            }
        }
    }

    /// Update the backing file and the config space of the block device.
    pub fn update_disk_image(&mut self, disk_image_path: String) -> Result<(), VirtioBlockError> {
        self.disk.update(disk_image_path, self.read_only)?;
        self.config_space = self.disk.virtio_block_config_space();

        // Kick the driver to pick up the changes.
        self.irq_trigger.trigger_irq(IrqType::Config).unwrap();

        self.metrics.update_count.inc();
        Ok(())
    }

    /// Updates the parameters for the rate limiter
    pub fn update_rate_limiter(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        self.rate_limiter.update_buckets(bytes, ops);
    }

    /// Retrieve the file engine type.
    pub fn file_engine_type(&self) -> FileEngineType {
        match self.disk.file_engine {
            FileEngine::Sync(_) => FileEngineType::Sync,
            FileEngine::Async(_) => FileEngineType::Async,
        }
    }

    fn drain_and_flush(&mut self, discard: bool) {
        if let Err(err) = self.disk.file_engine.drain_and_flush(discard) {
            error!("Failed to drain ops and flush block data: {:?}", err);
        }
    }

    /// Prepare device for being snapshotted.
    pub fn prepare_save(&mut self) {
        if !self.is_activated() {
            return;
        }

        self.drain_and_flush(false);
        if let FileEngine::Async(ref _engine) = self.disk.file_engine {
            self.process_async_completion_queue();
        }
    }
}

impl VirtioDevice for VirtioBlock {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

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

    fn interrupt_trigger(&self) -> &IrqTrigger {
        &self.irq_trigger
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            self.metrics.cfg_fails.inc();
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(
                &self.config_space[u64_to_usize(offset)..u64_to_usize(cmp::min(end, config_len))],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let start = usize::try_from(offset).ok();
        let end = start.and_then(|s| s.checked_add(data.len()));
        let Some(dst) = start
            .zip(end)
            .and_then(|(start, end)| self.config_space.get_mut(start..end))
        else {
            error!("Failed to write config space");
            self.metrics.cfg_fails.inc();
            return;
        };

        dst.copy_from_slice(data);
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError> {
        let event_idx = self.has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX));
        if event_idx {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        if self.activate_evt.write(1).is_err() {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

impl Drop for VirtioBlock {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Unsafe => {
                if let Err(err) = self.disk.file_engine.drain(true) {
                    error!("Failed to drain ops on drop: {:?}", err);
                }
            }
            CacheType::Writeback => {
                self.drain_and_flush(true);
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use std::fs::metadata;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::thread;
    use std::time::Duration;

    use utils::tempfile::TempFile;

    use super::*;
    use crate::check_metric_after_block;
    use crate::devices::virtio::block::virtio::test_utils::{
        default_block, read_blk_req_descriptors, set_queue, set_rate_limiter,
        simulate_async_completion_event, simulate_queue_and_async_completion_events,
        simulate_queue_event,
    };
    use crate::devices::virtio::block::virtio::IO_URING_NUM_ENTRIES;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{default_mem, VirtQueue};
    use crate::rate_limiter::TokenType;
    use crate::vstate::memory::{Address, Bytes, GuestAddress};

    #[test]
    fn test_from_config() {
        let block_config = BlockDeviceConfig {
            drive_id: "".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(true),
            path_on_host: Some("path".to_string()),
            rate_limiter: None,
            file_engine_type: Default::default(),

            socket: None,
        };
        VirtioBlockConfig::try_from(&block_config).unwrap();

        let block_config = BlockDeviceConfig {
            drive_id: "".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: None,
            path_on_host: None,
            rate_limiter: None,
            file_engine_type: Default::default(),

            socket: Some("sock".to_string()),
        };
        VirtioBlockConfig::try_from(&block_config).unwrap_err();

        let block_config = BlockDeviceConfig {
            drive_id: "".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(true),
            path_on_host: Some("path".to_string()),
            rate_limiter: None,
            file_engine_type: Default::default(),

            socket: Some("sock".to_string()),
        };
        VirtioBlockConfig::try_from(&block_config).unwrap_err();
    }

    #[test]
    fn test_disk_backing_file_helper() {
        let num_sectors = 2;
        let f = TempFile::new().unwrap();
        let size = u64::from(SECTOR_SIZE) * num_sectors;
        f.as_file().set_len(size).unwrap();

        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let disk_properties =
                DiskProperties::new(String::from(f.as_path().to_str().unwrap()), true, engine)
                    .unwrap();

            assert_eq!(size, u64::from(SECTOR_SIZE) * num_sectors);
            assert_eq!(disk_properties.nsectors, num_sectors);
            let cfg = disk_properties.virtio_block_config_space();
            assert_eq!(cfg.len(), BLOCK_CONFIG_SPACE_SIZE);
            for (i, byte) in cfg.iter().enumerate() {
                assert_eq!(*byte, ((num_sectors >> (8 * i)) & 0xff) as u8);
            }
            // Testing `backing_file.virtio_block_disk_image_id()` implies
            // duplicating that logic in tests, so skipping it.

            let res = DiskProperties::new("invalid-disk-path".to_string(), true, engine);
            assert!(
                matches!(res, Err(VirtioBlockError::BackingFile(_, _))),
                "{:?}",
                res
            );
        }
    }

    #[test]
    fn test_virtio_features() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            assert_eq!(block.device_type(), TYPE_BLOCK);

            let features: u64 = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

            assert_eq!(
                block.avail_features_by_page(0),
                (features & 0xffffffff) as u32,
            );
            assert_eq!(block.avail_features_by_page(1), (features >> 32) as u32);

            for i in 2..10 {
                assert_eq!(block.avail_features_by_page(i), 0u32);
            }

            for i in 0..10 {
                block.ack_features_by_page(i, u32::MAX);
            }
            assert_eq!(block.acked_features, features);
        }
    }

    #[test]
    fn test_virtio_read_config() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let block = default_block(engine);

            let mut actual_config_space = [0u8; BLOCK_CONFIG_SPACE_SIZE];
            block.read_config(0, &mut actual_config_space);
            // This will read the number of sectors.
            // The block's backing file size is 0x1000, so there are 8 (4096/512) sectors.
            // The config space is little endian.
            let expected_config_space: [u8; BLOCK_CONFIG_SPACE_SIZE] =
                [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            assert_eq!(actual_config_space, expected_config_space);

            // Invalid read.
            let expected_config_space: [u8; BLOCK_CONFIG_SPACE_SIZE] =
                [0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf];
            actual_config_space = expected_config_space;
            block.read_config(BLOCK_CONFIG_SPACE_SIZE as u64 + 1, &mut actual_config_space);

            // Validate read failed (the config space was not updated).
            assert_eq!(actual_config_space, expected_config_space);
        }
    }

    #[test]
    fn test_virtio_write_config() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            let expected_config_space: [u8; BLOCK_CONFIG_SPACE_SIZE] =
                [0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            block.write_config(0, &expected_config_space);

            let mut actual_config_space = [0u8; BLOCK_CONFIG_SPACE_SIZE];
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

            // Large offset that may cause an overflow.
            block.write_config(u64::MAX, &new_config_space);
            // Make sure nothing got written.
            block.read_config(0, &mut actual_config_space);
            assert_eq!(actual_config_space, expected_config_space);
        }
    }

    #[test]
    fn test_invalid_request() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone()).unwrap();
            read_blk_req_descriptors(&vq);

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
    }

    #[test]
    fn test_addr_out_of_bounds() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            // Default mem size is 0x10000
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone()).unwrap();
            read_blk_req_descriptors(&vq);
            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

            // Read at out of bounds address.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                // Mark the next available descriptor.
                vq.avail.idx.set(1);

                vq.dtable[1].set(0x20000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);

                let used = vq.used.ring[0].get();
                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(used.len, 1);
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }

            // Write at out of bounds address.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                // Mark the next available descriptor.
                vq.avail.idx.set(1);

                vq.dtable[1].set(0x20000, 0x1000, VIRTQ_DESC_F_NEXT, 2);
                mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);

                let used = vq.used.ring[0].get();
                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(used.len, 1);
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }
        }
    }

    #[test]
    fn test_request_parse_failures() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone()).unwrap();
            read_blk_req_descriptors(&vq);

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
    }

    #[test]
    fn test_unsupported_request_type() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone()).unwrap();
            read_blk_req_descriptors(&vq);

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
    }

    #[test]
    fn test_end_of_region() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone()).unwrap();
            read_blk_req_descriptors(&vq);
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
                &block.metrics.read_count,
                1,
                simulate_queue_and_async_completion_events(&mut block, true)
            );

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            // Added status byte length.
            assert_eq!(vq.used.ring[0].get().len, vq.dtable[1].len.get() + 1);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_read_write() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone()).unwrap();
            read_blk_req_descriptors(&vq);

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
                block
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::Start(0))
                    .unwrap();
                block.disk.file_engine.file().read_exact(&mut buf).unwrap();
                assert_eq!(buf, empty_data.as_slice());
            }

            // Write from valid address, with an overflowing length.
            {
                let mut block = default_block(engine);

                // Default mem size is 0x10000
                let mem = default_mem();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.activate(mem.clone()).unwrap();
                read_blk_req_descriptors(&vq);
                let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

                vq.dtable[1].set(0xff00, 0x1000, VIRTQ_DESC_F_NEXT, 2);
                mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                    .unwrap();

                // Mark the next available descriptor.
                vq.avail.idx.set(1);
                vq.used.idx.set(0);

                check_metric_after_block!(
                    &block.metrics.invalid_reqs_count,
                    1,
                    simulate_queue_and_async_completion_events(&mut block, true)
                );

                let used_idx = vq.used.idx.get();
                assert_eq!(used_idx, 1);

                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
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
                    &block.metrics.write_count,
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
                    &block.metrics.read_count,
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

                let size = block
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::End(0))
                    .unwrap();
                block.disk.file_engine.file().set_len(size / 2).unwrap();
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

                let size = block
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::End(0))
                    .unwrap();
                block.disk.file_engine.file().set_len(size / 2).unwrap();
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
                // Note: this test case only works because when we truncated the file above (with
                // set_len), we did not update the sector count stored in the block device
                // itself (is still 8, even though the file length is 1024 now, e.g. has 2 sectors).
                // Normally, requests that reach past the final sector are rejected by
                // Request::parse.
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

                block
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::Start(512))
                    .unwrap();
                block
                    .disk
                    .file_engine
                    .file()
                    .write_all(&rand_data[512..])
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);

                assert_eq!(
                    mem.read_obj::<u32>(status_addr).unwrap(),
                    VIRTIO_BLK_S_IOERR
                );

                // Check that we correctly read the second file sector.
                let mut buf = [0u8; 512];
                mem.read_slice(&mut buf, data_addr).unwrap();
                assert_eq!(buf, rand_data[512..]);
            }

            // Read at valid address, with an overflowing length.
            {
                // Default mem size is 0x10000
                let mem = default_mem();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.activate(mem.clone()).unwrap();
                read_blk_req_descriptors(&vq);
                vq.dtable[1].set(0xff00, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);

                let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

                // Mark the next available descriptor.
                vq.avail.idx.set(1);
                vq.used.idx.set(0);

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

                check_metric_after_block!(
                    &block.metrics.invalid_reqs_count,
                    1,
                    simulate_queue_and_async_completion_events(&mut block, true)
                );

                let used_idx = vq.used.idx.get();
                assert_eq!(used_idx, 1);

                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }
        }
    }

    #[test]
    fn test_flush() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone()).unwrap();
            read_blk_req_descriptors(&vq);

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
    }

    #[test]
    fn test_get_device_id() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone()).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());
            let blk_metadata = block.disk.file_engine.file().metadata();

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

                let blk_meta = blk_metadata.unwrap();
                let expected_device_id = format!(
                    "{}{}{}",
                    blk_meta.st_dev(),
                    blk_meta.st_rdev(),
                    blk_meta.st_ino()
                );

                let mut buf = [0; VIRTIO_BLK_ID_BYTES as usize];
                mem.read_slice(&mut buf, data_addr).unwrap();
                let chars_to_trim: &[char] = &['\u{0}'];
                let received_device_id = String::from_utf8(buf.to_ascii_lowercase())
                    .unwrap()
                    .trim_matches(chars_to_trim)
                    .to_string();
                assert_eq!(received_device_id, expected_device_id);
            }

            // Test that a device ID request will be discarded, if it fails to provide enough buffer
            // space.
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
    }

    fn add_flush_requests_batch(block: &mut VirtioBlock, vq: &VirtQueue, count: u16) {
        let mem = vq.memory();
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

    fn check_flush_requests_batch(count: u16, vq: &VirtQueue) {
        let used_idx = vq.used.idx.get();
        assert_eq!(used_idx, count);

        for i in 0..count {
            let used = vq.used.ring[i as usize].get();
            let status_addr = vq.dtable[used.id as usize + 1].addr.get();
            assert_eq!(used.len, 1);
            assert_eq!(
                u32::from(
                    vq.memory()
                        .read_obj::<u8>(GuestAddress(status_addr))
                        .unwrap(),
                ),
                VIRTIO_BLK_S_OK
            );
        }
    }

    #[test]
    fn test_io_engine_throttling() {
        // FullSQueue BlockError
        {
            let mut block = default_block(FileEngineType::Async);

            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, IO_URING_NUM_ENTRIES * 4);
            block.activate(mem.clone()).unwrap();

            // Run scenario that doesn't trigger FullSq BlockError: Add sq_size flush requests.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.is_io_engine_throttled);
            simulate_async_completion_event(&mut block, true);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES, &vq);

            // Run scenario that triggers FullSqError : Add sq_size + 10 flush requests.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES + 10);
            simulate_queue_event(&mut block, Some(false));
            assert!(block.is_io_engine_throttled);
            // When the async_completion_event is triggered:
            // 1. sq_size requests should be processed processed.
            // 2. is_io_engine_throttled should be set back to false.
            // 3. process_queue() should be called again.
            simulate_async_completion_event(&mut block, true);
            assert!(!block.is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES, &vq);
            // check that process_queue() was called again resulting in the processing of the
            // remaining 10 ops.
            simulate_async_completion_event(&mut block, true);
            assert!(!block.is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES + 10, &vq);
        }

        // FullCQueue BlockError
        {
            let mut block = default_block(FileEngineType::Async);

            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, IO_URING_NUM_ENTRIES * 4);
            block.activate(mem.clone()).unwrap();

            // Run scenario that triggers FullCqError. Push 2 * IO_URING_NUM_ENTRIES and wait for
            // completion. Then try to push another entry.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.is_io_engine_throttled);
            thread::sleep(Duration::from_millis(150));
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.is_io_engine_throttled);
            thread::sleep(Duration::from_millis(150));

            add_flush_requests_batch(&mut block, &vq, 1);
            simulate_queue_event(&mut block, Some(false));
            assert!(block.is_io_engine_throttled);
            simulate_async_completion_event(&mut block, true);
            assert!(!block.is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES * 2, &vq);
        }
    }

    #[test]
    fn test_prepare_save() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            block.activate(mem.clone()).unwrap();

            // Add a batch of flush requests.
            add_flush_requests_batch(&mut block, &vq, 5);
            simulate_queue_event(&mut block, None);
            block.prepare_save();

            // Check that all the pending flush requests were processed during `prepare_save()`.
            check_flush_requests_batch(5, &vq);
        }
    }

    #[test]
    fn test_bandwidth_rate_limiter() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone()).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Create bandwidth rate limiter that allows only 5120 bytes/s with bucket size of 8
            // bytes.
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
                    &block.metrics.rate_limiter_throttled_events,
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
                    &block.metrics.rate_limiter_throttled_events,
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
    }

    #[test]
    fn test_ops_rate_limiter() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone()).unwrap();
            read_blk_req_descriptors(&vq);

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
                    &block.metrics.rate_limiter_throttled_events,
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
                    &block.metrics.rate_limiter_throttled_events,
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
                    &block.metrics.rate_limiter_throttled_events,
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
    }

    #[test]
    fn test_update_disk_image() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let f = TempFile::new().unwrap();
            let path = f.as_path();
            let mdata = metadata(path).unwrap();
            let mut id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
            let str_id = format!("{}{}{}", mdata.st_dev(), mdata.st_rdev(), mdata.st_ino());
            let part_id = str_id.as_bytes();
            id[..cmp::min(part_id.len(), VIRTIO_BLK_ID_BYTES as usize)].clone_from_slice(
                &part_id[..cmp::min(part_id.len(), VIRTIO_BLK_ID_BYTES as usize)],
            );

            block
                .update_disk_image(String::from(path.to_str().unwrap()))
                .unwrap();

            assert_eq!(
                block.disk.file_engine.file().metadata().unwrap().st_ino(),
                mdata.st_ino()
            );
            assert_eq!(block.disk.image_id, id.as_slice());
        }
    }
}
