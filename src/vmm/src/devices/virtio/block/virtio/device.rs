// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::ops::Deref;
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use vm_memory::ByteValued;
use vmm_sys_util::eventfd::EventFd;

use super::io::FileEngine;
use super::worker::{BlockWorker, FlushMode, WorkerHandle};
use super::{BLOCK_QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE, VirtioBlockError};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::block::virtio::metrics::{BlockDeviceMetrics, BlockMetricsPerDevice};
use crate::devices::virtio::device::{ActiveState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_blk::{
    VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_BLK_ID_BYTES,
};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::{InvalidAvailIdx, Queue, QueueConfig, QueueError};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::impl_device_type;
use crate::logger::{IncMetric, error, warn};
use crate::rate_limiter::{BucketUpdate, RateLimiter};
use crate::seccomp::BpfProgram;
use crate::vmm_config::drive::BlockDeviceConfig;
use crate::vmm_config::{RateLimiterConfig, TokenBucketConfig};
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
    pub file_engine: FileEngine,
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
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct ConfigSpace {
    pub capacity: u64,
}

// SAFETY: `ConfigSpace` contains only PODs in `repr(C)` or `repr(transparent)`, without padding.
unsafe impl ByteValued for ConfigSpace {}

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
        if let (Some(path_on_host), None) = (&value.path_on_host, &value.socket) {
            Ok(Self {
                drive_id: value.drive_id.clone(),
                partuuid: value.partuuid.clone(),
                is_root_device: value.is_root_device,
                cache_type: value.cache_type,

                is_read_only: value.is_read_only.unwrap_or(false),
                path_on_host: path_on_host.clone(),
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
    pub config_space: ConfigSpace,
    pub activate_evt: EventFd,

    pub(crate) config: VirtioBlockConfig,
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
    pub(crate) state: BlockState,
    pub metrics: Arc<BlockDeviceMetrics>,
}

/// State of the block data-path resources.
#[derive(Debug)]
pub(crate) enum BlockState {
    // Vmm owns the runtime resources before activation
    // In threaded mode, it also owns a parked worker thread
    Configuring(BlockResources, Option<WorkerHandle>),
    // Active state, worker owns data-path resources
    Active(ActiveBlock),
    // Placeholder to hold state when activating
    Placeholder,
}

/// Active block data path.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ActiveBlock {
    // Data path on VMM thread (single thread)
    Inline(BlockWorker),
    // Data path on a dedicated worker thread (multi thread)
    Threaded(ThreadedActive),
}

/// VMM-side state when data path runs on a worker thread
#[derive(Debug)]
pub(crate) struct ThreadedActive {
    pub(crate) worker_handle: WorkerHandle,
    interrupt: Arc<dyn VirtioInterrupt>,
    queue_config: Vec<QueueConfig>,
}

/// Runtime resources used by the block data path.
#[derive(Debug)]
pub(crate) struct BlockResources {
    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: [EventFd; 1],
    pub(crate) disk: DiskProperties,
    pub(crate) is_io_engine_throttled: bool,
}

fn apply_bucket_update(config: &mut Option<TokenBucketConfig>, update: &BucketUpdate) {
    match update {
        BucketUpdate::None => {}
        BucketUpdate::Disabled => *config = None,
        BucketUpdate::Update(bucket) => *config = Some(bucket.into()),
    }
}

impl VirtioBlock {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(mut config: VirtioBlockConfig) -> Result<VirtioBlock, VirtioBlockError> {
        let disk_properties = DiskProperties::new(
            config.path_on_host.clone(),
            config.is_read_only,
            config.file_engine_type,
        )?;

        let rate_limiter = config
            .rate_limiter
            .map(RateLimiter::from)
            .unwrap_or_default();
        let rate_limiter_config: RateLimiterConfig = (&rate_limiter).into();
        config.rate_limiter = rate_limiter_config.into_option();

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if config.cache_type == CacheType::Writeback {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if config.is_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let config_space = ConfigSpace {
            capacity: disk_properties.nsectors.to_le(),
        };
        let metrics = BlockMetricsPerDevice::alloc(config.drive_id.clone());

        Ok(VirtioBlock {
            avail_features,
            acked_features: 0u64,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,

            config,
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
            state: BlockState::Configuring(
                BlockResources {
                    queues: BLOCK_QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect(),
                    queue_evts: [
                        EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?
                    ],
                    disk: disk_properties,
                    is_io_engine_throttled: false,
                },
                None,
            ),
            metrics,
        })
    }

    /// Returns a copy of a device config
    pub fn config(&self) -> VirtioBlockConfig {
        self.config.clone()
    }

    pub(crate) fn resources(&self) -> &BlockResources {
        match &self.state {
            BlockState::Configuring(resources, _) => resources,
            BlockState::Active(ActiveBlock::Inline(worker)) => &worker.resources,
            BlockState::Active(ActiveBlock::Threaded(_)) => {
                unreachable!("worker thread owns the runtime resources")
            }
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    pub(crate) fn resources_mut(&mut self) -> &mut BlockResources {
        match &mut self.state {
            BlockState::Configuring(resources, _) => resources,
            BlockState::Active(ActiveBlock::Inline(worker)) => &mut worker.resources,
            BlockState::Active(ActiveBlock::Threaded(_)) => {
                unreachable!("worker thread owns the runtime resources")
            }
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    pub(crate) fn disk(&self) -> &DiskProperties {
        &self.resources().disk
    }

    pub(crate) fn rate_limiter(&self) -> MutexGuard<'_, RateLimiter> {
        self.rate_limiter
            .lock()
            .expect("Poisoned block rate limiter lock")
    }

    pub(crate) fn is_threaded_active(&self) -> bool {
        matches!(self.state, BlockState::Active(ActiveBlock::Threaded(_)))
    }

    /// Process a single event in the Virtio queue.
    ///
    /// This function is called by the event manager when the guest notifies us
    /// about new buffers in the queue.
    pub(crate) fn process_queue_event(&mut self) {
        if let BlockState::Active(ActiveBlock::Inline(worker)) = &mut self.state {
            worker.process_queue_event();
        }
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        if let BlockState::Active(ActiveBlock::Inline(worker)) = &mut self.state {
            worker.process_virtio_queues()
        } else {
            Ok(())
        }
    }

    pub(crate) fn process_rate_limiter_event(&mut self) {
        self.metrics.rate_limiter_event_count.inc();
        if self.rate_limiter().event_handler().is_err() {
            return;
        }

        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        match &mut self.state {
            BlockState::Active(ActiveBlock::Inline(worker)) => {
                worker.process_virtio_queues().unwrap();
            }
            BlockState::Active(ActiveBlock::Threaded(active)) => active.worker_handle.kick(false),
            BlockState::Configuring(_, _) => {}
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    pub fn process_async_completion_event(&mut self) {
        if let BlockState::Active(ActiveBlock::Inline(worker)) = &mut self.state {
            worker.process_async_completion_event();
        }
    }

    /// Update the backing file and the config space of the block device.
    pub fn update_disk_image(&mut self, disk_image_path: String) -> Result<(), VirtioBlockError> {
        let config_path = disk_image_path.clone();
        let read_only = self.config.is_read_only;
        let nsectors = match &mut self.state {
            BlockState::Configuring(resources, _) => {
                resources.disk.update(disk_image_path, read_only)?;
                resources.disk.nsectors
            }
            BlockState::Active(ActiveBlock::Inline(worker)) => {
                worker.update_disk_image(disk_image_path, read_only)?
            }
            BlockState::Active(ActiveBlock::Threaded(active)) => active
                .worker_handle
                .update_disk_image(disk_image_path, read_only)?,
            BlockState::Placeholder => unreachable!("not a runtime state"),
        };
        self.config_space.capacity = nsectors.to_le();
        self.config.path_on_host = config_path;

        // Kick the driver to pick up the changes. (But only if the device is already activated).
        if self.is_activated() {
            self.interrupt_trigger()
                .trigger(VirtioInterruptType::Config)
                .unwrap();
        }

        self.metrics.update_count.inc();
        Ok(())
    }

    /// Updates the parameters for the rate limiter
    pub fn update_rate_limiter(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        let mut rate_limiter = self.config.rate_limiter.unwrap_or_default();
        apply_bucket_update(&mut rate_limiter.bandwidth, &bytes);
        apply_bucket_update(&mut rate_limiter.ops, &ops);

        self.rate_limiter().update_buckets(bytes, ops);
        self.config.rate_limiter = rate_limiter.into_option();
    }

    /// Retrieve the file engine type, which is fixed for the device lifetime.
    pub fn file_engine_type(&self) -> FileEngineType {
        self.config.file_engine_type
    }

    /// Prepare device for being snapshotted.
    pub fn prepare_save(&mut self) {
        match &mut self.state {
            BlockState::Active(ActiveBlock::Inline(worker)) => worker.prepare_save(),
            BlockState::Active(ActiveBlock::Threaded(active)) => {
                if let Err(err) = active.worker_handle.pause() {
                    error!("Failed to pause block worker for snapshot: {:?}", err);
                }
            }
            BlockState::Configuring(_, _) => {}
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    /// Spawn a parked worker thread for the next activation.
    pub(crate) fn spawn_worker(
        &mut self,
        seccomp_filter: Arc<BpfProgram>,
    ) -> Result<(), VirtioBlockError> {
        if let BlockState::Configuring(resources, worker_handle @ None) = &mut self.state {
            let queue_evts = resources
                .queue_evts
                .iter()
                .map(EventFd::try_clone)
                .collect::<Result<Vec<_>, _>>()
                .map_err(VirtioBlockError::EventFd)?;

            let name = format!("fc_{}", self.config.drive_id);
            let worker = WorkerHandle::spawn(seccomp_filter, queue_evts, name)
                .map_err(VirtioBlockError::ThreadSpawn)?;
            *worker_handle = Some(worker);
        }
        Ok(())
    }
}

impl VirtioDevice for VirtioBlock {
    impl_device_type!(VirtioDeviceType::Block);

    fn id(&self) -> &str {
        &self.config.drive_id
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

    fn num_queues(&self) -> usize {
        match &self.state {
            BlockState::Configuring(resources, _) => resources.queues.len(),
            BlockState::Active(ActiveBlock::Inline(worker)) => worker.resources.queues.len(),
            BlockState::Active(ActiveBlock::Threaded(active)) => active.queue_config.len(),
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn queue_config(&self, index: usize) -> Option<&QueueConfig> {
        match &self.state {
            BlockState::Configuring(resources, _) => {
                resources.queues.get(index).map(|queue| &queue.config)
            }
            BlockState::Active(ActiveBlock::Inline(worker)) => worker
                .resources
                .queues
                .get(index)
                .map(|queue| &queue.config),
            BlockState::Active(ActiveBlock::Threaded(active)) => active.queue_config.get(index),
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn queue_config_mut(&mut self, index: usize) -> Option<&mut QueueConfig> {
        match &mut self.state {
            BlockState::Configuring(resources, _) => resources
                .queues
                .get_mut(index)
                .map(|queue| &mut queue.config),
            BlockState::Active(ActiveBlock::Inline(worker)) => worker
                .resources
                .queues
                .get_mut(index)
                .map(|queue| &mut queue.config),
            BlockState::Active(ActiveBlock::Threaded(active)) => active.queue_config.get_mut(index),
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn queue_event(&self, index: usize) -> Option<&EventFd> {
        match &self.state {
            BlockState::Configuring(resources, _) => resources.queue_evts.get(index),
            BlockState::Active(ActiveBlock::Inline(worker)) => {
                worker.resources.queue_evts.get(index)
            }
            BlockState::Active(ActiveBlock::Threaded(active)) => {
                active.worker_handle.queue_events().get(index)
            }
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        match &self.state {
            BlockState::Active(ActiveBlock::Inline(worker)) => {
                worker.active_state.interrupt.deref()
            }
            BlockState::Active(ActiveBlock::Threaded(active)) => active.interrupt.deref(),
            BlockState::Configuring(_, _) => panic!("Device is not initialized"),
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn config_as_bytes(&self) -> &[u8] {
        self.config_space.as_slice()
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.metrics.cfg_fails.inc();
        warn!(
            "virtio-block: guest driver attempted to write device config (offset={:#x}, len={:#x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        assert!(!self.is_activated());

        let event_idx = self.has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX));

        let BlockState::Configuring(resources, _) = &mut self.state else {
            unreachable!("inactive device is not configurable");
        };

        for q in &mut resources.queues {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        if event_idx {
            for queue in &mut resources.queues {
                queue.enable_notif_suppression();
            }
        }

        if self.activate_evt.write(1).is_err() {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }

        let BlockState::Configuring(resources, worker_handle) =
            std::mem::replace(&mut self.state, BlockState::Placeholder)
        else {
            unreachable!("state checked before activation");
        };

        let queue_config = resources
            .queues
            .iter()
            .map(|queue| queue.config.clone())
            .collect();

        let is_blocked = self.rate_limiter().clone_blocked_flag();
        let worker = BlockWorker {
            resources,
            rate_limiter: self.rate_limiter.clone(),
            is_blocked,
            active_state: ActiveState {
                mem,
                interrupt: interrupt.clone(),
            },
            metrics: self.metrics.clone(),
        };

        self.state = if let Some(worker_handle) = worker_handle {
            worker_handle.start(worker);
            BlockState::Active(ActiveBlock::Threaded(ThreadedActive {
                worker_handle,
                interrupt,
                queue_config,
            }))
        } else {
            BlockState::Active(ActiveBlock::Inline(worker))
        };
        Ok(())
    }

    fn is_activated(&self) -> bool {
        matches!(&self.state, BlockState::Active(_))
    }

    fn deactivate(&mut self) {
        // `_reset` moves data-path resources back into the configuring state.
    }

    fn _reset(&mut self) -> bool {
        let state = std::mem::replace(&mut self.state, BlockState::Placeholder);
        let (resources, worker_handle) = match state {
            BlockState::Active(ActiveBlock::Threaded(active)) => {
                let Some(resources) = active.worker_handle.reset() else {
                    self.state = BlockState::Active(ActiveBlock::Threaded(active));
                    return false;
                };
                (resources, Some(active.worker_handle))
            }
            BlockState::Active(ActiveBlock::Inline(mut worker)) => {
                if !worker.reset() {
                    self.state = BlockState::Active(ActiveBlock::Inline(worker));
                    return false;
                }
                (worker.resources, None)
            }
            BlockState::Configuring(mut resources, worker_handle) => {
                if let Err(err) = resources.disk.file_engine.drain(true) {
                    error!("Failed to reset block IO engine: {:?}", err);
                    self.state = BlockState::Configuring(resources, worker_handle);
                    return false;
                }
                resources.is_io_engine_throttled = false;
                (resources, worker_handle)
            }
            BlockState::Placeholder => unreachable!("not a runtime state"),
        };

        self.state = BlockState::Configuring(resources, worker_handle);
        true
    }

    fn reset_queues(&mut self) {
        if let BlockState::Configuring(resources, _) = &mut self.state {
            resources.queues.iter_mut().for_each(Queue::reset);
        }
    }

    fn kick(&mut self) {
        match &self.state {
            BlockState::Active(ActiveBlock::Threaded(active)) => active.worker_handle.kick(true),
            BlockState::Active(ActiveBlock::Inline(_)) => self.notify_queue_events(),
            BlockState::Configuring(_, _) => {}
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn mark_queue_memory_dirty(&mut self, mem: &GuestMemoryMmap) -> Result<(), QueueError> {
        match &mut self.state {
            BlockState::Configuring(resources, _) => {
                for queue in &mut resources.queues {
                    queue.initialize(mem)?;
                }
            }
            BlockState::Active(ActiveBlock::Inline(worker)) => {
                for queue in &mut worker.resources.queues {
                    queue.initialize(mem)?;
                }
            }
            BlockState::Active(ActiveBlock::Threaded(active)) => {
                active.worker_handle.mark_queue_memory_dirty()?;
            }
            BlockState::Placeholder => unreachable!("not a runtime state"),
        }
        Ok(())
    }
}

impl Drop for VirtioBlock {
    fn drop(&mut self) {
        let flush_mode = match self.config.cache_type {
            CacheType::Unsafe => FlushMode::Drain,
            CacheType::Writeback => FlushMode::DrainAndFlush,
        };

        match std::mem::replace(&mut self.state, BlockState::Placeholder) {
            BlockState::Active(ActiveBlock::Inline(mut worker)) => match flush_mode {
                FlushMode::Drain => worker.drain(true),
                FlushMode::DrainAndFlush => worker.drain_and_flush(true),
            },
            BlockState::Active(ActiveBlock::Threaded(active)) => {
                active.worker_handle.finish(flush_mode);
            }
            BlockState::Configuring(mut resources, worker_handle) => {
                match flush_mode {
                    FlushMode::Drain => {
                        if let Err(err) = resources.disk.file_engine.drain(true) {
                            error!("Failed to drain ops on drop: {:?}", err);
                        }
                    }
                    FlushMode::DrainAndFlush => {
                        if let Err(err) = resources.disk.file_engine.drain_and_flush(true) {
                            error!("Failed to drain ops and flush block data: {:?}", err);
                        }
                    }
                }
                if let Some(worker_handle) = worker_handle {
                    // a parked worker owns no runtime resources, it just joins the thread
                    worker_handle.finish(FlushMode::Drain);
                }
            }
            BlockState::Placeholder => {}
        };
    }
}

#[cfg(test)]
mod tests {
    use std::fs::metadata;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::thread;
    use std::time::Duration;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::check_metric_after_block;
    use crate::devices::virtio::block::virtio::IO_URING_NUM_ENTRIES;
    use crate::devices::virtio::block::virtio::request::*;
    use crate::devices::virtio::block::virtio::test_utils::{
        default_block, read_blk_req_descriptors, set_queue, set_rate_limiter,
        simulate_async_completion_event, simulate_queue_and_async_completion_events,
        simulate_queue_event,
    };
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
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

            assert_eq!(block.device_type(), VirtioDeviceType::Block);

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
    fn test_config_as_bytes() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let block = default_block(engine);

            let config = block.config_as_bytes();
            // The block's backing file size is 0x1000, so there are 8 (4096/512) sectors.
            let expected_config_space = ConfigSpace { capacity: 8 };
            assert_eq!(config, expected_config_space.as_slice());
        }
    }

    #[test]
    fn test_config_tracks_rate_limiter_updates() {
        let mut block = default_block(FileEngineType::Sync);
        assert!(block.config().rate_limiter.is_some());

        block.update_rate_limiter(BucketUpdate::Disabled, BucketUpdate::Disabled);

        assert_eq!(block.config().rate_limiter, None);
    }

    #[test]
    fn test_virtio_device_config_space_is_read_only() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            // Snapshot the config space before any write attempt.
            let initial_config = block.config_as_bytes().to_vec();

            // A guest write must be rejected: the config space is left unchanged
            // and the attempt is counted under cfg_fails.
            let cfg_fails_before = block.metrics.cfg_fails.count();
            block.write_config(
                0,
                ConfigSpace {
                    capacity: 0x1122334455667788,
                }
                .as_slice(),
            );
            assert_eq!(block.config_as_bytes(), initial_config);
            assert_eq!(block.metrics.cfg_fails.count(), cfg_fails_before + 1);
        }
    }

    #[test]
    fn test_invalid_request() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
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
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
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
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
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
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
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
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
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
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            let empty_data = vec![0; 512];
            let rand_data = vmm_sys_util::rand::rand_alphanumerics(1024)
                .as_bytes()
                .to_vec();

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
                    .disk()
                    .file_engine
                    .file()
                    .seek(SeekFrom::Start(0))
                    .unwrap();
                block
                    .disk()
                    .file_engine
                    .file()
                    .read_exact(&mut buf)
                    .unwrap();
                assert_eq!(buf, empty_data.as_slice());
            }

            // Write from valid address, with an overflowing length.
            {
                let mut block = default_block(engine);

                // Default mem size is 0x10000
                let mem = default_mem();
                let interrupt = default_interrupt();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.activate(mem.clone(), interrupt).unwrap();
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
                    .disk()
                    .file_engine
                    .file()
                    .seek(SeekFrom::End(0))
                    .unwrap();
                block.disk().file_engine.file().set_len(size / 2).unwrap();
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
                    .disk()
                    .file_engine
                    .file()
                    .seek(SeekFrom::End(0))
                    .unwrap();
                block.disk().file_engine.file().set_len(size / 2).unwrap();
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
                    .disk()
                    .file_engine
                    .file()
                    .seek(SeekFrom::Start(512))
                    .unwrap();
                block
                    .disk()
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
                let mut block = default_block(engine);

                // Default mem size is 0x10000
                let mem = default_mem();
                let interrupt = default_interrupt();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.activate(mem.clone(), interrupt).unwrap();
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
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
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
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());
            let blk_metadata = block.disk().file_engine.file().metadata();

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
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, IO_URING_NUM_ENTRIES * 4);
            block.resources_mut().queues[0] = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

            // Run scenario that doesn't trigger FullSq BlockError: Add sq_size flush requests.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.resources().is_io_engine_throttled);
            simulate_async_completion_event(&mut block, true);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES, &vq);

            // Run scenario that triggers FullSqError : Add sq_size + 10 flush requests.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES + 10);
            simulate_queue_event(&mut block, Some(false));
            assert!(block.resources().is_io_engine_throttled);
            // When the async_completion_event is triggered:
            // 1. sq_size requests should be processed processed.
            // 2. is_io_engine_throttled should be set back to false.
            // 3. process_queue() should be called again.
            simulate_async_completion_event(&mut block, true);
            assert!(!block.resources().is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES, &vq);
            // check that process_queue() was called again resulting in the processing of the
            // remaining 10 ops.
            simulate_async_completion_event(&mut block, true);
            assert!(!block.resources().is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES + 10, &vq);
        }

        // FullCQueue BlockError
        {
            let mut block = default_block(FileEngineType::Async);

            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, IO_URING_NUM_ENTRIES * 4);
            block.resources_mut().queues[0] = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

            // Run scenario that triggers FullCqError. Push 2 * IO_URING_NUM_ENTRIES and wait for
            // completion. Then try to push another entry.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.resources().is_io_engine_throttled);
            thread::sleep(Duration::from_millis(150));
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.resources().is_io_engine_throttled);
            thread::sleep(Duration::from_millis(150));

            add_flush_requests_batch(&mut block, &vq, 1);
            simulate_queue_event(&mut block, Some(false));
            assert!(block.resources().is_io_engine_throttled);
            simulate_async_completion_event(&mut block, true);
            assert!(!block.resources().is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES * 2, &vq);
        }
    }

    #[test]
    fn test_prepare_save() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            block.resources_mut().queues[0] = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

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
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Create bandwidth rate limiter that allows only 5120 bytes/s with bucket size of 8
            // bytes.
            let mut rl = RateLimiter::new(512, 0, 100, 0, 0, 0);
            // Use up the budget.
            assert!(rl.consume(512, TokenType::Bytes));

            set_rate_limiter(&mut block, rl);
            block.activate(mem.clone(), interrupt).unwrap();

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
                assert!(block.rate_limiter().is_blocked());
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
                assert!(!block.rate_limiter().is_blocked());
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
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Create ops rate limiter that allows only 10 ops/s with bucket size of 1 ops.
            let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 100);
            // Use up the budget.
            assert!(rl.consume(1, TokenType::Ops));

            set_rate_limiter(&mut block, rl);
            block.activate(mem.clone(), interrupt).unwrap();

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
                assert!(block.rate_limiter().is_blocked());
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
                assert!(block.rate_limiter().is_blocked());
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
                assert!(!block.rate_limiter().is_blocked());
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
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem, interrupt).unwrap();
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

            assert_eq!(block.config().path_on_host, path.to_str().unwrap());
            assert_eq!(
                block.disk().file_engine.file().metadata().unwrap().st_ino(),
                mdata.st_ino()
            );
            assert_eq!(block.disk().image_id, id.as_slice());
        }
    }

    #[test]
    fn test_reset_and_reactivation() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            for threaded in [false, true] {
                let mut block = default_block(engine);
                if threaded {
                    block.spawn_worker(Arc::new(vec![])).unwrap();
                }

                let mem = default_mem();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.set_acked_features(1);
                block.activate(mem.clone(), default_interrupt()).unwrap();

                assert!(block.is_activated());
                assert_eq!(block.is_threaded_active(), threaded);
                assert!(block.reset());
                assert!(!block.is_activated());
                assert_eq!(block.acked_features(), 0);
                assert!(!block.queue_config(0).unwrap().ready);
                let BlockState::Configuring(_, worker_handle) = &block.state else {
                    panic!("reset must leave the block device configuring");
                };
                assert_eq!(worker_handle.is_some(), threaded);

                set_queue(&mut block, 0, vq.create_queue());
                block.activate(mem, default_interrupt()).unwrap();
                assert!(block.is_activated());
                assert_eq!(block.is_threaded_active(), threaded);
            }
        }
    }
}
