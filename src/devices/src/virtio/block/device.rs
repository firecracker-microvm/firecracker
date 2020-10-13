// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use logger::{error, warn, Metric, METRICS};
use rate_limiter::{RateLimiter, TokenType};
use utils::eventfd::EventFd;
use virtio_gen::virtio_blk::*;
use vm_memory::{Bytes, GuestMemoryMmap};

use super::{
    super::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_BLOCK, VIRTIO_MMIO_INT_VRING},
    request::*,
    Error, CONFIG_SPACE_SIZE, QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE,
};

use crate::Error as DeviceError;

/// Helper object for setting up all `Block` fields derived from its backing file.
pub(crate) struct DiskProperties {
    file_path: String,
    file: File,
    nsectors: u64,
    image_id: Vec<u8>,
}

impl DiskProperties {
    pub fn new(disk_image_path: String, is_disk_read_only: bool) -> io::Result<Self> {
        let mut disk_image = OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))?;
        let disk_size = disk_image.seek(SeekFrom::End(0))? as u64;

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
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: Self::build_disk_image_id(&disk_image),
            file_path: disk_image_path,
            file: disk_image,
        })
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
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

    fn build_disk_image_id(disk_file: &File) -> Vec<u8> {
        let mut default_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(m) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = m.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
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
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) interrupt_evt: EventFd,
    pub(crate) queue_evts: [EventFd; 1],
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) id: String,
    pub(crate) partuuid: Option<String>,
    pub(crate) root_device: bool,
    pub(crate) rate_limiter: RateLimiter,
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(
        id: String,
        partuuid: Option<String>,
        disk_image_path: String,
        is_disk_read_only: bool,
        is_disk_root: bool,
        rate_limiter: RateLimiter,
    ) -> io::Result<Block> {
        let disk_properties = DiskProperties::new(disk_image_path, is_disk_read_only)?;

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_BLK_F_FLUSH);

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK)?];

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
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK)?,
            queue_evts,
            queues,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK)?,
        })
    }

    pub(crate) fn process_queue_event(&mut self) {
        METRICS.block.queue_event_count.inc();
        if let Err(e) = self.queue_evts[0].read() {
            error!("Failed to get queue event: {:?}", e);
            METRICS.block.event_fails.inc();
        } else if self.rate_limiter.is_blocked() {
            METRICS.block.rate_limiter_throttled_events.inc();
        } else if self.process_queue(0) {
            let _ = self.signal_used_queue();
        }
    }

    pub(crate) fn process_rate_limiter_event(&mut self) {
        METRICS.block.rate_limiter_event_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        if self.rate_limiter.event_handler().is_ok() && self.process_queue(0) {
            let _ = self.signal_used_queue();
        }
    }

    pub fn process_queue(&mut self, queue_index: usize) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        let queue = &mut self.queues[queue_index];
        let mut used_any = false;
        while let Some(head) = queue.pop(mem) {
            let len;
            match Request::parse(&head, mem) {
                Ok(request) => {
                    // If limiter.consume() fails it means there is no more TokenType::Ops
                    // budget and rate limiting is in effect.
                    if !self.rate_limiter.consume(1, TokenType::Ops) {
                        // Stop processing the queue and return this descriptor chain to the
                        // avail ring, for later processing.
                        queue.undo_pop();
                        METRICS.block.rate_limiter_throttled_events.inc();
                        break;
                    }
                    // Exercise the rate limiter only if this request is of data transfer type.
                    if request.request_type == RequestType::In
                        || request.request_type == RequestType::Out
                    {
                        // If limiter.consume() fails it means there is no more TokenType::Bytes
                        // budget and rate limiting is in effect.
                        if !self
                            .rate_limiter
                            .consume(u64::from(request.data_len), TokenType::Bytes)
                        {
                            // Revert the OPS consume().
                            self.rate_limiter.manual_replenish(1, TokenType::Ops);
                            // Stop processing the queue and return this descriptor chain to the
                            // avail ring, for later processing.
                            queue.undo_pop();
                            METRICS.block.rate_limiter_throttled_events.inc();
                            break;
                        }
                    }
                    let status = match request.execute(&mut self.disk, mem) {
                        Ok(l) => {
                            len = l;
                            VIRTIO_BLK_S_OK
                        }
                        Err(e) => {
                            error!("Failed to execute request: {:?}", e);
                            METRICS.block.invalid_reqs_count.inc();
                            len = 1; // We need at least 1 byte for the status.
                            e.status()
                        }
                    };
                    // We use unwrap because the request parsing process already checked that the
                    // status_addr was valid.
                    mem.write_obj(status, request.status_addr).unwrap();
                }
                Err(e) => {
                    error!("Failed to parse available descriptor chain: {:?}", e);
                    METRICS.block.execute_fails.inc();
                    len = 0;
                }
            }

            queue.add_used(mem, head.index, len).unwrap_or_else(|e| {
                error!(
                    "Failed to add available descriptor head {}: {}",
                    head.index, e
                )
            });
            used_any = true;
        }

        if !used_any {
            METRICS.block.no_avail_buffer.inc();
        }

        used_any
    }

    pub(crate) fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);

        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            METRICS.block.event_fails.inc();
            DeviceError::FailedSignalingUsedQueue(e)
        })?;
        Ok(())
    }

    /// Update the backing file and the config space of the block device.
    pub fn update_disk_image(&mut self, disk_image_path: String) -> io::Result<()> {
        let disk_properties = DiskProperties::new(disk_image_path, self.is_read_only())?;
        self.disk = disk_properties;
        self.config_space = self.disk.virtio_block_config_space();
        METRICS.block.update_count.inc();
        Ok(())
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
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
        &self.interrupt_evt
    }

    /// Returns the current device interrupt status.
    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
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
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            error!("Block: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::metadata;
    use std::os::unix::io::AsRawFd;
    use std::thread;
    use std::time::Duration;
    use std::u32;

    use super::*;
    use crate::virtio::queue::tests::*;
    use polly::event_manager::{EventManager, Subscriber};
    use utils::epoll::{EpollEvent, EventSet};
    use utils::tempfile::TempFile;
    use vm_memory::GuestAddress;

    use crate::check_metric_after_block;
    use crate::virtio::block::test_utils::{
        default_block, invoke_handler_for_queue_event, set_queue, set_rate_limiter,
    };
    use crate::virtio::test_utils::{default_mem, initialize_virtqueue, VirtQueue};

    #[test]
    fn test_disk_backing_file_helper() {
        let num_sectors = 2;
        let f = TempFile::new().unwrap();
        let size = SECTOR_SIZE * num_sectors;
        f.as_file().set_len(size).unwrap();

        let disk_properties =
            DiskProperties::new(String::from(f.as_path().to_str().unwrap()), true).unwrap();

        assert_eq!(size, SECTOR_SIZE * num_sectors);
        assert_eq!(disk_properties.nsectors, num_sectors);
        let cfg = disk_properties.virtio_block_config_space();
        assert_eq!(cfg.len(), CONFIG_SPACE_SIZE);
        for (i, byte) in cfg.iter().enumerate() {
            assert_eq!(*byte, (num_sectors >> (8 * i)) as u8);
        }
        // Testing `backing_file.virtio_block_disk_image_id()` implies
        // duplicating that logic in tests, so skipping it.

        assert!(DiskProperties::new("invalid-disk-path".to_string(), true).is_err());
    }

    #[test]
    fn test_virtio_features() {
        let mut block = default_block();

        assert_eq!(block.device_type(), TYPE_BLOCK);

        let features: u64 = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_BLK_F_FLUSH);

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
        let block = default_block();

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
        let mut block = default_block();

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
        let mut block = default_block();
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

        invoke_handler_for_queue_event(&mut block);

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 0);
    }

    #[test]
    fn test_request_execute_failures() {
        let mut block = default_block();
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        {
            // First descriptor no longer writable.
            vq.dtable[0].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);

            // Generate a seek execute error caused by a very large sector number.
            let request_header = RequestHeader::new(VIRTIO_BLK_T_OUT, 0x000f_ffff_ffff);
            mem.write_obj::<RequestHeader>(request_header, request_type_addr)
                .unwrap();

            invoke_handler_for_queue_event(&mut block);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(
                mem.read_obj::<u32>(status_addr).unwrap(),
                VIRTIO_BLK_S_IOERR
            );
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

            invoke_handler_for_queue_event(&mut block);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(
                mem.read_obj::<u32>(status_addr).unwrap(),
                VIRTIO_BLK_S_IOERR
            );
        }
    }

    #[test]
    fn test_unsupported_request_type() {
        let mut block = default_block();
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

        invoke_handler_for_queue_event(&mut block);

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 1);
        assert_eq!(
            mem.read_obj::<u32>(status_addr).unwrap(),
            VIRTIO_BLK_S_UNSUPP
        );
    }

    #[test]
    fn test_read_write() {
        let mut block = default_block();
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        // Write.
        {
            mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                .unwrap();
            // Make data read only, 8 bytes in len, and set the actual value to be written.
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(8);
            mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

            check_metric_after_block!(
                &METRICS.block.write_count,
                1,
                invoke_handler_for_queue_event(&mut block)
            );

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
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

            check_metric_after_block!(
                &METRICS.block.read_count,
                1,
                invoke_handler_for_queue_event(&mut block)
            );

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, vq.dtable[1].len.get());
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            assert_eq!(mem.read_obj::<u64>(data_addr).unwrap(), 123_456_789);
        }
    }

    #[test]
    fn test_flush() {
        let mut block = default_block();
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

            invoke_handler_for_queue_event(&mut block);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }

        // Flush completes successfully even with a data descriptor.
        {
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());
            vq.dtable[0].next.set(1);

            mem.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, request_type_addr)
                .unwrap();

            invoke_handler_for_queue_event(&mut block);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_get_device_id() {
        let mut block = default_block();
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());
        let blk_metadata = block.disk.file.metadata();

        // Test that the driver receives the correct device id.
        {
            vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES);

            mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
                .unwrap();

            invoke_handler_for_queue_event(&mut block);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
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

        // Test that a device ID request will fail, if it fails to provide enough buffer space.
        {
            vq.used.idx.set(0);
            set_queue(&mut block, 0, vq.create_queue());
            vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES - 1);

            mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
                .unwrap();

            invoke_handler_for_queue_event(&mut block);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(
                mem.read_obj::<u32>(status_addr).unwrap(),
                VIRTIO_BLK_S_IOERR
            );
        }
    }

    #[test]
    fn test_bandwidth_rate_limiter() {
        let mut block = default_block();
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        let mut event_manager = EventManager::new().unwrap();
        let queue_evt = EpollEvent::new(EventSet::IN, block.queue_evts[0].as_raw_fd() as u64);

        // Create bandwidth rate limiter that allows only 80 bytes/s with bucket size of 8 bytes.
        let mut rl = RateLimiter::new(8, 0, 100, 0, 0, 0).unwrap();
        // Use up the budget.
        assert!(rl.consume(8, TokenType::Bytes));

        set_rate_limiter(&mut block, rl);
        let rate_limiter_evt = EpollEvent::new(EventSet::IN, block.rate_limiter.as_raw_fd() as u64);

        mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
            .unwrap();
        // Make data read only, 8 bytes in len, and set the actual value to be written
        vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
        vq.dtable[1].len.set(8);
        mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

        // Following write procedure should fail because of bandwidth rate limiting.
        {
            // Trigger the attempt to write.
            block.queue_evts[0].write(1).unwrap();
            check_metric_after_block!(
                &METRICS.block.rate_limiter_throttled_events,
                1,
                block.process(&queue_evt, &mut event_manager)
            );

            // Assert that limiter is blocked.
            assert!(block.rate_limiter.is_blocked());
            // Assert that no operation actually completed (limiter blocked it).
            assert!(block.interrupt_evt.read().is_err());
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
                block.process(&rate_limiter_evt, &mut event_manager)
            );
            // Validate the rate_limiter is no longer blocked.
            assert!(!block.rate_limiter.is_blocked());

            // Make sure the virtio queue operation completed this time.
            assert_eq!(block.interrupt_evt.read().unwrap(), 1);

            // Make sure the data queue advanced.
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_ops_rate_limiter() {
        let mut block = default_block();
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone()).unwrap();
        initialize_virtqueue(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        let mut event_manager = EventManager::new().unwrap();
        let queue_evt = EpollEvent::new(EventSet::IN, block.queue_evts[0].as_raw_fd() as u64);

        // Create ops rate limiter that allows only 10 ops/s with bucket size of 1 ops.
        let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 100).unwrap();
        // Use up the budget.
        assert!(rl.consume(1, TokenType::Ops));

        set_rate_limiter(&mut block, rl);
        let rate_limiter_evt = EpollEvent::new(EventSet::IN, block.rate_limiter.as_raw_fd() as u64);

        mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
            .unwrap();
        // Make data read only, 8 bytes in len, and set the actual value to be written.
        vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
        vq.dtable[1].len.set(8);
        mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

        // Following write procedure should fail because of ops rate limiting.
        {
            // Trigger the attempt to write.
            block.queue_evts[0].write(1).unwrap();
            check_metric_after_block!(
                &METRICS.block.rate_limiter_throttled_events,
                1,
                block.process(&queue_evt, &mut event_manager)
            );

            // Assert that limiter is blocked.
            assert!(block.rate_limiter.is_blocked());
            // Assert that no operation actually completed (limiter blocked it).
            assert!(block.interrupt_evt.read().is_err());
            // Make sure the data is still queued for processing.
            assert_eq!(vq.used.idx.get(), 0);
        }

        // Do a second write that still fails but this time on the fast path.
        {
            // Trigger the attempt to write.
            block.queue_evts[0].write(1).unwrap();
            check_metric_after_block!(
                &METRICS.block.rate_limiter_throttled_events,
                1,
                block.process(&queue_evt, &mut event_manager)
            );

            // Assert that limiter is blocked.
            assert!(block.rate_limiter.is_blocked());
            // Assert that no operation actually completed (limiter blocked it).
            assert!(block.interrupt_evt.read().is_err());
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
                block.process(&rate_limiter_evt, &mut event_manager)
            );
            // Validate the rate_limiter is no longer blocked.
            assert!(!block.rate_limiter.is_blocked());
            // Make sure the virtio queue operation completed this time.
            assert_eq!(block.interrupt_evt.read().unwrap(), 1);

            // Make sure the data queue advanced.
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_update_disk_image() {
        let mut block = default_block();
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

        assert_eq!(block.disk.file.metadata().unwrap().st_ino(), mdata.st_ino());
        assert_eq!(block.disk.image_id, id);
    }
}
