// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc(hidden)]

#[cfg(test)]
use std::thread;
#[cfg(test)]
use std::time::Duration;

use utils::tempfile::TempFile;

use super::device::VirtioBlockConfig;
use super::RequestHeader;
use crate::devices::virtio::block::virtio::device::FileEngineType;
#[cfg(test)]
use crate::devices::virtio::block::virtio::io::FileEngine;
use crate::devices::virtio::block::virtio::{CacheType, VirtioBlock};
#[cfg(test)]
use crate::devices::virtio::device::IrqType;
use crate::devices::virtio::queue::{Queue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::devices::virtio::test_utils::{VirtQueue, VirtqDesc};
use crate::rate_limiter::RateLimiter;
use crate::vmm_config::{RateLimiterConfig, TokenBucketConfig};
use crate::vstate::memory::{Bytes, GuestAddress};

/// Create a default Block instance to be used in tests.
pub fn default_block(file_engine_type: FileEngineType) -> VirtioBlock {
    // Create backing file.
    let f = TempFile::new().unwrap();
    f.as_file().set_len(0x1000).unwrap();

    default_block_with_path(f.as_path().to_str().unwrap().to_string(), file_engine_type)
}

/// Create a default Block instance using file at the specified path to be used in tests.
pub fn default_block_with_path(path: String, file_engine_type: FileEngineType) -> VirtioBlock {
    let config = VirtioBlockConfig {
        drive_id: "test".to_string(),
        path_on_host: path,
        is_root_device: false,
        partuuid: None,
        is_read_only: false,
        cache_type: CacheType::Unsafe,
        // Rate limiting is enabled but with a high operation rate (10 million ops/s).
        rate_limiter: Some(RateLimiterConfig {
            bandwidth: Some(TokenBucketConfig {
                size: 0,
                one_time_burst: Some(0),
                refill_time: 0,
            }),
            ops: Some(TokenBucketConfig {
                size: 100_000,
                one_time_burst: Some(0),
                refill_time: 10,
            }),
        }),
        file_engine_type,
    };

    // The default block device is read-write and non-root.
    VirtioBlock::new(config).unwrap()
}

pub fn set_queue(blk: &mut VirtioBlock, idx: usize, q: Queue) {
    blk.queues[idx] = q;
}

pub fn set_rate_limiter(blk: &mut VirtioBlock, rl: RateLimiter) {
    blk.rate_limiter = rl;
}

pub fn rate_limiter(blk: &mut VirtioBlock) -> &RateLimiter {
    &blk.rate_limiter
}

#[cfg(test)]
pub fn simulate_queue_event(b: &mut VirtioBlock, maybe_expected_irq: Option<bool>) {
    // Trigger the queue event.
    b.queue_evts[0].write(1).unwrap();
    // Handle event.
    b.process_queue_event();
    // Validate the queue operation finished successfully.
    if let Some(expected_irq) = maybe_expected_irq {
        assert_eq!(b.irq_trigger.has_pending_irq(IrqType::Vring), expected_irq);
    }
}

#[cfg(test)]
pub fn simulate_async_completion_event(b: &mut VirtioBlock, expected_irq: bool) {
    if let FileEngine::Async(ref mut engine) = b.disk.file_engine {
        // Wait for all the async operations to complete.
        engine.drain(false).unwrap();
        // Wait for the async completion event to be sent.
        thread::sleep(Duration::from_millis(150));
        // Handle event.
        b.process_async_completion_event();
    }

    // Validate if there are pending IRQs.
    assert_eq!(b.irq_trigger.has_pending_irq(IrqType::Vring), expected_irq);
}

#[cfg(test)]
pub fn simulate_queue_and_async_completion_events(b: &mut VirtioBlock, expected_irq: bool) {
    match b.disk.file_engine {
        FileEngine::Async(_) => {
            simulate_queue_event(b, None);
            simulate_async_completion_event(b, expected_irq);
        }
        FileEngine::Sync(_) => {
            simulate_queue_event(b, Some(expected_irq));
        }
    }
}

/// Structure encapsulating the virtq descriptors of a single request to the block device
#[derive(Debug)]
pub struct RequestDescriptorChain<'a, 'b> {
    pub driver_queue: &'b VirtQueue<'a>,

    pub header_desc: &'b VirtqDesc<'a>,
    pub data_desc: &'b VirtqDesc<'a>,
    pub status_desc: &'b VirtqDesc<'a>,
}

impl<'a, 'b> RequestDescriptorChain<'a, 'b> {
    /// Creates a new [`RequestDescriptor´] chain in the given [`VirtQueue`]
    ///
    /// The header, data and status descriptors are put into the first three indices in
    /// the queue's descriptor table. They point to address 0x1000, 0x2000 and 0x3000 in guest
    /// memory, respectively, and each have their `len` set to 0x1000.
    ///
    /// The data descriptor is initialized to be write_only
    pub fn new(vq: &'b VirtQueue<'a>) -> Self {
        read_blk_req_descriptors(vq);

        RequestDescriptorChain {
            driver_queue: vq,
            header_desc: &vq.dtable[0],
            data_desc: &vq.dtable[1],
            status_desc: &vq.dtable[2],
        }
    }

    pub fn header(&self) -> RequestHeader {
        self.header_desc
            .memory()
            .read_obj(GuestAddress(self.header_desc.addr.get()))
            .unwrap()
    }

    pub fn set_header(&self, header: RequestHeader) {
        self.header_desc
            .memory()
            .write_obj(header, GuestAddress(self.header_desc.addr.get()))
            .unwrap()
    }
}

/// Puts a descriptor chain of length three into the given [`VirtQueue`].
///
/// This chain follows the skeleton of a block device request, e.g. the first
/// descriptor offers space for the header (readonly), the second descriptor offers space
/// for the data (set to writeonly, if you want a write request, update to readonly),
/// and the last descriptor for the device-written status field (writeonly).
///
/// The head of the chain is made available as the first descriptor to be processed, by
/// setting avail_idx to 1.
pub fn read_blk_req_descriptors(vq: &VirtQueue) {
    let request_type_desc: u16 = 0;
    let data_desc: u16 = 1;
    let status_desc: u16 = 2;

    let request_addr: u64 = 0x1000;
    let data_addr: u64 = 0x2000;
    let status_addr: u64 = 0x3000;
    let len = 0x1000;

    // Set the request type descriptor.
    vq.avail.ring[request_type_desc as usize].set(request_type_desc);
    vq.dtable[request_type_desc as usize].set(request_addr, len, VIRTQ_DESC_F_NEXT, data_desc);

    // Set the data descriptor.
    vq.avail.ring[data_desc as usize].set(data_desc);
    vq.dtable[data_desc as usize].set(
        data_addr,
        len,
        VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
        status_desc,
    );

    // Set the status descriptor.
    vq.avail.ring[status_desc as usize].set(status_desc);
    vq.dtable[status_desc as usize].set(status_addr, len, VIRTQ_DESC_F_WRITE, status_desc + 1);

    // Mark the next available descriptor.
    vq.avail.idx.set(1);
}
