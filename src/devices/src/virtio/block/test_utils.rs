// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc(hidden)]

#[cfg(test)]
use std::thread;
#[cfg(test)]
use std::time::Duration;

use crate::virtio::block::device::FileEngineType;
#[cfg(test)]
use crate::virtio::block::io::FileEngine;
#[cfg(test)]
use crate::virtio::IrqType;
use crate::virtio::{Block, CacheType, Queue};
use rate_limiter::RateLimiter;
use utils::kernel_version::{min_kernel_version_for_io_uring, KernelVersion};
use utils::tempfile::TempFile;

/// Create a default Block instance to be used in tests.
pub fn default_block(file_engine_type: FileEngineType) -> Block {
    // Create backing file.
    let f = TempFile::new().unwrap();
    f.as_file().set_len(0x1000).unwrap();

    default_block_with_path(f.as_path().to_str().unwrap().to_string(), file_engine_type)
}

/// Return the Async FileEngineType if supported by the host, otherwise default to Sync.
pub fn default_engine_type_for_kv() -> FileEngineType {
    if KernelVersion::get().unwrap() >= min_kernel_version_for_io_uring() {
        FileEngineType::Async
    } else {
        FileEngineType::Sync
    }
}

/// Create a default Block instance using file at the specified path to be used in tests.
pub fn default_block_with_path(path: String, file_engine_type: FileEngineType) -> Block {
    // Rate limiting is enabled but with a high operation rate (10 million ops/s).
    let rate_limiter = RateLimiter::new(0, 0, 0, 100_000, 0, 10).unwrap();

    let id = "test".to_string();
    // The default block device is read-write and non-root.
    Block::new(
        id,
        None,
        CacheType::Unsafe,
        path,
        false,
        false,
        rate_limiter,
        file_engine_type,
    )
    .unwrap()
}

pub fn set_queue(blk: &mut Block, idx: usize, q: Queue) {
    blk.queues[idx] = q;
}

pub fn set_rate_limiter(blk: &mut Block, rl: RateLimiter) {
    blk.rate_limiter = rl;
}

pub fn rate_limiter(blk: &mut Block) -> &RateLimiter {
    &blk.rate_limiter
}

#[cfg(test)]
pub fn simulate_queue_event(b: &mut Block, maybe_expected_irq: Option<bool>) {
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
pub fn simulate_async_completion_event(b: &mut Block, expected_irq: bool) {
    if let FileEngine::Async(engine) = b.disk.file_engine_mut() {
        // Wait for all the async operations to complete.
        engine.drain_submission_queue().unwrap();
        // Wait for the async completion event to be sent.
        thread::sleep(Duration::from_millis(150));
        // Handle event.
        b.process_async_completion_event();
    }

    // Validate if there are pending IRQs.
    assert_eq!(b.irq_trigger.has_pending_irq(IrqType::Vring), expected_irq);
}

#[cfg(test)]
pub fn simulate_queue_and_async_completion_events(b: &mut Block, expected_irq: bool) {
    match b.disk.file_engine_mut() {
        FileEngine::Async(_) => {
            simulate_queue_event(b, None);
            simulate_async_completion_event(b, expected_irq);
        }
        FileEngine::Sync(_) => {
            simulate_queue_event(b, Some(expected_irq));
        }
    }
}
