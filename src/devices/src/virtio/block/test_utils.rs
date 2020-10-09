// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;

use crate::virtio::{Block, Queue};
use polly::event_manager::{EventManager, Subscriber};
use rate_limiter::RateLimiter;
use utils::epoll::{EpollEvent, EventSet};
use utils::tempfile::TempFile;

/// Create a default Block instance to be used in tests.
pub fn default_block() -> Block {
    // Create backing file.
    let f = TempFile::new().unwrap();
    f.as_file().set_len(0x1000).unwrap();

    default_block_with_path(f.as_path().to_str().unwrap().to_string())
}

/// Create a default Block instance using file at the specified path to be used in tests.
pub fn default_block_with_path(path: String) -> Block {
    // Rate limiting is enabled but with a high operation rate (10 million ops/s).
    let rate_limiter = RateLimiter::new(0, 0, 0, 100_000, 0, 10).unwrap();

    let id = "test".to_string();
    // The default block device is read-write and non-root.
    Block::new(id, None, path, false, false, rate_limiter).unwrap()
}

pub fn invoke_handler_for_queue_event(b: &mut Block) {
    // Trigger the queue event.
    b.queue_evts[0].write(1).unwrap();
    // Handle event.
    b.process(
        &EpollEvent::new(EventSet::IN, b.queue_evts[0].as_raw_fd() as u64),
        &mut EventManager::new().unwrap(),
    );
    // Validate the queue operation finished successfully.
    assert_eq!(b.interrupt_evt.read().unwrap(), 1);
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
