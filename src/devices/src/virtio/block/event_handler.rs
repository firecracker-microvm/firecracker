// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::os::unix::io::AsRawFd;

use crate::virtio::block::device::Block;
use polly::event_manager::EventHandler;
use polly::pollable::{Pollable, PollableOp, PollableOpBuilder};

impl EventHandler for Block {
    // Handle an event for queue or rate limiter.
    fn handle_read(&mut self, source: Pollable) -> Vec<PollableOp> {
        let queue = self.queue_evt.as_raw_fd();
        let rate_limiter = self.rate_limiter.as_raw_fd();

        // Looks better than C style if/else if/else.
        match source {
            _ if queue == source => self.process_queue_event(),
            _ if rate_limiter == source => self.process_rate_limiter_event(),
            _ => warn!("Spurious event received: {:?}", source),
        }

        vec![]
    }

    // Returns the rate_limiter and queue event fds.
    fn init(&self) -> Vec<PollableOp> {
        vec![
            PollableOpBuilder::new(self.rate_limiter.as_raw_fd())
                .readable()
                .register(),
            PollableOpBuilder::new(self.queue_evt.as_raw_fd())
                .readable()
                .register(),
        ]
    }
}
