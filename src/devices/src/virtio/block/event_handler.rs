// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::device::*;
use polly::event_manager::EventHandler;
use polly::pollable::*;
use std::os::unix::io::AsRawFd;

impl EventHandler for Block {
    // Handle an event for queue or rate limiter.
    fn handle_read(&mut self, source: Pollable) -> Vec<PollableOp> {
        let queue = self.queue_evt.as_raw_fd();
        let rate_limiter = self.rate_limiter.as_raw_fd();
        let source = source.as_raw_fd();

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
            PollableOpBuilder::new(Pollable::from(&self.rate_limiter))
                .readable()
                .register(),
            PollableOpBuilder::new(Pollable::from(&self.queue_evt))
                .readable()
                .register(),
        ]
    }
}
