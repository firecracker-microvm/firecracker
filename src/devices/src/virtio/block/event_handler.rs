// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::os::unix::io::AsRawFd;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::block::device::Block;
use crate::virtio::VirtioDevice;

impl Subscriber for Block {
    // Handle an event for queue or rate limiter.
    fn process(&mut self, event: &EpollEvent, _: &mut EventManager) {
        if !self.is_activated() {
            warn!("The device is not yet activated. Events can not be handled.");
            return;
        }

        let queue_evt = self.queue_evt.as_raw_fd();
        let rate_limiter_evt = self.rate_limiter.as_raw_fd();

        let source = event.fd();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!(
                "Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        // Looks better than C style if/else if/else.
        match source {
            _ if queue_evt == source => self.process_queue_event(),
            _ if rate_limiter_evt == source => self.process_rate_limiter_event(),
            _ => warn!("Spurious event received: {:?}", source),
        }
    }

    // Returns the rate_limiter and queue event fds.
    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![
            EpollEvent::new(EventSet::IN, self.rate_limiter.as_raw_fd() as u64),
            EpollEvent::new(EventSet::IN, self.queue_evt.as_raw_fd() as u64),
        ]
    }
}
