// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;

use event_manager::{EventOps, Events, MutEventSubscriber};
use log::{error, warn};
use utils::epoll::EventSet;

use super::{Entropy, RNG_QUEUE};
use crate::devices::virtio::VirtioDevice;

impl Entropy {
    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.queue_events()[RNG_QUEUE], EventSet::IN)) {
            error!("entropy: Failed to register queue event: {err}");
        }
        if let Err(err) = ops.add(Events::new(self.rate_limiter(), EventSet::IN)) {
            error!("entropy: Failed to register rate-limiter event: {err}");
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(self.activate_event(), EventSet::IN)) {
            error!("entropy: Failed to register activate event: {err}");
        }
    }

    fn process_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = self.activate_event().read() {
            error!("entropy: Failed to consume activate event: {err}");
        }

        // Register runtime events
        self.register_runtime_events(ops);

        // Remove activate event
        if let Err(err) = ops.remove(Events::new(self.activate_event(), EventSet::IN)) {
            error!("entropy: Failed to un-register activate event: {err}");
        }
    }
}

impl MutEventSubscriber for Entropy {
    fn init(&mut self, ops: &mut event_manager::EventOps) {
        // This function can be called during different points in the device lifetime:
        //  - shortly after device creation,
        //  - on device activation (is-activated already true at this point),
        //  - on device restore from snapshot.
        if self.is_activated() {
            self.register_runtime_events(ops);
        } else {
            self.register_activate_event(ops);
        }
    }

    fn process(&mut self, events: event_manager::Events, ops: &mut event_manager::EventOps) {
        let event_set = events.event_set();
        let source = events.fd();

        if !event_set.contains(EventSet::IN) {
            warn!("entropy: Received unknown event: {event_set:?} from source {source}");
            return;
        }

        if !self.is_activated() {
            warn!("entropy: The device is not activated yet. Spurious event received: {source}");
            return;
        }

        if source == self.queue_events()[RNG_QUEUE].as_raw_fd() {
            self.process_entropy_queue_event()
        } else if source == self.rate_limiter().as_raw_fd() {
            self.process_rate_limiter_event();
        } else if source == self.activate_event().as_raw_fd() {
            self.process_activate_event(ops)
        } else {
            warn!("entropy: Unknown event received: {source}");
        }
    }
}
