// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use super::{Entropy, RNG_QUEUE};
use crate::devices::virtio::device::VirtioDevice;
use crate::logger::{error, warn};

impl Entropy {
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_ENTROPY_QUEUE: u32 = 1;
    const PROCESS_RATE_LIMITER: u32 = 2;

    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.queue_events()[RNG_QUEUE],
            Self::PROCESS_ENTROPY_QUEUE,
            EventSet::IN,
        )) {
            error!("entropy: Failed to register queue event: {err}");
        }
        if let Err(err) = ops.add(Events::with_data(
            self.rate_limiter(),
            Self::PROCESS_RATE_LIMITER,
            EventSet::IN,
        )) {
            error!("entropy: Failed to register rate-limiter event: {err}");
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            self.activate_event(),
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
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
        if let Err(err) = ops.remove(Events::with_data(
            self.activate_event(),
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
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
        let source = events.data();

        if !event_set.contains(EventSet::IN) {
            warn!("entropy: Received unknown event: {event_set:?} from source {source}");
            return;
        }

        if !self.is_activated() {
            warn!("entropy: The device is not activated yet. Spurious event received: {source}");
            return;
        }

        match source {
            Self::PROCESS_ACTIVATE => self.process_activate_event(ops),
            Self::PROCESS_ENTROPY_QUEUE => self.process_entropy_queue_event(),
            Self::PROCESS_RATE_LIMITER => self.process_rate_limiter_event(),
            _ => {
                warn!("entropy: Unknown event received: {source}");
            }
        }
    }
}
