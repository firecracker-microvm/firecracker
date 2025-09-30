// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use event_manager::{EventOps, EventSet, Events, MutEventSubscriber};
use log::{error, warn};

use super::device::Pmem;
use crate::devices::virtio::device::VirtioDevice;

impl Pmem {
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_PMEM_QUEUE: u32 = 1;

    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.queue_events[0],
            Self::PROCESS_PMEM_QUEUE,
            EventSet::IN,
        )) {
            error!("pmem: Failed to register queue event: {err}");
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.activate_event,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("pmem: Failed to register activate event: {err}");
        }
    }

    fn process_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = self.activate_event.read() {
            error!("pmem: Failed to consume activate event: {err}");
        }

        // Register runtime events
        self.register_runtime_events(ops);

        // Remove activate event
        if let Err(err) = ops.remove(Events::with_data(
            &self.activate_event,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("pmem: Failed to unregister activate event: {err}");
        }
    }
}

impl MutEventSubscriber for Pmem {
    fn init(&mut self, ops: &mut EventOps) {
        if self.is_activated() {
            self.register_runtime_events(ops)
        } else {
            self.register_activate_event(ops)
        }
    }

    fn process(&mut self, events: Events, ops: &mut EventOps) {
        let event_set = events.event_set();
        let source = events.data();

        if !event_set.contains(EventSet::IN) {
            warn!("pmem: Received unknown event: {event_set:#?} from source {source}");
            return;
        }

        if !self.is_activated() {
            warn!("pmem: The device is not activated yet. Spurious event received from {source}");
            return;
        }

        match source {
            Self::PROCESS_ACTIVATE => self.process_activate_event(ops),
            Self::PROCESS_PMEM_QUEUE => self.process_queue(),
            _ => {
                warn!("pmem: Unknown event received: {source}");
            }
        }
    }
}
