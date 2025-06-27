// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use super::{MEM_QUEUE, VirtioMem};
use crate::devices::virtio::device::VirtioDevice;
use crate::logger::{error, warn};

impl VirtioMem {
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_MEM_QUEUE: u32 = 1;

    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.queue_events()[MEM_QUEUE],
            Self::PROCESS_MEM_QUEUE,
            EventSet::IN,
        )) {
            error!("virtio-mem: Failed to register queue event: {err}");
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            self.activate_event(),
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("virtio-mem: Failed to register activate event: {err}");
        }
    }

    fn process_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = self.activate_event().read() {
            error!("virtio-mem: Failed to consume activate event: {err}");
        }

        // Register runtime events
        self.register_runtime_events(ops);

        // Remove activate event
        if let Err(err) = ops.remove(Events::with_data(
            self.activate_event(),
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("virtio-mem: Failed to un-register activate event: {err}");
        }
    }
}

impl MutEventSubscriber for VirtioMem {
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
            warn!("virtio-mem: Received unknown event: {event_set:?} from source {source}");
            return;
        }

        if !self.is_activated() {
            warn!("virtio-mem: The device is not activated yet. Spurious event received: {source}");
            return;
        }

        match source {
            Self::PROCESS_ACTIVATE => self.process_activate_event(ops),
            Self::PROCESS_MEM_QUEUE => self.process_mem_queue_event(),

            _ => {
                warn!("virtio-mem: Unknown event received: {source}");
            }
        }
    }
}
