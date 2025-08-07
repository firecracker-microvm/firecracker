// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::mem::MEM_QUEUE;
use crate::devices::virtio::mem::device::VirtioMem;
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use event_manager::{EventManager, SubscriberOps};
    use vmm_sys_util::epoll::EventSet;

    use super::*;
    use crate::devices::virtio::ActivateError;
    use crate::devices::virtio::generated::virtio_mem::VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE;
    use crate::devices::virtio::mem::device::test_utils::default_virtio_mem;
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::vstate::memory::GuestAddress;

    #[test]
    fn test_event_handler_activation() {
        let mut event_manager = EventManager::new().unwrap();
        let mut mem_device = default_virtio_mem();
        let mem = default_mem();
        let interrupt = default_interrupt();

        // Set up queue
        let virtq = VirtQueue::new(GuestAddress(0), &mem, 16);
        mem_device.queues_mut()[MEM_QUEUE] = virtq.create_queue();

        let mem_device = Arc::new(Mutex::new(mem_device));
        let _id = event_manager.add_subscriber(mem_device.clone());

        // Device should register activate event when inactive
        assert!(!mem_device.lock().unwrap().is_activated());

        // Device should prevent activation before features are acked
        let err = mem_device
            .lock()
            .unwrap()
            .activate(mem.clone(), interrupt.clone())
            .unwrap_err();

        assert!(matches!(err, ActivateError::RequiredFeatureNotAcked(_)));

        // Ack the feature and activate the device
        mem_device
            .lock()
            .unwrap()
            .set_acked_features(1 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE);

        mem_device.lock().unwrap().activate(mem, interrupt).unwrap();

        // Process activation event
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 1);
        assert!(mem_device.lock().unwrap().is_activated());
    }

    #[test]
    fn test_process_mem_queue_event() {
        let mut event_manager = EventManager::new().unwrap();
        let mut mem_device = default_virtio_mem();
        let mem = default_mem();
        let interrupt = default_interrupt();

        // Set up queue
        let virtq = VirtQueue::new(GuestAddress(0), &mem, 16);
        mem_device.queues_mut()[MEM_QUEUE] = virtq.create_queue();
        mem_device.set_acked_features(mem_device.avail_features());

        let mem_device = Arc::new(Mutex::new(mem_device));
        let _id = event_manager.add_subscriber(mem_device.clone());

        // Activate device first
        mem_device.lock().unwrap().activate(mem, interrupt).unwrap();
        event_manager.run_with_timeout(50).unwrap(); // Process activation

        // Trigger queue event
        mem_device.lock().unwrap().queue_events()[MEM_QUEUE]
            .write(1)
            .unwrap();

        // Process queue event
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 1);
    }

    #[test]
    fn test_spurious_event_before_activation() {
        let mut event_manager = EventManager::new().unwrap();
        let mem_device = default_virtio_mem();
        let mem_device = Arc::new(Mutex::new(mem_device));
        let _id = event_manager.add_subscriber(mem_device.clone());

        // Try to trigger queue event before activation
        mem_device.lock().unwrap().queue_events()[MEM_QUEUE]
            .write(1)
            .unwrap();

        // Should not process queue events before activation
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 0);
    }
}
