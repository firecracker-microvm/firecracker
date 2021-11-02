// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::os::unix::io::AsRawFd;

use event_manager::{EventOps, Events, MutEventSubscriber};
use logger::{debug, error, warn};
use utils::epoll::EventSet;

use super::io::FileEngine;
use crate::virtio::block::device::Block;
use crate::virtio::VirtioDevice;

impl Block {
    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(e) = ops.add(Events::new(&self.queue_evts[0], EventSet::IN)) {
            error!("Failed to register queue event: {}", e);
        }
        if let Err(e) = ops.add(Events::new(&self.rate_limiter, EventSet::IN)) {
            error!("Failed to register ratelimiter event: {}", e);
        }
        if let FileEngine::Async(engine) = self.disk.file_engine() {
            if let Err(e) = ops.add(Events::new(engine.completion_evt(), EventSet::IN)) {
                error!("Failed to register IO engine completion event: {}", e);
            }
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(e) = ops.add(Events::new(&self.activate_evt, EventSet::IN)) {
            error!("Failed to register activate event: {}", e);
        }
    }

    fn process_activate_event(&self, ops: &mut EventOps) {
        debug!("block: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume block activate event: {:?}", e);
        }
        self.register_runtime_events(ops);
        if let Err(e) = ops.remove(Events::new(&self.activate_evt, EventSet::IN)) {
            error!("Failed to un-register activate event: {}", e);
        }
    }
}

impl MutEventSubscriber for Block {
    // Handle an event for queue or rate limiter.
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!(
                "Block: Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if self.is_activated() {
            let queue_evt = self.queue_evts[0].as_raw_fd();
            let rate_limiter_evt = self.rate_limiter.as_raw_fd();
            let activate_fd = self.activate_evt.as_raw_fd();
            let maybe_completion_fd = match self.disk.file_engine() {
                FileEngine::Async(engine) => Some(engine.completion_evt().as_raw_fd()),
                FileEngine::Sync(_) => None,
            };

            // Looks better than C style if/else if/else.
            match source {
                _ if queue_evt == source => self.process_queue_event(),
                _ if rate_limiter_evt == source => self.process_rate_limiter_event(),
                _ if activate_fd == source => self.process_activate_event(ops),
                _ if maybe_completion_fd == Some(source) => self.process_async_completion_event(),
                _ => warn!("Block: Spurious event received: {:?}", source),
            }
        } else {
            warn!(
                "Block: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
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
}

#[cfg(test)]
pub mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::virtio::block::test_utils::{
        default_block, set_queue, simulate_async_completion_event,
    };
    use crate::virtio::queue::tests::*;
    use crate::virtio::test_utils::{default_mem, initialize_virtqueue, VirtQueue};
    use event_manager::{EventManager, SubscriberOps};
    use virtio_gen::virtio_blk::*;
    use vm_memory::{Bytes, GuestAddress};

    #[test]
    fn test_event_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let mut block = default_block();
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        initialize_virtqueue(&vq);

        let block = Arc::new(Mutex::new(block));
        let _id = event_manager.add_subscriber(block.clone());

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        // Push a 'Write' operation.
        {
            mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                .unwrap();
            // Make data read only, 512 bytes in len, and set the actual value to be written.
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(512);
            mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

            // Trigger the queue event.
            block.lock().unwrap().queue_evts[0].write(1).unwrap();
        }

        // EventManager should report no events since block has only registered
        // its activation event so far (even though queue event is pending).
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 0);

        // Now activate the device.
        block.lock().unwrap().activate(mem.clone()).unwrap();
        // Process the activate event.
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 1);

        // Handle the pending queue event through EventManager.
        event_manager
            .run_with_timeout(100)
            .expect("Metrics event timeout or error.");
        // Complete async IO ops if needed
        simulate_async_completion_event(&mut block.lock().unwrap(), true);

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 1);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
    }
}
