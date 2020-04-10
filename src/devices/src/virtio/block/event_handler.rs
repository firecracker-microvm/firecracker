// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::os::unix::io::AsRawFd;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::block::device::Block;
use crate::virtio::VirtioDevice;

impl Block {
    fn process_activate_event(&self, event_manager: &mut EventManager) {
        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = event_manager
            .subscriber(self.activate_evt.as_raw_fd())
            .unwrap();

        event_manager
            .register(
                self.queue_evts[0].as_raw_fd(),
                EpollEvent::new(EventSet::IN, self.queue_evts[0].as_raw_fd() as u64),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register block queue with event manager: {:?}", e);
            });

        event_manager
            .register(
                self.rate_limiter.as_raw_fd(),
                EpollEvent::new(EventSet::IN, self.rate_limiter.as_raw_fd() as u64),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!(
                    "Failed to register block rate limiter with event manager: {:?}",
                    e
                );
            });

        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!("Failed to unregister block activate evt: {:?}", e);
            })
    }
}

impl Subscriber for Block {
    // Handle an event for queue or rate limiter.
    fn process(&mut self, event: &EpollEvent, evmgr: &mut EventManager) {
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

            // Looks better than C style if/else if/else.
            match source {
                _ if queue_evt == source => self.process_queue_event(),
                _ if rate_limiter_evt == source => self.process_rate_limiter_event(),
                _ if activate_fd == source => self.process_activate_event(evmgr),
                _ => warn!("Block: Spurious event received: {:?}", source),
            }
        } else {
            warn!(
                "Block: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.activate_evt.as_raw_fd() as u64,
        )]
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::virtio::block::device::tests::*;
    use crate::virtio::queue::tests::*;
    use virtio_gen::virtio_blk::*;
    use vm_memory::{Bytes, GuestAddress};

    #[test]
    fn test_event_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let mut block = default_block();
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        block.set_queue(0, vq.create_queue());
        initialize_virtqueue(&vq);

        let block = Arc::new(Mutex::new(block));
        event_manager.add_subscriber(block.clone()).unwrap();

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        // Push a 'Write' operation.
        {
            mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                .unwrap();
            // Make data read only, 8 bytes in len, and set the actual value to be written.
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(8);
            mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

            // Trigger the queue event.
            block.lock().unwrap().queue_evts[0].write(1).unwrap();
        }

        // EventManager should report no events since block has only registered
        // its activation event so far (even though queue event is pending).
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 0);

        // Manually force a queue event and check it's ignored pre-activation.
        {
            let mut b = block.lock().unwrap();
            let raw_q_evt = b.queue_evts[0].as_raw_fd() as u64;
            // Artificially push event.
            b.process(
                &EpollEvent::new(EventSet::IN, raw_q_evt),
                &mut event_manager,
            );
            // Validate there was no queue operation.
            assert_eq!(
                b.interrupt_evt().read().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(vq.used.idx.get(), 0);
        }

        // Now activate the device.
        block.lock().unwrap().activate(mem.clone()).unwrap();
        // Process the activate event.
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 1);

        // Handle the pending queue event through EventManager.
        event_manager
            .run_with_timeout(100)
            .expect("Metrics event timeout or error.");
        // Validate the queue operation finished successfully.
        assert_eq!(block.lock().unwrap().interrupt_evt().read().unwrap(), 1);

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 0);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
    }
}
