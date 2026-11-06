// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use super::io::FileEngine;
use crate::devices::virtio::block::virtio::device::{BlockRuntimeState, VirtioBlock};
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::worker::{
    INLINE_WORKER_TOKEN_BASE, QueueGroupWorker, register_inline_events,
};
use crate::logger::{error, warn};

impl VirtioBlock {
    // The data path's own events (queue, IO engine completion) are the inline worker's,
    // registered from its event list at INLINE_WORKER_TOKEN_BASE and up.
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_RATE_LIMITER: u32 = 1;

    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let BlockRuntimeState::Inline(worker) = &self.state {
            register_inline_events(ops, worker.events());
        }
    }

    fn register_rate_limiter_event(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &*self.rate_limiter.lock(),
            Self::PROCESS_RATE_LIMITER,
            EventSet::IN,
        )) {
            error!("Failed to register rate limiter event: {}", err);
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.activate_evt,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("Failed to register activate event: {}", err);
        }
    }

    fn process_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = self.activate_evt.read() {
            error!("Failed to consume block activate event: {:?}", err);
        }

        self.register_rate_limiter_event(ops);
        self.register_runtime_events(ops);

        if let Err(err) = ops.remove(Events::with_data(
            &self.activate_evt,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("Failed to un-register activate event: {}", err);
        }
    }
}

impl MutEventSubscriber for VirtioBlock {
    // Handle an event for queue or rate limiter.
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.data();
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
            match source {
                Self::PROCESS_ACTIVATE => self.process_activate_event(ops),
                Self::PROCESS_RATE_LIMITER => self.process_rate_limiter_event(),
                token if token >= INLINE_WORKER_TOKEN_BASE => {
                    if let BlockRuntimeState::Inline(worker) = &mut self.state {
                        worker.process(token - INLINE_WORKER_TOKEN_BASE);
                    }
                }
                _ => warn!("Block: Spurious event received: {:?}", source),
            }
        } else {
            warn!(
                "Block: The device is not yet activated. Spurious event received: {:?}",
                source
            );
            match source {
                Self::PROCESS_ACTIVATE => {
                    let _ = self.activate_evt.read();
                }
                Self::PROCESS_RATE_LIMITER => {
                    let _ = self.rate_limiter.lock().event_handler();
                }
                // The inline worker's events stay registered across a reset: consume whichever
                // fired (reading an eventfd that did not is a harmless EAGAIN).
                token if token >= INLINE_WORKER_TOKEN_BASE => {
                    self.drain_queue_events();
                    for resources in self.resources() {
                        if let FileEngine::Async(engine) = &resources.disk.file_engine {
                            let _ = engine.completion_evt().read();
                        }
                    }
                }
                _ => (),
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        // This function can be called during different points in the device lifetime:
        //  - shortly after device creation,
        //  - on device activation (is-activated already true at this point),
        //  - on device restore from snapshot.
        if self.is_activated() {
            self.register_rate_limiter_event(ops);
            self.register_runtime_events(ops);
        } else {
            self.register_activate_event(ops);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use event_manager::{EventManager, SubscriberOps};
    use utils::time::MockClock;
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::devices::virtio::block::virtio::device::FileEngineType;
    use crate::devices::virtio::block::virtio::test_utils::{
        default_block, read_blk_req_descriptors, set_queue, set_rate_limiter,
    };
    use crate::devices::virtio::block::virtio::{VIRTIO_BLK_S_OK, VIRTIO_BLK_T_OUT};
    use crate::devices::virtio::queue::VIRTQ_DESC_F_NEXT;
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::logger::IncMetric;
    use crate::rate_limiter::{RateLimiter, TokenType};
    use crate::vstate::memory::{Bytes, GuestAddress};

    #[test]
    fn test_inline_registers_the_worker_event_list() {
        // A source only the worker declares: a device registering a list of its own instead of
        // the worker's would never watch it.
        let mut event_manager = EventManager::new().unwrap();
        let mut block = default_block(FileEngineType::Sync);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        let block = Arc::new(Mutex::new(block));
        let _id = event_manager.add_subscriber(block.clone());
        block
            .lock()
            .unwrap()
            .activate(mem, default_interrupt())
            .unwrap();
        let test_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        {
            let mut block = block.lock().unwrap();
            let BlockRuntimeState::Inline(worker) = &mut block.state else {
                panic!("a block device without num_queues runs inline");
            };
            worker.test_event = Some(test_evt.try_clone().unwrap());
        }

        // The activation event registers the inline worker's list, the test source included.
        assert_eq!(event_manager.run_with_timeout(50).unwrap(), 1);
        test_evt.write(1).unwrap();
        assert_eq!(event_manager.run_with_timeout(50).unwrap(), 1);
        // The worker's process consumed it.
        test_evt.read().unwrap_err();
    }

    #[test]
    fn test_event_handler() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut event_manager = EventManager::new().unwrap();
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            read_blk_req_descriptors(&vq);

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
                block
                    .lock()
                    .unwrap()
                    .queue_event(0)
                    .unwrap()
                    .write(1)
                    .unwrap();
            }

            // EventManager should report no events since block has only registered
            // its activation event so far (even though queue event is pending).
            let ev_count = event_manager.run_with_timeout(50).unwrap();
            assert_eq!(ev_count, 0);

            // Now activate the device.
            block
                .lock()
                .unwrap()
                .activate(mem.clone(), interrupt)
                .unwrap();
            // Process the activate event.
            let ev_count = event_manager.run_with_timeout(50).unwrap();
            assert_eq!(ev_count, 1);

            // Handle the pending queue event through EventManager. An async engine completes the
            // request later, and its completion event reaches the inline worker through the same loop.
            for _ in 0..10 {
                if vq.used.idx.get() == 1 {
                    break;
                }
                event_manager
                    .run_with_timeout(100)
                    .expect("Metrics event timeout or error.");
            }

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_inline_events_after_reset() {
        let mut event_manager = EventManager::new().unwrap();
        let mut block = default_block(FileEngineType::default());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        let block = Arc::new(Mutex::new(block));
        event_manager.add_subscriber(block.clone());
        block
            .lock()
            .unwrap()
            .activate(mem, default_interrupt())
            .unwrap();
        // The activate event registers the inline worker's events.
        assert_eq!(event_manager.run_with_timeout(50).unwrap(), 1);

        // They stay registered across a reset: a queue notification is consumed and ignored.
        assert!(block.lock().unwrap().reset());
        let queue_evt = block
            .lock()
            .unwrap()
            .queue_event(0)
            .unwrap()
            .try_clone()
            .unwrap();
        queue_evt.write(1).unwrap();
        assert_eq!(event_manager.run_with_timeout(50).unwrap(), 1);
        queue_evt.read().unwrap_err();
    }

    #[test]
    fn test_subscribe_after_activation() {
        // As on snapshot restore, the device is activated before it joins the event loop, which
        // then registers the inline worker's events straight away.
        let mut event_manager = EventManager::new().unwrap();
        let mut block = default_block(FileEngineType::default());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem, default_interrupt()).unwrap();
        let block = Arc::new(Mutex::new(block));
        event_manager.add_subscriber(block.clone());

        // Block metrics are shared by drive id, so count the events this test adds.
        let queue_events = block.lock().unwrap().metrics.queue_event_count.count();
        block
            .lock()
            .unwrap()
            .queue_event(0)
            .unwrap()
            .write(1)
            .unwrap();
        assert_eq!(event_manager.run_with_timeout(50).unwrap(), 1);
        assert_eq!(
            block.lock().unwrap().metrics.queue_event_count.count(),
            queue_events + 1
        );
    }

    #[test]
    fn test_rate_limiter_event_before_activation() {
        let mut block = default_block(FileEngineType::default());
        // One op per second: the second op blocks the limiter and arms its 100 ms refill timer.
        let clock = MockClock::new();
        let mut limiter = RateLimiter::new_mocked(0, 0, 0, 1, 0, 1000, &clock);
        assert!(limiter.consume(1, TokenType::Ops));
        assert!(!limiter.consume(1, TokenType::Ops));
        set_rate_limiter(&mut block, limiter);
        assert!(block.rate_limiter.is_blocked());

        let mut event_manager = EventManager::new().unwrap();
        let block = Arc::new(Mutex::new(block));
        let id = event_manager.add_subscriber(block.clone());
        let mut ops = event_manager.event_ops(id).unwrap();
        let mut block = block.lock().unwrap();

        // A timer that fires before the device is activated still unblocks the limiter. Events
        // are dispatched on their data, so the mocked timer needs no fd.
        clock.advance(Duration::from_millis(100));
        block.process(
            Events::with_data_raw(0, VirtioBlock::PROCESS_RATE_LIMITER, EventSet::IN),
            &mut ops,
        );
        assert!(!block.is_activated());
        assert!(!block.rate_limiter.is_blocked());
    }
}
