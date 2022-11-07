// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use event_manager::EventManager;
use logger::{debug, error, warn};
use utils::epoll::EventSet;

use super::io::FileEngine;
use crate::virtio::block::device::Block;
use crate::virtio::VirtioDevice;

impl Block {
    fn register_runtime_events(block: Arc<Mutex<Self>>, ops: &mut EventManager) {
        // Queue event
        {
            let block_clone = block.clone();
            if let Err(err) = ops.add(
                block.lock().unwrap().queue_evts[0].as_raw_fd(),
                EventSet::IN,
                Box::new(move |_: &mut EventManager, _: EventSet| {
                    if block_clone.lock().unwrap().is_activated() {
                        block_clone.lock().unwrap().process_queue_event();
                    } else {
                        warn!("Block: The device is not yet activated. Spurious event received.");
                    }
                }),
            ) {
                error!("Failed to register queue event: {}", err);
            }
        }

        // Rate limiter event
        {
            let block_clone = block.clone();
            if let Err(err) = ops.add(
                block.lock().unwrap().rate_limiter.as_raw_fd(),
                EventSet::IN,
                Box::new(move |_: &mut EventManager, _: EventSet| {
                    let mut b = block_clone.lock().unwrap();
                    if b.is_activated() {
                        b.process_rate_limiter_event();
                    } else {
                        warn!("Block: The device is not yet activated. Spurious event received.");
                    }
                }),
            ) {
                error!("Failed to register ratelimiter event: {}", err);
            }
        }

        // File engine event
        {
            let block_clone = block.clone();
            if let FileEngine::Async(engine) = block.lock().unwrap().disk.file_engine() {
                if let Err(err) = ops.add(
                    // TODO: Avoid needing  to manaully do `.as_raw_fd()` here.
                    engine.completion_evt().as_raw_fd(),
                    EventSet::IN,
                    Box::new(move |_: &mut EventManager, _: EventSet| {
                        let mut b = block_clone.lock().unwrap();
                        if b.is_activated() {
                            match b.disk.file_engine() {
                                FileEngine::Async(_) => b.process_async_completion_event(),
                                FileEngine::Sync(_) => warn!("Block: Spurious event received."),
                            }
                        } else {
                            warn!(
                                "Block: The device is not yet activated. Spurious event received."
                            );
                        }
                    }),
                ) {
                    error!("Failed to register IO engine completion event: {}", err);
                }
            }
        }
    }

    fn register_activate_event(block: Arc<Mutex<Self>>, ops: &mut EventManager) {
        let block_clone = block.clone();
        if let Err(err) = ops.add(
            block.lock().unwrap().activate_evt.as_raw_fd(),
            EventSet::IN,
            Box::new(move |event_manager: &mut EventManager, _: EventSet| {
                if block_clone.lock().unwrap().is_activated() {
                    Self::process_activate_event(block_clone.clone(), event_manager);
                } else {
                    warn!("Block: The device is not yet activated. Spurious event received.");
                }
            }),
        ) {
            error!("Failed to register activate event: {}", err);
        }
    }

    fn process_activate_event(block: Arc<Mutex<Self>>, ops: &mut EventManager) {
        debug!("block: activate event");
        if let Err(err) = block.lock().unwrap().activate_evt.read() {
            error!("Failed to consume block activate event: {:?}", err);
        }
        Self::register_runtime_events(block.clone(), ops);
        if let Err(err) = ops.del(block.lock().unwrap().activate_evt.as_raw_fd()) {
            error!("Failed to un-register activate event: {}", err);
        }
    }

    /// Attach to event manager.
    pub fn init(block: Arc<Mutex<Self>>, ops: &mut EventManager) {
        // This function can be called during different points in the device lifetime:
        //  - shortly after device creation,
        //  - on device activation (is-activated already true at this point),
        //  - on device restore from snapshot.
        if block.lock().unwrap().is_activated() {
            Self::register_runtime_events(block, ops);
        } else {
            Self::register_activate_event(block, ops);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::{Arc, Mutex};

    use event_manager::EventManager;
    use virtio_gen::virtio_blk::{VIRTIO_BLK_S_OK, VIRTIO_BLK_T_OUT};
    use vm_memory::{Bytes, GuestAddress};

    use super::*;
    use crate::virtio::block::device::FileEngineType;
    use crate::virtio::block::test_utils::{
        default_block, set_queue, simulate_async_completion_event,
    };
    use crate::virtio::queue::tests::*;
    use crate::virtio::test_utils::{default_mem, initialize_virtqueue, VirtQueue};

    #[test]
    fn test_event_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let mut block = default_block(FileEngineType::default());
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        initialize_virtqueue(&vq);

        let block = Arc::new(Mutex::new(block));
        Block::init(block.clone(), &mut event_manager);

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
        assert_eq!(event_manager.wait(Some(50)), Ok(false));

        // Now activate the device.
        block.lock().unwrap().activate(mem.clone()).unwrap();
        // Process the activate event.
        assert_eq!(event_manager.wait(Some(50)), Ok(true));

        // Handle the pending queue event through EventManager.
        assert_eq!(
            event_manager.wait(Some(100)),
            Ok(true),
            "Metrics event timeout or error."
        );
        // Complete async IO ops if needed
        simulate_async_completion_event(&mut block.lock().unwrap(), true);

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 1);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
    }
}
