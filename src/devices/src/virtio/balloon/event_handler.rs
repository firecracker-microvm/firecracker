// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use event_manager::EventManager;
use logger::{debug, error, warn};
use utils::epoll::EventSet;

use crate::report_balloon_event_fail;
use crate::virtio::balloon::device::Balloon;
use crate::virtio::{VirtioDevice, DEFLATE_INDEX, INFLATE_INDEX, STATS_INDEX};

impl Balloon {
    fn register_runtime_events(balloon: Arc<Mutex<Self>>, ops: &mut EventManager) {
        // Inflate
        {
            let balloon_clone = balloon.clone();
            if let Err(err) = ops.add(
                balloon.lock().unwrap().queue_evts[INFLATE_INDEX].as_raw_fd(),
                EventSet::IN,
                Box::new(move |_: &mut EventManager, _: EventSet| {
                    let mut b = balloon_clone.lock().unwrap();
                    if b.is_activated() {
                        b.process_inflate_queue_event()
                            .unwrap_or_else(report_balloon_event_fail)
                    } else {
                        warn!("Balloon: The device is not yet activated. Spurious event received.");
                    }
                }),
            ) {
                error!("Failed to register inflate queue event: {}", err);
            }
        }

        // Deflate
        {
            let balloon_clone = balloon.clone();
            if let Err(err) = ops.add(
                balloon.lock().unwrap().queue_evts[DEFLATE_INDEX].as_raw_fd(),
                EventSet::IN,
                Box::new(move |_: &mut EventManager, _: EventSet| {
                    let mut b = balloon_clone.lock().unwrap();
                    if b.is_activated() {
                        b.process_deflate_queue_event()
                            .unwrap_or_else(report_balloon_event_fail)
                    } else {
                        warn!("Balloon: The device is not yet activated. Spurious event received.");
                    }
                }),
            ) {
                error!("Failed to register deflate queue event: {}", err);
            }
        }

        if balloon.lock().unwrap().stats_enabled() {
            // Stats queue
            {
                let balloon_clone = balloon.clone();
                if let Err(err) = ops.add(
                    balloon.lock().unwrap().queue_evts[STATS_INDEX].as_raw_fd(),
                    EventSet::IN,
                    Box::new(move |_: &mut EventManager, _: EventSet| {
                        let mut b = balloon_clone.lock().unwrap();
                        if b.is_activated() {
                            b.process_stats_queue_event()
                                .unwrap_or_else(report_balloon_event_fail)
                        } else {
                            warn!(
                                "Balloon: The device is not yet activated. Spurious event \
                                 received."
                            );
                        }
                    }),
                ) {
                    error!("Failed to register stats queue event: {}", err);
                }
            }

            // Stats timer
            {
                let balloon_clone = balloon.clone();
                if let Err(err) = ops.add(
                    balloon.lock().unwrap().stats_timer.as_raw_fd(),
                    EventSet::IN,
                    Box::new(move |_: &mut EventManager, _: EventSet| {
                        let mut b = balloon_clone.lock().unwrap();
                        if b.is_activated() {
                            b.process_stats_timer_event()
                                .unwrap_or_else(report_balloon_event_fail)
                        } else {
                            warn!(
                                "Balloon: The device is not yet activated. Spurious event \
                                 received."
                            );
                        }
                    }),
                ) {
                    error!("Failed to register stats timerfd event: {}", err);
                }
            }
        }
    }

    fn register_activate_event(balloon: Arc<Mutex<Self>>, ops: &mut EventManager) {
        let balloon_clone = balloon.clone();
        if let Err(err) = ops.add(
            balloon.lock().unwrap().activate_evt.as_raw_fd(),
            EventSet::IN,
            Box::new(move |event_manager: &mut EventManager, _: EventSet| {
                if balloon_clone.lock().unwrap().is_activated() {
                    Self::process_activate_event(balloon_clone.clone(), event_manager);
                } else {
                    warn!("Balloon: The device is not yet activated. Spurious event received.");
                }
            }),
        ) {
            error!("Failed to register activate event: {}", err);
        }
    }

    fn process_activate_event(balloon: Arc<Mutex<Self>>, ops: &mut EventManager) {
        debug!("balloon: activate event");
        if let Err(err) = balloon.lock().unwrap().activate_evt.read() {
            error!("Failed to consume balloon activate event: {:?}", err);
        }
        Self::register_runtime_events(balloon.clone(), ops);
        if let Err(err) = ops.del(balloon.lock().unwrap().activate_evt.as_raw_fd()) {
            error!("Failed to un-register activate event: {}", err);
        }
    }
    /// Attach to event manager.
    pub fn init(balloon: Arc<Mutex<Self>>, ops: &mut EventManager) {
        // This function can be called during different points in the device lifetime:
        //  - shortly after device creation,
        //  - on device activation (is-activated already true at this point),
        //  - on device restore from snapshot.
        if balloon.lock().unwrap().is_activated() {
            Self::register_runtime_events(balloon, ops);
        } else {
            Self::register_activate_event(balloon, ops);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::{Arc, Mutex};

    use event_manager::EventManager;
    use vm_memory::GuestAddress;

    use super::*;
    use crate::virtio::balloon::test_utils::set_request;
    use crate::virtio::test_utils::{default_mem, VirtQueue};

    #[test]
    fn test_event_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let mut balloon = Balloon::new(0, true, 10, false).unwrap();
        let mem = default_mem();
        let infq = VirtQueue::new(GuestAddress(0), &mem, 16);
        balloon.set_queue(INFLATE_INDEX, infq.create_queue());

        let balloon = Arc::new(Mutex::new(balloon));
        // Register events
        Ballon::init(balloon.clone(), &mut event_manager);

        // Push a queue event, use the inflate queue in this test.
        {
            let addr = 0x100;
            set_request(&infq, 0, addr, 4, 0);
            balloon.lock().unwrap().queue_evts[INFLATE_INDEX]
                .write(1)
                .unwrap();
        }

        // EventManager should report no events since balloon has only registered
        // its activation event so far (even though there is also a queue event pending).
        assert_eq!(event_manager.wait(Some(50)), Ok(false));

        // Manually force a queue event and check it's ignored pre-activation.
        {
            let b = balloon.lock().unwrap();
            // Artificially push event.
            b.queue_evts[INFLATE_INDEX].write(1).unwrap();
            // Process the pushed event.
            assert_eq!(event_manager.wait(Some(50)), Ok(false));
            // Validate there was no queue operation.
            assert_eq!(infq.used.idx.get(), 0);
        }

        // Now activate the device.
        balloon.lock().unwrap().activate(mem.clone()).unwrap();
        // Process the activate event.
        assert_eq!(event_manager.wait(Some(50)), Ok(true));

        // Handle the previously pushed queue event through EventManager.
        assert_eq!(event_manager.wait(Some(100)), Ok(true));
        // Make sure the data queue advanced.
        assert_eq!(infq.used.idx.get(), 1);
    }
}
