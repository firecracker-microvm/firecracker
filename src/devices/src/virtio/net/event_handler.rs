// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use event_manager::EventManager;
use logger::{debug, error, warn, IncMetric, METRICS};
use utils::epoll::EventSet;

use crate::virtio::net::device::Net;
use crate::virtio::{VirtioDevice, RX_INDEX, TX_INDEX};

impl Net {
    fn register_runtime_events(net: Arc<Mutex<Self>>, ops: &mut EventManager) {
        {
            let net_clone = net.clone();
            if let Err(err) = ops.add(
                net.lock().unwrap().queue_evts[RX_INDEX].as_raw_fd(),
                EventSet::IN,
                Box::new(move |_: &mut EventManager, _: EventSet| {
                    let mut n = net_clone.lock().unwrap();
                    if n.is_activated() {
                        n.process_rx_queue_event();
                    } else {
                        warn!("Net: The device is not yet activated. Spurious event received.");
                    }
                }),
            ) {
                error!("Failed to register rx queue event: {}", err);
            }
        }

        {
            let net_clone = net.clone();
            if let Err(err) = ops.add(
                net.lock().unwrap().queue_evts[TX_INDEX].as_raw_fd(),
                EventSet::IN,
                Box::new(move |_: &mut EventManager, _: EventSet| {
                    let mut n = net_clone.lock().unwrap();
                    if n.is_activated() {
                        n.process_tx_queue_event();
                    } else {
                        warn!("Net: The device is not yet activated. Spurious event received.");
                    }
                }),
            ) {
                error!("Failed to register tx queue event: {}", err);
            }
        }

        {
            let net_clone = net.clone();
            if let Err(err) = ops.add(
                net.lock().unwrap().rx_rate_limiter.as_raw_fd(),
                EventSet::IN,
                Box::new(move |_: &mut EventManager, _: EventSet| {
                    let mut n = net_clone.lock().unwrap();
                    if n.is_activated() {
                        n.process_rx_rate_limiter_event();
                    } else {
                        warn!("Net: The device is not yet activated. Spurious event received.");
                    }
                }),
            ) {
                error!("Failed to register rx queue event: {}", err);
            }
        }

        {
            let net_clone = net.clone();
            if let Err(err) = ops.add(
                net.lock().unwrap().tx_rate_limiter.as_raw_fd(),
                EventSet::IN,
                Box::new(move |_: &mut EventManager, _: EventSet| {
                    let mut n = net_clone.lock().unwrap();
                    if n.is_activated() {
                        n.process_tx_rate_limiter_event();
                    } else {
                        warn!("Net: The device is not yet activated. Spurious event received.");
                    }
                }),
            ) {
                error!("Failed to register tx queue event: {}", err);
            }
        }

        {
            let net_clone = net.clone();
            if let Err(err) = ops.add(
                net.lock().unwrap().tap.as_raw_fd(),
                EventSet::IN | EventSet::EDGE_TRIGGERED,
                Box::new(move |_: &mut EventManager, _: EventSet| {
                    let mut n = net_clone.lock().unwrap();
                    if n.is_activated() {
                        n.process_tap_rx_event();
                    } else {
                        warn!("Net: The device is not yet activated. Spurious event received.");
                    }
                }),
            ) {
                error!("Failed to register tap event: {}", err);
            }
        }
    }

    fn register_activate_event(net: Arc<Mutex<Self>>, ops: &mut EventManager) {
        let net_clone = net.clone();
        if let Err(err) = ops.add(
            net.lock().unwrap().activate_evt.as_raw_fd(),
            EventSet::IN,
            Box::new(move |event_manager: &mut EventManager, _: EventSet| {
                if net_clone.lock().unwrap().is_activated() {
                    Self::process_activate_event(net_clone.clone(), event_manager);
                } else {
                    warn!("Net: The device is not yet activated. Spurious event received.");
                }
            }),
        ) {
            error!("Failed to register activate event: {}", err);
        }
    }

    fn process_activate_event(net: Arc<Mutex<Self>>, ops: &mut EventManager) {
        debug!("net: activate event");
        if let Err(err) = net.lock().unwrap().activate_evt.read() {
            error!("Failed to consume net activate event: {:?}", err);
        }
        Net::register_runtime_events(net.clone(), ops);
        if let Err(err) = ops.del(net.lock().unwrap().activate_evt.as_raw_fd()) {
            error!("Failed to un-register activate event: {}", err);
        }
    }
    /// Attach to event manager.
    pub fn init(net: Arc<Mutex<Self>>, ops: &mut EventManager) {
        // This function can be called during different points in the device lifetime:
        //  - shortly after device creation,
        //  - on device activation (is-activated already true at this point),
        //  - on device restore from snapshot.
        if net.lock().unwrap().is_activated() {
            Self::register_runtime_events(net, ops);
        } else {
            Self::register_activate_event(net, ops);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::virtio::net::test_utils::test::TestHelper;
    use crate::virtio::net::test_utils::NetQueue;
    use crate::virtio::net::TX_INDEX;

    #[test]
    fn test_event_handler() {
        let mut th = TestHelper::get_default();

        // Push a queue event, use the TX_QUEUE_EVENT in this test.
        th.add_desc_chain(NetQueue::Tx, 0, &[(0, 4096, 0)]);

        // EventManager should report no events since net has only registered
        // its activation event so far (even though there is also a queue event pending).
        assert_eq!(th.event_manager.wait(Some(50)), Ok(false));

        // Manually force a queue event and check it's ignored pre-activation.
        th.net().queue_evts[TX_INDEX].write(1).unwrap();
        assert_eq!(th.event_manager.wait(Some(50)), Ok(false));
        // Validate there was no queue operation.
        assert_eq!(th.txq.used.idx.get(), 0);

        // Now activate the device.
        th.activate_net();
        // Handle the previously pushed queue event through EventManager.
        assert_eq!(
            th.event_manager.wait(Some(50)),
            Ok(true),
            "Metrics event timeout or error."
        );
        // Make sure the data queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
    }
}
