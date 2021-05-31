// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;

use event_manager::{EventOps, Events, MutEventSubscriber};
use logger::{debug, error, warn, IncMetric, METRICS};
use utils::epoll::EventSet;

use crate::virtio::net::device::Net;
use crate::virtio::{VirtioDevice, RX_INDEX, TX_INDEX};

impl Net {
    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(e) = ops.add(Events::new(&self.queue_evts[RX_INDEX], EventSet::IN)) {
            error!("Failed to register rx queue event: {}", e);
        }
        if let Err(e) = ops.add(Events::new(&self.queue_evts[TX_INDEX], EventSet::IN)) {
            error!("Failed to register tx queue event: {}", e);
        }
        if let Err(e) = ops.add(Events::new(&self.rx_rate_limiter, EventSet::IN)) {
            error!("Failed to register rx queue event: {}", e);
        }
        if let Err(e) = ops.add(Events::new(&self.tx_rate_limiter, EventSet::IN)) {
            error!("Failed to register tx queue event: {}", e);
        }
        if let Err(e) = ops.add(Events::new(
            &self.tap,
            EventSet::IN | EventSet::EDGE_TRIGGERED,
        )) {
            error!("Failed to register tap event: {}", e);
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(e) = ops.add(Events::new(&self.activate_evt, EventSet::IN)) {
            error!("Failed to register activate event: {}", e);
        }
    }

    fn process_activate_event(&self, ops: &mut EventOps) {
        debug!("net: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume net activate event: {:?}", e);
        }
        self.register_runtime_events(ops);
        if let Err(e) = ops.remove(Events::new(&self.activate_evt, EventSet::IN)) {
            error!("Failed to un-register activate event: {}", e);
        }
    }
}

impl MutEventSubscriber for Net {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!(
                "Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if self.is_activated() {
            let virtq_rx_ev_fd = self.queue_evts[RX_INDEX].as_raw_fd();
            let virtq_tx_ev_fd = self.queue_evts[TX_INDEX].as_raw_fd();
            let rx_rate_limiter_fd = self.rx_rate_limiter.as_raw_fd();
            let tx_rate_limiter_fd = self.tx_rate_limiter.as_raw_fd();
            let tap_fd = self.tap.as_raw_fd();
            let activate_fd = self.activate_evt.as_raw_fd();

            // Looks better than C style if/else if/else.
            match source {
                _ if source == virtq_rx_ev_fd => self.process_rx_queue_event(),
                _ if source == tap_fd => self.process_tap_rx_event(),
                _ if source == virtq_tx_ev_fd => self.process_tx_queue_event(),
                _ if source == rx_rate_limiter_fd => self.process_rx_rate_limiter_event(),
                _ if source == tx_rate_limiter_fd => self.process_tx_rate_limiter_event(),
                _ if activate_fd == source => self.process_activate_event(ops),
                _ => {
                    warn!("Net: Spurious event received: {:?}", source);
                    METRICS.net.event_fails.inc();
                }
            }
        } else {
            warn!(
                "Net: The device is not yet activated. Spurious event received: {:?}",
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
    use crate::virtio::net::test_utils::test::TestHelper;
    use crate::virtio::net::test_utils::NetQueue;
    use crate::virtio::net::TX_INDEX;

    #[test]
    fn test_event_handler() {
        let mut th = TestHelper::default();

        // Push a queue event, use the TX_QUEUE_EVENT in this test.
        th.add_desc_chain(NetQueue::Tx, 0, &[(0, 4096, 0)]);

        // EventManager should report no events since net has only registered
        // its activation event so far (even though there is also a queue event pending).
        let ev_count = th.event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 0);

        // Manually force a queue event and check it's ignored pre-activation.
        th.net().queue_evts[TX_INDEX].write(1).unwrap();
        let ev_count = th.event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 0);
        // Validate there was no queue operation.
        assert_eq!(th.txq.used.idx.get(), 0);

        // Now activate the device.
        th.activate_net();
        // Handle the previously pushed queue event through EventManager.
        th.event_manager
            .run_with_timeout(50)
            .expect("Metrics event timeout or error.");
        // Make sure the data queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
    }
}
