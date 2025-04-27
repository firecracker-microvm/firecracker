// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::net::device::Net;
use crate::devices::virtio::net::{RX_INDEX, TX_INDEX};
use crate::logger::{IncMetric, error, warn};

impl Net {
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_VIRTQ_RX: u32 = 1;
    const PROCESS_VIRTQ_TX: u32 = 2;
    const PROCESS_TAP_RX: u32 = 3;
    const PROCESS_RX_RATE_LIMITER: u32 = 4;
    const PROCESS_TX_RATE_LIMITER: u32 = 5;

    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.queue_evts[RX_INDEX],
            Self::PROCESS_VIRTQ_RX,
            EventSet::IN,
        )) {
            error!("Failed to register rx queue event: {}", err);
        }
        if let Err(err) = ops.add(Events::with_data(
            &self.queue_evts[TX_INDEX],
            Self::PROCESS_VIRTQ_TX,
            EventSet::IN,
        )) {
            error!("Failed to register tx queue event: {}", err);
        }
        if let Err(err) = ops.add(Events::with_data(
            &self.rx_rate_limiter,
            Self::PROCESS_RX_RATE_LIMITER,
            EventSet::IN,
        )) {
            error!("Failed to register rx queue event: {}", err);
        }
        if let Err(err) = ops.add(Events::with_data(
            &self.tx_rate_limiter,
            Self::PROCESS_TX_RATE_LIMITER,
            EventSet::IN,
        )) {
            error!("Failed to register tx queue event: {}", err);
        }
        if let Err(err) = ops.add(Events::with_data(
            &self.tap,
            Self::PROCESS_TAP_RX,
            EventSet::IN | EventSet::EDGE_TRIGGERED,
        )) {
            error!("Failed to register tap event: {}", err);
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
            error!("Failed to consume net activate event: {:?}", err);
        }
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

impl MutEventSubscriber for Net {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.data();
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
            match source {
                Self::PROCESS_ACTIVATE => self.process_activate_event(ops),
                Self::PROCESS_VIRTQ_RX => self.process_rx_queue_event(),
                Self::PROCESS_VIRTQ_TX => self.process_tx_queue_event(),
                Self::PROCESS_TAP_RX => self.process_tap_rx_event(),
                Self::PROCESS_RX_RATE_LIMITER => self.process_rx_rate_limiter_event(),
                Self::PROCESS_TX_RATE_LIMITER => self.process_tx_rate_limiter_event(),
                _ => {
                    warn!("Net: Spurious event received: {:?}", source);
                    self.metrics.event_fails.inc();
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
    use crate::devices::virtio::net::test_utils::NetQueue;
    use crate::devices::virtio::net::test_utils::test::TestHelper;
    use crate::devices::virtio::net::{MAX_BUFFER_SIZE, TX_INDEX};
    use crate::test_utils::single_region_mem;

    #[test]
    fn test_event_handler() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);

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
