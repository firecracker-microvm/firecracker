// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;

use logger::{Metric, METRICS};
use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::net::device::Net;
use crate::virtio::{VirtioDevice, RX_INDEX, TX_INDEX};

impl Subscriber for Net {
    fn process(&mut self, event: &EpollEvent, _: &mut EventManager) {
        if !self.is_activated() {
            warn!("The device is not yet activated. Events can not be handled.");
            return;
        }

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

        let virtq_rx_ev_fd = self.queue_evts[RX_INDEX].as_raw_fd();
        let virtq_tx_ev_fd = self.queue_evts[TX_INDEX].as_raw_fd();
        let rx_rate_limiter_fd = self.rx_rate_limiter.as_raw_fd();
        let tx_rate_limiter_fd = self.tx_rate_limiter.as_raw_fd();
        let tap_fd = self.tap.as_raw_fd();

        match source {
            _ if source == virtq_rx_ev_fd => self.process_rx_queue_event(),
            _ if source == tap_fd => self.process_tap_rx_event(),
            _ if source == virtq_tx_ev_fd => self.process_tx_queue_event(),
            _ if source == rx_rate_limiter_fd => self.process_rx_rate_limiter_event(),
            _ if source == tx_rate_limiter_fd => self.process_tx_rate_limiter_event(),
            _ => {
                error!("Unknown event source.");
                METRICS.net.event_fails.inc();
            }
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![
            EpollEvent::new(
                EventSet::IN | EventSet::EDGE_TRIGGERED,
                self.tap.as_raw_fd() as u64,
            ),
            EpollEvent::new(EventSet::IN, self.queue_evts[RX_INDEX].as_raw_fd() as u64),
            EpollEvent::new(EventSet::IN, self.queue_evts[TX_INDEX].as_raw_fd() as u64),
            EpollEvent::new(EventSet::IN, self.rx_rate_limiter.as_raw_fd() as u64),
            EpollEvent::new(EventSet::IN, self.tx_rate_limiter.as_raw_fd() as u64),
        ]
    }
}
