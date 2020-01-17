// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::virtio::net::device::Net;
use crate::virtio::{RX_INDEX, TX_INDEX};
use polly::event_manager::EventHandler;
use polly::pollable::{Pollable, PollableOp, PollableOpBuilder};
use std::os::unix::io::AsRawFd;

impl EventHandler for Net {
    fn handle_read(&mut self, source: Pollable) -> Vec<PollableOp> {
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
            _ => error!("Unknown event. No handling was done."),
        }

        vec![]
    }

    fn init(&self) -> Vec<PollableOp> {
        vec![
            PollableOpBuilder::new(self.tap.as_raw_fd())
                .readable()
                .edge_trigered()
                .register(),
            PollableOpBuilder::new(self.queue_evts[RX_INDEX].as_raw_fd())
                .readable()
                .register(),
            PollableOpBuilder::new(self.queue_evts[TX_INDEX].as_raw_fd())
                .readable()
                .register(),
            PollableOpBuilder::new(self.rx_rate_limiter.as_raw_fd())
                .readable()
                .register(),
            PollableOpBuilder::new(self.tx_rate_limiter.as_raw_fd())
                .readable()
                .register(),
        ]
    }
}
