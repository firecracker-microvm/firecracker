// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::virtio::net::device::Net;
use crate::virtio::{VirtioDevice, RX_INDEX, TX_INDEX};
use logger::{Metric, METRICS};
use polly::event_manager::EventHandler;
use polly::pollable::{Pollable, PollableOp, PollableOpBuilder};
use std::os::unix::io::AsRawFd;

impl EventHandler for Net {
    fn handle_read(&mut self, source: Pollable) -> Vec<PollableOp> {
        if !self.is_activated() {
            warn!("The device is not yet activated. Events can not be handled.");
            return vec![];
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
#[cfg(test)]
pub mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use rate_limiter::RateLimiter;
    use utils::net::Tap;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    fn new_tap(enabled: bool) -> Tap {
        static NEXT_INDEX: AtomicUsize = AtomicUsize::new(1);
        let next_tap = NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
        let tap = Tap::open_named(&format!("net-handler{}", next_tap)).unwrap();
        if enabled {
            tap.enable().unwrap();
        }
        tap
    }

    #[test]
    fn test_event_handler_init() {
        let net = Net::new_with_tap(
            new_tap(false),
            None,
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
            RateLimiter::default(),
            RateLimiter::default(),
            false,
        )
        .unwrap();
        let pollable_ops = net.init();
        assert_eq!(pollable_ops.len(), 5);
        for (idx, pollable_op) in pollable_ops.iter().enumerate() {
            match pollable_op {
                PollableOp::Register(reg_data) => {
                    let (pollable, event_set) = reg_data;
                    match idx {
                        0 => {
                            assert_eq!(*pollable, net.tap.as_raw_fd());
                            assert!(event_set.is_edge_triggered());
                        }
                        1 => assert_eq!(*pollable, net.queue_evts[RX_INDEX].as_raw_fd()),
                        2 => assert_eq!(*pollable, net.queue_evts[TX_INDEX].as_raw_fd()),
                        3 => assert_eq!(*pollable, net.rx_rate_limiter.as_raw_fd()),
                        4 => assert_eq!(*pollable, net.tx_rate_limiter.as_raw_fd()),
                        _ => panic!("Unexpected pollable op."),
                    };
                    assert!(event_set.is_readable());
                    assert!(!event_set.is_writeable());
                    assert!(!event_set.is_closed());
                }
                _ => panic!("Unexpected pollable op."),
            }
        }
    }
}
