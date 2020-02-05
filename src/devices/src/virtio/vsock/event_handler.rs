// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

/// The vsock object implements the runtime logic of our vsock device:
/// 1. Respond to TX queue events by wrapping virtio buffers into `VsockPacket`s, then sending those
///    packets to the `VsockBackend`;
/// 2. Forward backend FD event notifications to the `VsockBackend`;
/// 3. Fetch incoming packets from the `VsockBackend` and place them into the virtio RX queue;
/// 4. Whenever we have processed some virtio buffers (either TX or RX), let the driver know by
///    raising our assigned IRQ.
///
/// In a nutshell, the logic looks like this:
/// - on TX queue event:
///   - fetch all packets from the TX queue and send them to the backend; then
///   - if the backend has queued up any incoming packets, fetch them into any available RX buffers.
/// - on RX queue event:
///   - fetch any incoming packets, queued up by the backend, into newly available RX buffers.
/// - on backend event:
///   - forward the event to the backend; then
///   - again, attempt to fetch any incoming packets queued by the backend into virtio RX buffers.
use std::os::unix::io::AsRawFd;

use polly::epoll::{EpollEvent, EventSet};
use polly::event_manager::{EventManager, Subscriber};

use super::device::{Vsock, EVQ_INDEX, RXQ_INDEX, TXQ_INDEX};
use super::VsockBackend;

impl<B> Vsock<B>
where
    B: VsockBackend + 'static,
{
    pub(crate) fn handle_rxq_event(&mut self, event: EpollEvent) -> bool {
        debug!("vsock: RX queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("vsock: rxq unexpected event {:?}", event_set);
            return false;
        }

        let mut raise_irq = false;
        if let Err(e) = self.queue_events[RXQ_INDEX].read() {
            error!("Failed to get vsock rx queue event: {:?}", e);
        } else if self.backend.has_pending_rx() {
            raise_irq |= self.process_rx();
        }
        raise_irq
    }

    pub(crate) fn handle_txq_event(&mut self, event: EpollEvent) -> bool {
        debug!("vsock: TX queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("vsock: txq unexpected event {:?}", event_set);
            return false;
        }

        let mut raise_irq = false;
        if let Err(e) = self.queue_events[TXQ_INDEX].read() {
            error!("Failed to get vsock tx queue event: {:?}", e);
        } else {
            raise_irq |= self.process_tx();
            // The backend may have queued up responses to the packets we sent during
            // TX queue processing. If that happened, we need to fetch those responses
            // and place them into RX buffers.
            if self.backend.has_pending_rx() {
                raise_irq |= self.process_rx();
            }
        }
        raise_irq
    }

    fn handle_evq_event(&mut self, event: EpollEvent) -> bool {
        debug!("vsock: event queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("vsock: evq unexpected event {:?}", event_set);
            return false;
        }

        if let Err(e) = self.queue_events[EVQ_INDEX].read() {
            error!("Failed to consume vsock evq event: {:?}", e);
        }
        false
    }

    fn notify_backend(&mut self, event: EpollEvent) -> bool {
        debug!("vsock: backend event");

        self.backend.notify(event.event_set());
        // After the backend has been kicked, it might've freed up some resources, so we
        // can attempt to send it more data to process.
        // In particular, if `self.backend.send_pkt()` halted the TX queue processing (by
        // reurning an error) at some point in the past, now is the time to try walking the
        // TX queue again.
        let mut raise_irq = self.process_tx();
        if self.backend.has_pending_rx() {
            raise_irq |= self.process_rx();
        }
        raise_irq
    }

    fn handle_activate_event(&self, event_manager: &mut EventManager) {
        debug!("vsock: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume vsock activate event: {:?}", e);
        }

        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = event_manager
            .subscriber(self.activate_evt.as_raw_fd())
            .unwrap();

        event_manager
            .register(
                self.queue_events[RXQ_INDEX].as_raw_fd(),
                EpollEvent::new(
                    EventSet::IN,
                    self.queue_events[RXQ_INDEX].as_raw_fd() as u64,
                ),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register vsock rxq with event manager: {:?}", e);
            });

        event_manager
            .register(
                self.queue_events[TXQ_INDEX].as_raw_fd(),
                EpollEvent::new(
                    EventSet::IN,
                    self.queue_events[TXQ_INDEX].as_raw_fd() as u64,
                ),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register vsock txq with event manager: {:?}", e);
            });

        event_manager
            .register(
                self.queue_events[EVQ_INDEX].as_raw_fd(),
                EpollEvent::new(
                    EventSet::IN,
                    self.queue_events[EVQ_INDEX].as_raw_fd() as u64,
                ),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register vsock evq with event manager: {:?}", e);
            });

        event_manager
            .register(
                self.backend.as_raw_fd(),
                EpollEvent::new(
                    self.backend.get_polled_evset(),
                    self.backend.as_raw_fd() as u64,
                ),
                self_subscriber,
            )
            .unwrap_or_else(|e| {
                error!("Failed to register vsock backend events: {:?}", e);
            });

        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!("Failed to unregister vsock activate evt: {:?}", e);
            })
    }
}

impl<B> Subscriber for Vsock<B>
where
    B: VsockBackend + 'static,
{
    fn process(&mut self, event: EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let rxq = self.queue_events[RXQ_INDEX].as_raw_fd();
        let txq = self.queue_events[TXQ_INDEX].as_raw_fd();
        let evq = self.queue_events[EVQ_INDEX].as_raw_fd();
        let backend = self.backend.as_raw_fd();
        let activate_evt = self.activate_evt.as_raw_fd();

        let mut raise_irq = false;

        match source {
            _ if source == rxq => raise_irq = self.handle_rxq_event(event),
            _ if source == txq => raise_irq = self.handle_txq_event(event),
            _ if source == evq => raise_irq = self.handle_evq_event(event),
            _ if source == backend => {
                raise_irq = self.notify_backend(event);
            }
            _ if source == activate_evt => {
                self.handle_activate_event(event_manager);
            }
            _ => warn!("Unexpected vsock event received: {:?}", source),
        }

        if raise_irq {
            self.signal_used_queue().unwrap_or_default();
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
mod tests {
    use std::sync::atomic::Ordering;

    use super::super::tests::TestContext;
    use super::super::*;
    use super::*;

    use crate::virtio::VIRTIO_MMIO_INT_VRING;
    use crate::Error as DeviceError;

    #[test]
    fn test_irq() {
        // Test case: successful IRQ signaling.
        {
            let test_ctx = TestContext::new();
            let ctx = test_ctx.create_event_handler_context();

            ctx.device.signal_used_queue().unwrap();
            assert_eq!(
                ctx.device.interrupt_status.load(Ordering::SeqCst),
                VIRTIO_MMIO_INT_VRING as usize
            );
            assert_eq!(ctx.device.interrupt_evt.read().unwrap(), 1);
        }

        // Test case: error (a real stretch) - the event counter is full.
        //
        {
            let test_ctx = TestContext::new();
            let ctx = test_ctx.create_event_handler_context();

            ctx.device.interrupt_evt.write(std::u64::MAX - 1).unwrap();
            match ctx.device.signal_used_queue() {
                Err(DeviceError::FailedSignalingUsedQueue(_)) => (),
                other => panic!("{:?}", other),
            }
        }
    }

    #[test]
    fn test_txq_event() {
        // Test case:
        // - the driver has something to send (there's data in the TX queue); and
        // - the backend has no pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();

            ctx.device.backend.set_pending_rx(false);
            ctx.signal_txq_event();

            // The available TX descriptor should have been used.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            // The available RX descriptor should be untouched.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }

        // Test case:
        // - the driver has something to send (there's data in the TX queue); and
        // - the backend also has some pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();

            ctx.device.backend.set_pending_rx(true);
            ctx.signal_txq_event();

            // Both available RX and TX descriptors should have been used.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
        }

        // Test case:
        // - the driver has something to send (there's data in the TX queue); and
        // - the backend errors out and cannot process the TX queue.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();

            ctx.device.backend.set_pending_rx(false);
            ctx.device.backend.set_tx_err(Some(VsockError::NoData));
            ctx.signal_txq_event();

            // Both RX and TX queues should be untouched.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 0);
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }

        // Test case:
        // - the driver supplied a malformed TX buffer.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();

            // Invalidate the packet header descriptor, by setting its length to 0.
            ctx.guest_txvq.dtable[0].len.set(0);
            ctx.signal_txq_event();

            // The available descriptor should have been consumed, but no packet should have
            // reached the backend.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            assert_eq!(ctx.device.backend.tx_ok_cnt, 0);
        }

        // Test case: spurious TXQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();

            assert!(!ctx
                .device
                .handle_txq_event(EpollEvent::new(EventSet::IN, 0)));
        }
    }

    #[test]
    fn test_rxq_event() {
        // Test case:
        // - there is pending RX data in the backend; and
        // - the driver makes RX buffers available; and
        // - the backend successfully places its RX data into the queue.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();

            ctx.device.backend.set_pending_rx(true);
            ctx.device.backend.set_rx_err(Some(VsockError::NoData));
            ctx.signal_rxq_event();

            // The available RX buffer should've been left untouched.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }

        // Test case:
        // - there is pending RX data in the backend; and
        // - the driver makes RX buffers available; and
        // - the backend errors out, when attempting to receive data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();

            ctx.device.backend.set_pending_rx(true);
            ctx.signal_rxq_event();

            // The available RX buffer should have been used.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
        }

        // Test case: the driver provided a malformed RX descriptor chain.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();

            // Invalidate the packet header descriptor, by setting its length to 0.
            ctx.guest_rxvq.dtable[0].len.set(0);

            // The chain should've been processed, without employing the backend.
            assert_eq!(ctx.device.process_rx(), true);
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
            assert_eq!(ctx.device.backend.rx_ok_cnt, 0);
        }

        // Test case: spurious RXQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.device.backend.set_pending_rx(false);
            assert!(!ctx
                .device
                .handle_rxq_event(EpollEvent::new(EventSet::IN, 0)));
        }
    }

    #[test]
    fn test_evq_event() {
        // Test case: spurious EVQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.device.backend.set_pending_rx(false);
            assert!(!ctx
                .device
                .handle_evq_event(EpollEvent::new(EventSet::IN, 0)));
        }
    }

    #[test]
    fn test_backend_event() {
        // Test case:
        // - a backend event is received; and
        // - the backend has pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();

            ctx.device.backend.set_pending_rx(true);
            ctx.device.notify_backend(EpollEvent::new(EventSet::IN, 0));

            // The backend should've received this event.
            assert_eq!(ctx.device.backend.evset, Some(EventSet::IN));
            // TX queue processing should've been triggered.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            // RX queue processing should've been triggered.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
        }

        // Test case:
        // - a backend event is received; and
        // - the backend doesn't have any pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();

            ctx.device.backend.set_pending_rx(false);
            ctx.device.notify_backend(EpollEvent::new(EventSet::IN, 0));

            // The backend should've received this event.
            assert_eq!(ctx.device.backend.evset, Some(EventSet::IN));
            // TX queue processing should've been triggered.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            // The RX queue should've been left untouched.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }
    }
}
