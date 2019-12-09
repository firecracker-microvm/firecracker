// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

/// The vsock `EpollHandler` implements the runtime logic of our vsock device:
/// 1. Respond to TX queue events by wrapping virtio buffers into `VsockPacket`s, then sending those
///    packets to the `VsockBackend`;
/// 2. Forward backend FD event notifications to the `VsockBackend`;
/// 3. Fetch incoming packets from the `VsockBackend` and place them into the virtio RX queue;
/// 4. Whenever we have processed some virtio buffers (either TX or RX), let the driver know by
///    raising our assigned IRQ.
///
/// In a nutshell, the `EpollHandler` logic looks like this:
/// - on TX queue event:
///   - fetch all packets from the TX queue and send them to the backend; then
///   - if the backend has queued up any incoming packets, fetch them into any available RX buffers.
/// - on RX queue event:
///   - fetch any incoming packets, queued up by the backend, into newly available RX buffers.
/// - on backend event:
///   - forward the event to the backend; then
///   - again, attempt to fetch any incoming packets queued by the backend into virtio RX buffers.
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use memory_model::GuestMemory;
use utils::eventfd::EventFd;

use super::super::super::{DeviceEventT, Error as DeviceError};
use super::super::queue::Queue as VirtQueue;
use super::super::VIRTIO_MMIO_INT_VRING;
use super::defs;
use super::packet::VsockPacket;
use super::{EpollHandler, VsockBackend};

// TODO: Detect / handle queue deadlock:
// 1. If the driver halts RX queue processing, we'll need to notify `self.backend`, so that it
//    can unregister any EPOLLIN listeners, since otherwise it will keep spinning, unable to consume
//    its EPOLLIN events.

pub struct VsockEpollHandler<B: VsockBackend + 'static> {
    pub rxvq: VirtQueue,
    pub rxvq_evt: EventFd,
    pub txvq: VirtQueue,
    pub txvq_evt: EventFd,
    pub evvq: VirtQueue,
    pub evvq_evt: EventFd,
    pub cid: u64,
    pub mem: GuestMemory,
    pub interrupt_status: Arc<AtomicUsize>,
    pub interrupt_evt: EventFd,
    pub backend: B,
}

impl<B> VsockEpollHandler<B>
where
    B: VsockBackend + 'static,
{
    /// Signal the guest driver that we've used some virtio buffers that it had previously made
    /// available.
    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        debug!("vsock: raising IRQ");
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            DeviceError::FailedSignalingUsedQueue(e)
        })
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending.
    fn process_rx(&mut self) -> bool {
        debug!("vsock: epoll_handler::process_rx()");

        let mut have_used = false;

        while let Some(head) = self.rxvq.pop(&self.mem) {
            let used_len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => {
                    if self.backend.recv_pkt(&mut pkt).is_ok() {
                        pkt.hdr().len() as u32 + pkt.len()
                    } else {
                        // We are using a consuming iterator over the virtio buffers, so, if we can't
                        // fill in this buffer, we'll need to undo the last iterator step.
                        self.rxvq.undo_pop();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue error: {:?}", e);
                    0
                }
            };

            have_used = true;
            self.rxvq.add_used(&self.mem, head.index, used_len);
        }

        have_used
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and send them to
    /// the backend for processing.
    fn process_tx(&mut self) -> bool {
        debug!("vsock: epoll_handler::process_tx()");

        let mut have_used = false;

        while let Some(head) = self.txvq.pop(&self.mem) {
            let pkt = match VsockPacket::from_tx_virtq_head(&head) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("vsock: error reading TX packet: {:?}", e);
                    have_used = true;
                    self.txvq.add_used(&self.mem, head.index, 0);
                    continue;
                }
            };

            if self.backend.send_pkt(&pkt).is_err() {
                self.txvq.undo_pop();
                break;
            }

            have_used = true;
            self.txvq.add_used(&self.mem, head.index, 0);
        }

        have_used
    }
}

impl<B> EpollHandler for VsockEpollHandler<B>
where
    B: VsockBackend,
{
    /// Respond to a new event, coming from the main epoll loop (implemented by the VMM).
    fn handle_event(
        &mut self,
        device_event: DeviceEventT,
        evset: epoll::Events,
    ) -> result::Result<(), DeviceError> {
        let mut raise_irq = false;

        match device_event {
            defs::RXQ_EVENT => {
                debug!("vsock: RX queue event");
                if let Err(e) = self.rxvq_evt.read() {
                    error!("Failed to get rx queue event: {:?}", e);
                    return Err(DeviceError::FailedReadingQueue {
                        event_type: "rx queue event",
                        underlying: e,
                    });
                } else if self.backend.has_pending_rx() {
                    raise_irq |= self.process_rx();
                }
            }
            defs::TXQ_EVENT => {
                debug!("vsock: TX queue event");
                if let Err(e) = self.txvq_evt.read() {
                    error!("Failed to get tx queue event: {:?}", e);
                    return Err(DeviceError::FailedReadingQueue {
                        event_type: "tx queue event",
                        underlying: e,
                    });
                } else {
                    raise_irq |= self.process_tx();
                    // The backend may have queued up responses to the packets we sent during TX queue
                    // processing. If that happened, we need to fetch those responses and place them
                    // into RX buffers.
                    if self.backend.has_pending_rx() {
                        raise_irq |= self.process_rx();
                    }
                }
            }
            defs::EVQ_EVENT => {
                debug!("vsock: event queue event");
                if let Err(e) = self.evvq_evt.read() {
                    error!("Failed to consume evq event: {:?}", e);
                    return Err(DeviceError::FailedReadingQueue {
                        event_type: "ev queue event",
                        underlying: e,
                    });
                }
            }
            defs::BACKEND_EVENT => {
                debug!("vsock: backend event");
                self.backend.notify(evset);
                // After the backend has been kicked, it might've freed up some resources, so we
                // can attempt to send it more data to process.
                // In particular, if `self.backend.send_pkt()` halted the TX queue processing (by
                // reurning an error) at some point in the past, now is the time to try walking the
                // TX queue again.
                raise_irq |= self.process_tx();
                if self.backend.has_pending_rx() {
                    raise_irq |= self.process_rx();
                }
            }
            other => {
                return Err(DeviceError::UnknownEvent {
                    device: "vsock",
                    event: other,
                });
            }
        }

        if raise_irq {
            self.signal_used_queue().unwrap_or_default();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::TestContext;
    use super::super::*;
    use super::*;
    use crate::virtio::vsock::defs::{BACKEND_EVENT, EVQ_EVENT, RXQ_EVENT, TXQ_EVENT};
    use crate::virtio::vsock::packet::VSOCK_PKT_HDR_SIZE;

    #[test]
    fn test_irq() {
        // Test case: successful IRQ signaling.
        {
            let test_ctx = TestContext::new();
            let ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.signal_used_queue().unwrap();
            assert_eq!(
                ctx.handler.interrupt_status.load(Ordering::SeqCst),
                VIRTIO_MMIO_INT_VRING as usize
            );
            assert_eq!(ctx.handler.interrupt_evt.read().unwrap(), 1);
        }

        // Test case: error (a real stretch) - the event counter is full.
        //
        {
            let test_ctx = TestContext::new();
            let ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.interrupt_evt.write(std::u64::MAX - 1).unwrap();
            match ctx.handler.signal_used_queue() {
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
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.set_pending_rx(false);
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
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.set_pending_rx(true);
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
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.set_pending_rx(false);
            ctx.handler.backend.set_tx_err(Some(VsockError::NoData));
            ctx.signal_txq_event();

            // Both RX and TX queues should be untouched.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 0);
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }

        // Test case:
        // - the driver supplied a malformed TX buffer.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            // Invalidate the packet header descriptor, by setting its length to 0.
            ctx.guest_txvq.dtable[0].len.set(0);
            ctx.signal_txq_event();

            // The available descriptor should have been consumed, but no packet should have
            // reached the backend.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            assert_eq!(ctx.handler.backend.tx_ok_cnt, 0);
        }

        // Test case: spurious TXQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            match ctx.handler.handle_event(TXQ_EVENT, epoll::Events::EPOLLIN) {
                Err(DeviceError::FailedReadingQueue { .. }) => (),
                other => panic!("{:?}", other),
            }
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
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.set_pending_rx(true);
            ctx.handler.backend.set_rx_err(Some(VsockError::NoData));
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
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.set_pending_rx(true);
            ctx.signal_rxq_event();

            // The available RX buffer should have been used.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
        }

        // Test case: the driver provided a malformed RX descriptor chain.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            // Invalidate the packet header descriptor, by setting its length to 0.
            ctx.guest_rxvq.dtable[0].len.set(0);

            // The chain should've been processed, without employing the backend.
            assert_eq!(ctx.handler.process_rx(), true);
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
            assert_eq!(ctx.handler.backend.rx_ok_cnt, 0);
        }

        // Test case: spurious RXQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();
            ctx.handler.backend.set_pending_rx(false);
            match ctx.handler.handle_event(RXQ_EVENT, epoll::Events::EPOLLIN) {
                Err(DeviceError::FailedReadingQueue { .. }) => (),
                other => panic!("{:?}", other),
            }
        }
    }

    #[test]
    fn test_evq_event() {
        // Test case: spurious EVQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();
            ctx.handler.backend.set_pending_rx(false);
            match ctx.handler.handle_event(EVQ_EVENT, epoll::Events::EPOLLIN) {
                Err(DeviceError::FailedReadingQueue { .. }) => (),
                other => panic!("{:?}", other),
            }
        }
    }

    #[test]
    fn test_backend_event() {
        // Test case:
        // - a backend event is received; and
        // - the backend has pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.set_pending_rx(true);
            ctx.handler
                .handle_event(BACKEND_EVENT, epoll::Events::EPOLLIN)
                .unwrap();

            // The backend should've received this event.
            assert_eq!(ctx.handler.backend.evset, Some(epoll::Events::EPOLLIN));
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
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.set_pending_rx(false);
            ctx.handler
                .handle_event(BACKEND_EVENT, epoll::Events::EPOLLIN)
                .unwrap();

            // The backend should've received this event.
            assert_eq!(ctx.handler.backend.evset, Some(epoll::Events::EPOLLIN));
            // TX queue processing should've been triggered.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            // The RX queue should've been left untouched.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }
    }

    #[test]
    fn test_unknown_event() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_epoll_handler_context();

        match ctx.handler.handle_event(0xff, epoll::Events::EPOLLIN) {
            Err(DeviceError::UnknownEvent { .. }) => (),
            other => panic!("{:?}", other),
        }
    }

    // Creates an epoll handler context and attempts to assemble a VsockPkt from the descriptor
    // chains available on the rx and tx virtqueues, but first it will set the addr and len
    // of the descriptor specified by desc_idx to the provided values. We are only using this
    // function for testing error cases, so the asserts always expect is_err() to be true. When
    // desc_idx = 0 we are altering the header (first descriptor in the chain), and when
    // desc_idx = 1 we are altering the packet buffer.
    fn vsock_bof_helper(test_ctx: &mut TestContext, desc_idx: usize, addr: u64, len: u32) {
        use memory_model::GuestAddress;

        assert!(desc_idx <= 1);

        {
            let mut ctx = test_ctx.create_epoll_handler_context();
            ctx.guest_rxvq.dtable[desc_idx].addr.set(addr);
            ctx.guest_rxvq.dtable[desc_idx].len.set(len);
            // If the descriptor chain is already declared invalid, there's no reason to assemble
            // a packet.
            if let Some(rx_desc) = ctx.handler.rxvq.pop(&test_ctx.mem) {
                assert!(VsockPacket::from_rx_virtq_head(&rx_desc).is_err());
            }
        }

        {
            let mut ctx = test_ctx.create_epoll_handler_context();

            // When modifiyng the buffer descriptor, make sure the len field is altered in the
            // vsock packet header descriptor as well.
            if desc_idx == 1 {
                // The vsock packet len field has offset 24 in the header.
                let hdr_len_addr = GuestAddress(ctx.guest_txvq.dtable[0].addr.get() + 24);
                test_ctx
                    .mem
                    .write_obj_at_addr(len.to_le_bytes(), hdr_len_addr)
                    .unwrap();
            }

            ctx.guest_txvq.dtable[desc_idx].addr.set(addr);
            ctx.guest_txvq.dtable[desc_idx].len.set(len);

            if let Some(tx_desc) = ctx.handler.txvq.pop(&test_ctx.mem) {
                assert!(VsockPacket::from_tx_virtq_head(&tx_desc).is_err());
            }
        }
    }

    #[test]
    fn test_vsock_bof() {
        use memory_model::GuestAddress;

        const GAP_SIZE: usize = 768 << 20;
        const FIRST_AFTER_GAP: usize = 1 << 32;
        const GAP_START_ADDR: usize = FIRST_AFTER_GAP - GAP_SIZE;
        const MIB: usize = 1 << 20;

        let mut test_ctx = TestContext::new();
        test_ctx.mem = GuestMemory::new(&[
            (GuestAddress(0), 8 * MIB),
            (GuestAddress((GAP_START_ADDR - MIB) as u64), MIB),
            (GuestAddress(FIRST_AFTER_GAP as u64), MIB),
        ])
        .unwrap();

        // The default configured descriptor chains are valid.
        {
            let mut ctx = test_ctx.create_epoll_handler_context();
            let rx_desc = ctx.handler.rxvq.pop(&test_ctx.mem).unwrap();
            assert!(VsockPacket::from_rx_virtq_head(&rx_desc).is_ok());
        }

        {
            let mut ctx = test_ctx.create_epoll_handler_context();
            let tx_desc = ctx.handler.txvq.pop(&test_ctx.mem).unwrap();
            assert!(VsockPacket::from_tx_virtq_head(&tx_desc).is_ok());
        }

        // Let's check what happens when the header descriptor is right before the gap.
        vsock_bof_helper(
            &mut test_ctx,
            0,
            GAP_START_ADDR as u64 - 1,
            VSOCK_PKT_HDR_SIZE as u32,
        );

        // Let's check what happens when the buffer descriptor crosses into the gap, but does
        // not go past its right edge.
        vsock_bof_helper(
            &mut test_ctx,
            1,
            GAP_START_ADDR as u64 - 4,
            GAP_SIZE as u32 + 4,
        );

        // Let's modify the buffer descriptor addr and len such that it crosses over the MMIO gap,
        // and check we cannot assemble the VsockPkts.
        vsock_bof_helper(
            &mut test_ctx,
            1,
            GAP_START_ADDR as u64 - 4,
            GAP_SIZE as u32 + 100,
        );
    }
}
