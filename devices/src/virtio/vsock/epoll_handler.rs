// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use memory_model::GuestMemory;
use sys_util::EventFd;

use super::super::super::{DeviceEventT, Error as DeviceError};
use super::super::queue::Queue as VirtQueue;
use super::super::VIRTIO_MMIO_INT_VRING;
use super::defs;
use super::{EpollHandler, VsockBackend};

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
    ///
    #[allow(dead_code)]
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
    ///
    fn process_rx(&mut self) {
        error!("vsock: EpollHandler::process_rx() NYI");
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and send them to
    /// the backend for processing.
    ///
    fn process_tx(&mut self) {
        error!("vsock: EpollHandler::process_tx() NYI");
    }
}

impl<B> EpollHandler for VsockEpollHandler<B>
where
    B: VsockBackend,
{
    /// Respond to a new event, coming from the main epoll loop (implemented by the VMM).
    ///
    fn handle_event(
        &mut self,
        device_event: DeviceEventT,
        evset: epoll::Events,
    ) -> result::Result<(), DeviceError> {
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
                    self.process_rx();
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
                    self.process_tx();
                    // The backend may have queued up responses to the packets we sent during TX queue
                    // processing. If that happened, we need to fetch those responses and place them
                    // into RX buffers.
                    if self.backend.has_pending_rx() {
                        self.process_rx();
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
//                if let Some(evset) = epoll::Events::from_bits(evset_bits) {
//                    self.backend.notify(evset);
//                    // This event may have caused some packets to be queued up by the backend.
//                    // Make sure they are processed.
//                    if self.backend.has_pending_rx() {
//                        self.process_rx();
//                    }
//                } else {
//                    warn!("vsock: unexpected backend event flags={:08x}", evset_bits);
//                }
                self.backend.notify(epoll::Events::EPOLLIN);
                if self.backend.has_pending_rx() {
                    self.process_rx();
                }
            }
            other => {
                return Err(DeviceError::UnknownEvent {
                    device: "vsock",
                    event: other,
                });
            }
        }

        Ok(())
    }
}
