// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! This is the `VirtioDevice` implementation for our vsock device. It handles the virtio-level
//! device logic: feature negociation, device configuration, and device activation.
//!
//! We aim to conform to the VirtIO v1.1 spec:
//! https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html
//!
//! The vsock device has two input parameters: a CID to identify the device, and a
//! `VsockBackend` to use for offloading vsock traffic.
//!
//! Upon its activation, the vsock device registers handlers for the following events/FDs:
//! - an RX queue FD;
//! - a TX queue FD;
//! - an event queue FD; and
//! - a backend FD.

use std::fmt::Debug;

use log::{error, warn};
use utils::byte_order;
use utils::eventfd::EventFd;

use super::super::super::DeviceError;
use super::defs::uapi;
use super::packet::{VsockPacket, VSOCK_PKT_HDR_SIZE};
use super::{defs, VsockBackend};
use crate::devices::virtio::device::{DeviceState, IrqTrigger, IrqType, VirtioDevice};
use crate::devices::virtio::queue::Queue as VirtQueue;
use crate::devices::virtio::vsock::metrics::METRICS;
use crate::devices::virtio::vsock::VsockError;
use crate::devices::virtio::ActivateError;
use crate::logger::IncMetric;
use crate::vstate::memory::{Bytes, GuestMemoryMmap};

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;
pub(crate) const EVQ_INDEX: usize = 2;

pub(crate) const VIRTIO_VSOCK_EVENT_TRANSPORT_RESET: u32 = 0;

/// The virtio features supported by our vsock device:
/// - VIRTIO_F_VERSION_1: the device conforms to at least version 1.0 of the VirtIO spec.
/// - VIRTIO_F_IN_ORDER: the device returns used buffers in the same order that the driver makes
///   them available.
pub(crate) const AVAIL_FEATURES: u64 =
    1 << uapi::VIRTIO_F_VERSION_1 as u64 | 1 << uapi::VIRTIO_F_IN_ORDER as u64;

/// Structure representing the vsock device.
#[derive(Debug)]
pub struct Vsock<B> {
    cid: u64,
    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,
    pub(crate) backend: B,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) irq_trigger: IrqTrigger,
    // This EventFd is the only one initially registered for a vsock device, and is used to convert
    // a VirtioDevice::activate call into an EventHandler read event which allows the other events
    // (queue and backend related) to be registered post virtio device activation. That's
    // mostly something we wanted to happen for the backend events, to prevent (potentially)
    // continuous triggers from happening before the device gets activated.
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
}

// TODO: Detect / handle queue deadlock:
// 1. If the driver halts RX queue processing, we'll need to notify `self.backend`, so that it can
//    unregister any EPOLLIN listeners, since otherwise it will keep spinning, unable to consume its
//    EPOLLIN events.

impl<B> Vsock<B>
where
    B: VsockBackend + Debug,
{
    /// Auxiliary function for creating a new virtio-vsock device with the given VM CID, vsock
    /// backend and empty virtio queues.
    pub fn with_queues(
        cid: u64,
        backend: B,
        queues: Vec<VirtQueue>,
    ) -> Result<Vsock<B>, VsockError> {
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events.push(EventFd::new(libc::EFD_NONBLOCK).map_err(VsockError::EventFd)?);
        }

        Ok(Vsock {
            cid,
            queues,
            queue_events,
            backend,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            irq_trigger: IrqTrigger::new().map_err(VsockError::EventFd)?,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VsockError::EventFd)?,
            device_state: DeviceState::Inactive,
        })
    }

    /// Create a new virtio-vsock device with the given VM CID and vsock backend.
    pub fn new(cid: u64, backend: B) -> Result<Vsock<B>, VsockError> {
        let queues: Vec<VirtQueue> = defs::VSOCK_QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(cid, backend, queues)
    }

    /// Provides the ID of this vsock device as used in MMIO device identification.
    pub fn id(&self) -> &str {
        defs::VSOCK_DEV_ID
    }

    /// Retrieve the cid associated with this vsock device.
    pub fn cid(&self) -> u64 {
        self.cid
    }

    /// Access the backend behind the device.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Signal the guest driver that we've used some virtio buffers that it had previously made
    /// available.
    pub fn signal_used_queue(&self) -> Result<(), DeviceError> {
        self.irq_trigger
            .trigger_irq(IrqType::Vring)
            .map_err(DeviceError::FailedSignalingIrq)
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if descriptors have been added to the used ring, and `false`
    /// otherwise.
    pub fn process_rx(&mut self) -> bool {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();

        let mut have_used = false;

        while let Some(head) = self.queues[RXQ_INDEX].pop(mem) {
            let index = head.index;
            let used_len = match VsockPacket::from_rx_virtq_head(head) {
                Ok(mut pkt) => {
                    if self.backend.recv_pkt(&mut pkt).is_ok() {
                        match pkt.commit_hdr() {
                            // This addition cannot overflow, because packet length
                            // is previously validated against `MAX_PKT_BUF_SIZE`
                            // bound as part of `commit_hdr()`.
                            Ok(()) => VSOCK_PKT_HDR_SIZE + pkt.len(),
                            Err(err) => {
                                warn!(
                                    "vsock: Error writing packet header to guest memory: \
                                     {:?}.Discarding the package.",
                                    err
                                );
                                0
                            }
                        }
                    } else {
                        // We are using a consuming iterator over the virtio buffers, so, if we
                        // can't fill in this buffer, we'll need to undo the
                        // last iterator step.
                        self.queues[RXQ_INDEX].undo_pop();
                        break;
                    }
                }
                Err(err) => {
                    warn!("vsock: RX queue error: {:?}. Discarding the package.", err);
                    0
                }
            };

            have_used = true;
            self.queues[RXQ_INDEX]
                .add_used(mem, index, used_len)
                .unwrap_or_else(|err| {
                    error!("Failed to add available descriptor {}: {}", index, err)
                });
        }

        have_used
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and send them
    /// to the backend for processing. Return `true` if descriptors have been added to the used
    /// ring, and `false` otherwise.
    pub fn process_tx(&mut self) -> bool {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();

        let mut have_used = false;

        while let Some(head) = self.queues[TXQ_INDEX].pop(mem) {
            let index = head.index;
            let pkt = match VsockPacket::from_tx_virtq_head(head) {
                Ok(pkt) => pkt,
                Err(err) => {
                    error!("vsock: error reading TX packet: {:?}", err);
                    have_used = true;
                    self.queues[TXQ_INDEX]
                        .add_used(mem, index, 0)
                        .unwrap_or_else(|err| {
                            error!("Failed to add available descriptor {}: {}", index, err);
                        });
                    continue;
                }
            };

            if self.backend.send_pkt(&pkt).is_err() {
                self.queues[TXQ_INDEX].undo_pop();
                break;
            }

            have_used = true;
            self.queues[TXQ_INDEX]
                .add_used(mem, index, 0)
                .unwrap_or_else(|err| {
                    error!("Failed to add available descriptor {}: {}", index, err);
                });
        }

        have_used
    }

    // Send TRANSPORT_RESET_EVENT to driver. According to specs, the driver shuts down established
    // connections and the guest_cid configuration field is fetched again. Existing listen sockets
    // remain but their CID is updated to reflect the current guest_cid.
    pub fn send_transport_reset_event(&mut self) -> Result<(), DeviceError> {
        // This is safe since we checked in the caller function that the device is activated.
        let mem = self.device_state.mem().unwrap();

        let head = self.queues[EVQ_INDEX].pop(mem).ok_or_else(|| {
            METRICS.ev_queue_event_fails.inc();
            DeviceError::VsockError(VsockError::EmptyQueue)
        })?;

        mem.write_obj::<u32>(VIRTIO_VSOCK_EVENT_TRANSPORT_RESET, head.addr)
            .unwrap_or_else(|err| error!("Failed to write virtio vsock reset event: {:?}", err));

        self.queues[EVQ_INDEX]
            .add_used(mem, head.index, head.len)
            .unwrap_or_else(|err| {
                error!("Failed to add used descriptor {}: {}", head.index, err);
            });

        self.signal_used_queue()?;

        Ok(())
    }
}

impl<B> VirtioDevice for Vsock<B>
where
    B: VsockBackend + Debug + 'static,
{
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_VSOCK
    }

    fn queues(&self) -> &[VirtQueue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [VirtQueue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_trigger(&self) -> &IrqTrigger {
        &self.irq_trigger
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => byte_order::write_le_u64(data, self.cid()),
            0 if data.len() == 4 => {
                byte_order::write_le_u32(data, (self.cid() & 0xffff_ffff) as u32)
            }
            4 if data.len() == 4 => {
                byte_order::write_le_u32(data, ((self.cid() >> 32) & 0xffff_ffff) as u32)
            }
            _ => {
                METRICS.cfg_fails.inc();
                warn!(
                    "vsock: virtio-vsock received invalid read request of {} bytes at offset {}",
                    data.len(),
                    offset
                )
            }
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        METRICS.cfg_fails.inc();
        warn!(
            "vsock: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError> {
        if self.queues.len() != defs::VSOCK_NUM_QUEUES {
            METRICS.activate_fails.inc();
            return Err(ActivateError::QueueMismatch {
                expected: defs::VSOCK_NUM_QUEUES,
                got: self.queues.len(),
            });
        }

        if self.activate_evt.write(1).is_err() {
            METRICS.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }

        self.device_state = DeviceState::Activated(mem);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::vsock::defs::uapi;
    use crate::devices::virtio::vsock::test_utils::TestContext;

    #[test]
    fn test_virtio_device() {
        let mut ctx = TestContext::new();
        let device_features = AVAIL_FEATURES;
        let driver_features: u64 = AVAIL_FEATURES | 1 | (1 << 32);
        let device_pages = [
            (device_features & 0xffff_ffff) as u32,
            (device_features >> 32) as u32,
        ];
        let driver_pages = [
            (driver_features & 0xffff_ffff) as u32,
            (driver_features >> 32) as u32,
        ];
        assert_eq!(ctx.device.device_type(), uapi::VIRTIO_ID_VSOCK);
        assert_eq!(ctx.device.avail_features_by_page(0), device_pages[0]);
        assert_eq!(ctx.device.avail_features_by_page(1), device_pages[1]);
        assert_eq!(ctx.device.avail_features_by_page(2), 0);

        // Ack device features, page 0.
        ctx.device.ack_features_by_page(0, driver_pages[0]);
        // Ack device features, page 1.
        ctx.device.ack_features_by_page(1, driver_pages[1]);
        // Ack some bogus page (i.e. 2). This should have no side effect.
        ctx.device.ack_features_by_page(2, 0);
        // Attempt to un-ack the first feature page. This should have no side effect.
        ctx.device.ack_features_by_page(0, !driver_pages[0]);
        // Check that no side effect are present, and that the acked features are exactly the same
        // as the device features.
        assert_eq!(ctx.device.acked_features, device_features & driver_features);

        // Test reading 32-bit chunks.
        let mut data = [0u8; 8];
        ctx.device.read_config(0, &mut data[..4]);
        assert_eq!(
            u64::from(byte_order::read_le_u32(&data[..])),
            ctx.cid & 0xffff_ffff
        );
        ctx.device.read_config(4, &mut data[4..]);
        assert_eq!(
            u64::from(byte_order::read_le_u32(&data[4..])),
            (ctx.cid >> 32) & 0xffff_ffff
        );

        // Test reading 64-bit.
        let mut data = [0u8; 8];
        ctx.device.read_config(0, &mut data);
        assert_eq!(byte_order::read_le_u64(&data), ctx.cid);

        // Check that out-of-bounds reading doesn't mutate the destination buffer.
        let mut data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        ctx.device.read_config(2, &mut data);
        assert_eq!(data, [0u8, 1, 2, 3, 4, 5, 6, 7]);

        // Just covering lines here, since the vsock device has no writable config.
        // A warning is, however, logged, if the guest driver attempts to write any config data.
        ctx.device.write_config(0, &data[..4]);

        // Test a bad activation.
        // let bad_activate = ctx.device.activate(
        //     ctx.mem.clone(),
        // );
        // match bad_activate {
        //     Err(ActivateError::BadActivate) => (),
        //     other => panic!("{:?}", other),
        // }

        // Test a correct activation.
        ctx.device.activate(ctx.mem.clone()).unwrap();
    }
}
