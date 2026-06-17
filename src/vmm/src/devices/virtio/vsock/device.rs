// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! This is the `VirtioDevice` implementation for our vsock device. It handles the virtio-level
//! device logic: feature negotiation, device configuration, and device activation.
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
use std::ops::Deref;
use std::sync::Arc;

use vmm_sys_util::eventfd::EventFd;

use super::super::super::DeviceError;
use super::defs::uapi;
use super::packet::{VSOCK_PKT_HDR_SIZE, VsockPacketRx, VsockPacketTx};
use super::{VsockBackend, defs};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::{VIRTIO_F_IN_ORDER, VIRTIO_F_VERSION_1};
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::{InvalidAvailIdx, Queue as VirtQueue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::vsock::VsockError;
use crate::devices::virtio::vsock::metrics::{METRICS, VsockDeviceMetrics};
use crate::impl_device_type;
use crate::logger::{IncMetric, error, info, warn};
use crate::utils::byte_order;
use crate::vstate::memory::{ByteValued, Bytes, GuestMemoryMmap};

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;
pub(crate) const EVQ_INDEX: usize = 2;

pub(crate) const VIRTIO_VSOCK_EVENT_TRANSPORT_RESET: u32 = 0;

/// The virtio features supported by our vsock device:
/// - VIRTIO_F_VERSION_1: the device conforms to at least version 1.0 of the VirtIO spec.
/// - VIRTIO_F_IN_ORDER: the device returns used buffers in the same order that the driver makes
///   them available.
/// - VIRTIO_RING_F_EVENT_IDX: the device supports used_event/avail_event notification
///   suppression.
pub(crate) const AVAIL_FEATURES: u64 = (1 << VIRTIO_F_VERSION_1 as u64)
    | (1 << VIRTIO_F_IN_ORDER as u64)
    | (1 << VIRTIO_RING_F_EVENT_IDX as u64);

/// Structure representing the vsock device.
#[derive(Debug)]
pub struct Vsock<B> {
    cid: u64,
    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,
    pub(crate) backend: B,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    // This EventFd is the only one initially registered for a vsock device, and is used to convert
    // a VirtioDevice::activate call into an EventHandler read event which allows the other events
    // (queue and backend related) to be registered post virtio device activation. That's
    // mostly something we wanted to happen for the backend events, to prevent (potentially)
    // continuous triggers from happening before the device gets activated.
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    pub(crate) metrics: Arc<VsockDeviceMetrics>,

    pub rx_packet: VsockPacketRx,
    pub tx_packet: VsockPacketTx,

    /// Gates RX delivery while a TRANSPORT_RESET is awaiting guest ack.
    pub(crate) pending_event_ack: bool,
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
        metrics: Option<Arc<VsockDeviceMetrics>>,
    ) -> Result<Vsock<B>, VsockError> {
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events.push(EventFd::new(libc::EFD_NONBLOCK).map_err(VsockError::EventFd)?);
        }
        // the metrics instance may be supplied from the vsock backend (muxer)
        // or if the vsock struct is being initialized in a test let it create its
        // own metrics instance
        let metrics_instance = metrics.unwrap_or_else(|| {
            let metrics = Arc::new(VsockDeviceMetrics::default());
            _ = METRICS.write().unwrap().insert(cid, metrics.clone());
            metrics
        });

        Ok(Vsock {
            cid,
            queues,
            queue_events,
            backend,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VsockError::EventFd)?,
            device_state: DeviceState::Inactive,
            rx_packet: VsockPacketRx::new()?,
            tx_packet: VsockPacketTx::default(),
            pending_event_ack: false,
            metrics: metrics_instance,
        })
    }

    /// Create a new virtio-vsock device with the given VM CID and vsock backend.
    pub fn new(
        cid: u64,
        backend: B,
        metrics: Option<Arc<VsockDeviceMetrics>>,
    ) -> Result<Vsock<B>, VsockError> {
        let queues: Vec<VirtQueue> = defs::VSOCK_QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(cid, backend, queues, metrics)
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
    pub fn signal_used_queue(&self, qidx: usize) -> Result<(), DeviceError> {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .trigger(VirtioInterruptType::Queue(qidx.try_into().unwrap_or_else(
                |_| panic!("vsock: invalid queue index: {qidx}"),
            )))
            .map_err(DeviceError::FailedSignalingIrq)
    }

    /// Signal the guest which queues are ready to be consumed
    pub fn signal_used_queues(&self, used_queues: &[u16]) -> Result<(), DeviceError> {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .trigger_queues(used_queues)
            .map_err(DeviceError::FailedSignalingIrq)
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if the guest needs to be notified (respecting notification
    /// suppression).
    pub fn process_rx(&mut self) -> Result<bool, InvalidAvailIdx> {
        if self.pending_event_ack {
            return Ok(false);
        }

        // This is safe since we checked in the event handler that the device is activated.
        let mem = &self.device_state.active_state().unwrap().mem;

        let queue = &mut self.queues[RXQ_INDEX];
        let mut have_used = false;

        while let Some(head) = queue.pop_or_enable_notification()? {
            let index = head.index;
            let used_len = match self.rx_packet.parse(mem, head) {
                Ok(()) => {
                    if self.backend.recv_pkt(&mut self.rx_packet).is_ok() {
                        match self.rx_packet.commit_hdr() {
                            // This addition cannot overflow, because packet length
                            // is previously validated against `MAX_PKT_BUF_SIZE`
                            // bound as part of `commit_hdr()`.
                            Ok(()) => VSOCK_PKT_HDR_SIZE + self.rx_packet.hdr.len(),
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
                        queue.undo_pop();
                        break;
                    }
                }
                Err(err) => {
                    warn!("vsock: RX queue error: {:?}. Discarding the package.", err);
                    0
                }
            };

            have_used = true;
            queue.add_used(index, used_len).unwrap_or_else(|err| {
                error!("Failed to add available descriptor {}: {}", index, err)
            });
        }
        queue.advance_used_ring_idx();

        Ok(have_used && queue.prepare_kick())
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and send them
    /// to the backend for processing. Return `true` if the guest needs to be notified (respecting
    /// notification suppression).
    pub fn process_tx(&mut self) -> Result<bool, InvalidAvailIdx> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = &self.device_state.active_state().unwrap().mem;

        let queue = &mut self.queues[TXQ_INDEX];
        let mut have_used = false;

        while let Some(head) = queue.pop_or_enable_notification()? {
            let index = head.index;
            match self.tx_packet.parse(mem, head) {
                Ok(()) => (),
                Err(err) => {
                    error!("vsock: error reading TX packet: {:?}", err);
                    have_used = true;
                    queue.add_used(index, 0).unwrap_or_else(|err| {
                        error!("Failed to add available descriptor {}: {}", index, err);
                    });
                    continue;
                }
            };

            self.backend.send_pkt(&self.tx_packet);

            have_used = true;
            queue.add_used(index, 0).unwrap_or_else(|err| {
                error!("Failed to add available descriptor {}: {}", index, err);
            });
        }
        queue.advance_used_ring_idx();

        Ok(have_used && queue.prepare_kick())
    }

    // Send TRANSPORT_RESET_EVENT to driver. According to specs, the driver shuts down established
    // connections and the guest_cid configuration field is fetched again. Existing listen sockets
    // remain but their CID is updated to reflect the current guest_cid.
    pub fn send_transport_reset_event(&mut self) -> Result<(), DeviceError> {
        // This is safe since we checked in the caller function that the device is activated.
        let mem = &self.device_state.active_state().unwrap().mem;

        let queue = &mut self.queues[EVQ_INDEX];
        let head = queue.pop()?.ok_or_else(|| {
            self.metrics.ev_queue_event_fails.inc();
            DeviceError::VsockError(VsockError::EmptyQueue)
        })?;

        mem.write_obj::<u32>(VIRTIO_VSOCK_EVENT_TRANSPORT_RESET, head.addr)
            .unwrap_or_else(|err| error!("Failed to write virtio vsock reset event: {:?}", err));

        queue.add_used(head.index, head.len).unwrap_or_else(|err| {
            error!("Failed to add used descriptor {}: {}", head.index, err);
        });
        queue.advance_used_ring_idx();

        // The evq is only popped here, not via a drain loop, so
        // `avail_event` is not advanced by `pop_or_enable_notification`.
        // Arm it so the driver's refill of the consumed head is not
        // suppressed by EVENT_IDX.
        queue.enable_notification();

        self.pending_event_ack = true;

        // NOTE: kick() will be called on resume and it will trigger the interrupt again. As calling
        // it multiple times should not cause any harm, it would be safer to call it here as well
        // as part of the sequence of actions that signal the reset event, prior to saving the
        // transport state.
        self.signal_used_queue(EVQ_INDEX)?;

        Ok(())
    }
}

impl<B> VirtioDevice for Vsock<B>
where
    B: VsockBackend + Debug + 'static,
{
    impl_device_type!(VirtioDeviceType::Vsock);

    fn id(&self) -> &str {
        defs::VSOCK_DEV_ID
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
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

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .deref()
    }

    fn config_as_bytes(&self) -> &[u8] {
        // ByteValued::as_slice() gives native-endian bytes. Firecracker only
        // targets little-endian platforms, matching virtio's LE config space;
        // the static assert below makes a big-endian target a compile error
        // rather than a silent mis-serialization.
        const _: () = assert!(
            cfg!(target_endian = "little"),
            "virtio config requires a little-endian target"
        );
        self.cid.as_slice()
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.metrics.cfg_fails.inc();
        warn!(
            "vsock: guest driver attempted to write device config (offset={:#x}, len={:#x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        assert!(!self.is_activated());

        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        if self.queues.len() != defs::VSOCK_NUM_QUEUES {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::QueueMismatch {
                expected: defs::VSOCK_NUM_QUEUES,
                got: self.queues.len(),
            });
        }

        if self.has_feature(VIRTIO_RING_F_EVENT_IDX as u64) {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        self.backend.activate().map_err(|err| {
            self.metrics.activate_fails.inc();
            ActivateError::VsockBackend(err)
        })?;

        if self.activate_evt.write(1).is_err() {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }

        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn deactivate(&mut self) {
        self.device_state = DeviceState::Inactive;
    }

    fn _reset(&mut self) -> bool {
        self.backend.reset();
        self.rx_packet.clear();
        self.tx_packet.clear();
        self.pending_event_ack = false;
        true
    }

    fn kick(&mut self) {
        if self.is_activated() {
            self.pending_event_ack = true;

            // Vsock has a complicated protocol that isn't resilient to any packet loss,
            // so for Vsock we don't support connection persistence through snapshot. Any
            // in-flight packets or events are simply lost and Vsock is restored 'empty'.
            // We signal the event queue to make the guest process the
            // `TRANSPORT_RESET_EVENT` event we sent during snapshot creation. (We signal
            // it host->guest rather than writing its eventfd, which would invoke the
            // guest's reset-ack path and clear `pending_event_ack` prematurely.)
            info!(
                "[{:?}:{}] signaling event queue",
                self.device_type(),
                self.id()
            );
            self.signal_used_queue(EVQ_INDEX).unwrap();

            // Replay the TX queue notification, like the default `VirtioDevice::kick`
            // does for its data queues, so the device re-processes any TX descriptor
            // that was in-flight at snapshot time and re-arms `avail_event`.
            //
            // Without this, `avail_idx` stays ahead of the `avail_event` we published.
            // Under EVENT_IDX the guest only notifies us when `avail_idx` crosses
            // `avail_event`; since it is already past, the guest considers itself to
            // have notified us and stays silent, so we never process the queue and
            // guest-to-host connections hang. RX needs no replay: it is gated by
            // `pending_event_ack` until the guest acks the reset, and the host pulls
            // from the backend rather than waiting on a guest RX notification.
            info!(
                "[{:?}:{}] notifying tx queue",
                self.device_type(),
                self.id()
            );
            if let Err(err) = self.queue_events[TXQ_INDEX].write(1) {
                error!(
                    "[{:?}:{}] error notifying tx queue: {}",
                    self.device_type(),
                    self.id(),
                    err
                );
            }
        }
    }

    fn prepare_save(&mut self) {
        // Send Transport event to reset connections if device
        // is activated.
        if self.is_activated() {
            self.send_transport_reset_event().unwrap_or_else(|err| {
                error!("Failed to send reset transport event: {:?}", err);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::epoll::EventSet;

    use super::*;
    use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::devices::virtio::vsock::defs::uapi;
    use crate::devices::virtio::vsock::test_utils::{EventHandlerContext, TestContext};
    use crate::vstate::memory::GuestAddress;

    /// Guest address used for the writable evq descriptor payload in tests.
    const EVQ_PAYLOAD_GUEST_ADDR: u64 = 0x0040_2000;

    /// Publish a single 4-byte writable descriptor on the event virtqueue and reload the
    /// device-side queue so it sees the new avail index. Required by any test that exercises
    /// `send_transport_reset_event` directly.
    fn publish_evq_descriptor(ctx: &mut EventHandlerContext<'_>) {
        ctx.guest_evvq.dtable[0].set(EVQ_PAYLOAD_GUEST_ADDR, 4, VIRTQ_DESC_F_WRITE, 0);
        ctx.guest_evvq.avail.ring[0].set(0);
        ctx.guest_evvq.avail.idx.set(1);
        ctx.device.queues[EVQ_INDEX] = ctx.guest_evvq.create_queue();
    }

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
        assert_eq!(ctx.device.device_type(), VirtioDeviceType::Vsock);
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

        // Validate config_as_bytes returns the CID in little-endian.
        let config = ctx.device.config_as_bytes();
        assert_eq!(config.len(), 8);
        assert_eq!(byte_order::read_le_u64(config), ctx.cid);

        // Just covering lines here, since the vsock device has no writable config.
        // A warning is, however, logged, if the guest driver attempts to write any config data.
        ctx.device.write_config(0, &[0u8; 4]);

        // Test a bad activation.
        // let bad_activate = ctx.device.activate(
        //     ctx.mem.clone(),
        // );
        // match bad_activate {
        //     Err(ActivateError::BadActivate) => (),
        //     other => panic!("{:?}", other),
        // }

        // Test a correct activation.
        ctx.device
            .activate(ctx.mem.clone(), ctx.interrupt.clone())
            .unwrap();
    }

    #[test]
    fn test_send_transport_reset_event_sets_pending_event_ack() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        publish_evq_descriptor(&mut ctx);

        assert!(!ctx.device.pending_event_ack);

        ctx.device.send_transport_reset_event().unwrap();

        assert!(
            ctx.device.pending_event_ack,
            "TRANSPORT_RESET emission must arm the RX gate"
        );
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            1,
            "evq used ring must advance once the event is published"
        );

        // The 4-byte payload must be VIRTIO_VSOCK_EVENT_TRANSPORT_RESET (== 0).
        let mut buf = [0xffu8; 4];
        test_ctx
            .mem
            .read_slice(&mut buf, GuestAddress(EVQ_PAYLOAD_GUEST_ADDR))
            .unwrap();
        assert_eq!(u32::from_le_bytes(buf), VIRTIO_VSOCK_EVENT_TRANSPORT_RESET);
    }

    #[test]
    fn test_send_transport_reset_event_empty_queue() {
        // No available descriptors on the evq -> the device cannot publish the event.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        let err = ctx.device.send_transport_reset_event().unwrap_err();
        match err {
            DeviceError::VsockError(VsockError::EmptyQueue) => (),
            other => panic!("unexpected error variant: {other:?}"),
        }
        assert!(
            !ctx.device.pending_event_ack,
            "flag must not be armed if the event was never published"
        );
    }

    #[test]
    fn test_kick_when_inactive_is_a_noop() {
        // The fix runs `kick()` only when activated. The inactive branch must not arm
        // the RX gate, otherwise a freshly restored-but-unactivated device would refuse
        // RX forever.
        let mut ctx = TestContext::new();
        assert!(!ctx.device.is_activated());

        ctx.device.kick();

        assert!(
            !ctx.device.pending_event_ack,
            "kick() on an inactive device must remain a no-op"
        );
    }

    #[test]
    fn test_kick_when_active_arms_pending_event_ack() {
        // Restore path: kick() is invoked after the snapshot is loaded to re-deliver the
        // TRANSPORT_RESET interrupt. It must arm the RX gate so the post-restore RX/EVQ
        // race cannot deliver data ahead of the guest ack.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.pending_event_ack = false;
        ctx.device.kick();

        assert!(
            ctx.device.pending_event_ack,
            "kick() on an active device must arm the RX gate"
        );

        // After kick(), the gate must actually suppress RX delivery.
        ctx.device.backend.set_pending_rx(true);
        let progressed = ctx.device.process_rx().unwrap();
        assert!(!progressed);
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
    }

    #[test]
    fn test_kick_replays_tx_notification_only() {
        // On restore, kick() must replay only the TX data queue (to re-process in-flight
        // TX and re-arm avail_event). RX is gated by pending_event_ack so it needs no
        // replay, and the event queue's data eventfd must not be notified -- that is the
        // guest's TRANSPORT_RESET ack path; the event queue is signaled host->guest.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.kick();

        // TX queue eventfd was replayed for re-processing.
        assert_eq!(ctx.device.queue_events[TXQ_INDEX].read().unwrap(), 1);
        // RX and the event queue's data eventfd must not be signaled by kick()
        // (non-blocking read returns an error when the eventfd has no pending count).
        ctx.device.queue_events[RXQ_INDEX].read().unwrap_err();
        ctx.device.queue_events[EVQ_INDEX].read().unwrap_err();
    }

    #[test]
    fn test_prepare_save_emits_transport_reset_when_active() {
        // The snapshot path goes through prepare_save -> send_transport_reset_event.
        // Both the evq publication and the RX gate must be observable afterwards.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        publish_evq_descriptor(&mut ctx);

        ctx.device.prepare_save();

        assert!(ctx.device.pending_event_ack);
        assert_eq!(ctx.guest_evvq.used.idx.get(), 1);
    }

    #[test]
    fn test_prepare_save_inactive_is_a_noop() {
        let mut ctx = TestContext::new();
        assert!(!ctx.device.is_activated());

        // Must not panic, must not arm the gate.
        ctx.device.prepare_save();

        assert!(!ctx.device.pending_event_ack);
    }

    #[test]
    fn test_pending_event_ack_default_is_false() {
        let ctx = TestContext::new();
        assert!(
            !ctx.device.pending_event_ack,
            "freshly created device must have the RX gate disarmed"
        );
    }

    #[test]
    fn test_evq_event_with_non_in_evset_is_a_noop() {
        // Spurious evset flavours must not flip the gate or drain the RX queue.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.pending_event_ack = true;
        ctx.device.backend.set_pending_rx(true);

        let used = ctx.device.handle_evq_event(EventSet::OUT);

        assert!(used.is_empty());
        assert!(
            ctx.device.pending_event_ack,
            "non-IN evset must not clear the gate"
        );
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
    }
}
