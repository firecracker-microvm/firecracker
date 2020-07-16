// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::virtio::net::tap::Tap;
use crate::virtio::net::Error;
use crate::virtio::net::Result;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE, QUEUE_SIZES, RX_INDEX, TX_INDEX};
use crate::virtio::{
    ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_NET, VIRTIO_MMIO_INT_VRING,
};
use crate::{report_net_event_fail, Error as DeviceError};
use dumbo::pdu::ethernet::EthernetFrame;
use dumbo::{MacAddr, MAC_ADDR_LEN};
use libc::EAGAIN;
use logger::{Metric, METRICS};
use mmds::ns::MmdsNetworkStack;
use rate_limiter::{BucketUpdate, RateLimiter, TokenType};
#[cfg(not(test))]
use std::io;
use std::io::{Read, Write};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{cmp, mem, result};
use utils::eventfd::EventFd;
use virtio_gen::virtio_net::{
    virtio_net_hdr_v1, VIRTIO_F_VERSION_1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC,
};
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

// Frames being sent/received through the network device model have a VNET header. This
// function returns a slice which holds the L2 frame bytes without this header.
fn frame_bytes_from_buf(buf: &[u8]) -> Result<&[u8]> {
    if buf.len() < vnet_hdr_len() {
        Err(Error::VnetHeaderMissing)
    } else {
        Ok(&buf[vnet_hdr_len()..])
    }
}

fn frame_bytes_from_buf_mut(buf: &mut [u8]) -> Result<&mut [u8]> {
    if buf.len() < vnet_hdr_len() {
        Err(Error::VnetHeaderMissing)
    } else {
        Ok(&mut buf[vnet_hdr_len()..])
    }
}

// This initializes to all 0 the VNET hdr part of a buf.
fn init_vnet_hdr(buf: &mut [u8]) {
    // The buffer should be larger than vnet_hdr_len.
    // TODO: any better way to set all these bytes to 0? Or is this optimized by the compiler?
    for i in &mut buf[0..vnet_hdr_len()] {
        *i = 0;
    }
}

#[derive(Clone, Copy)]
pub struct ConfigSpace {
    pub guest_mac: [u8; MAC_ADDR_LEN],
}

impl Default for ConfigSpace {
    fn default() -> ConfigSpace {
        ConfigSpace {
            guest_mac: [0; MAC_ADDR_LEN],
        }
    }
}

unsafe impl ByteValued for ConfigSpace {}

pub struct Net {
    pub(crate) id: String,

    pub(crate) tap: Tap,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,

    pub(crate) rx_rate_limiter: RateLimiter,
    pub(crate) tx_rate_limiter: RateLimiter,

    rx_deferred_frame: bool,
    rx_deferred_irqs: bool,

    rx_bytes_read: usize,
    rx_frame_buf: [u8; MAX_BUFFER_SIZE],

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],

    pub(crate) interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,

    pub(crate) config_space: ConfigSpace,
    pub(crate) guest_mac: Option<MacAddr>,

    pub(crate) device_state: DeviceState,
    pub(crate) activate_evt: EventFd,

    pub(crate) mmds_ns: Option<MmdsNetworkStack>,

    #[cfg(test)]
    mocks: tests::Mocks,
}

impl Net {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(
        id: String,
        tap_if_name: String,
        guest_mac: Option<&MacAddr>,
        rx_rate_limiter: RateLimiter,
        tx_rate_limiter: RateLimiter,
        allow_mmds_requests: bool,
    ) -> Result<Self> {
        let tap = Tap::open_named(&tap_if_name).map_err(Error::TapOpen)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_gen::TUN_F_CSUM | net_gen::TUN_F_UFO | net_gen::TUN_F_TSO4 | net_gen::TUN_F_TSO6,
        )
        .map_err(Error::TapSetOffload)?;

        let vnet_hdr_size = vnet_hdr_len() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(Error::TapSetVnetHdrSize)?;

        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        let mut config_space = ConfigSpace::default();
        if let Some(mac) = guest_mac {
            config_space.guest_mac.copy_from_slice(mac.get_bytes());
            // When this feature isn't available, the driver generates a random MAC address.
            // Otherwise, it should attempt to read the device MAC address from the config space.
            avail_features |= 1 << VIRTIO_NET_F_MAC;
        }

        let mut queue_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
        }

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let mmds_ns = if allow_mmds_requests {
            Some(MmdsNetworkStack::new_with_defaults(None))
        } else {
            None
        };
        Ok(Net {
            id,
            tap,
            avail_features,
            acked_features: 0u64,
            queues,
            queue_evts,
            rx_rate_limiter,
            tx_rate_limiter,
            rx_deferred_frame: false,
            rx_deferred_irqs: false,
            rx_bytes_read: 0,
            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            config_space,
            mmds_ns,
            guest_mac: guest_mac.copied(),

            #[cfg(test)]
            mocks: tests::Mocks::default(),
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the MAC of this net device.
    pub fn guest_mac(&self) -> Option<&MacAddr> {
        self.guest_mac.as_ref()
    }

    /// Provides a mutable reference to the `MmdsNetworkStack`.
    pub fn mmds_ns_mut(&mut self) -> Option<&mut MmdsNetworkStack> {
        self.mmds_ns.as_mut()
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            METRICS.net.event_fails.inc();
            DeviceError::FailedSignalingUsedQueue(e)
        })
    }

    // Attempts to copy a single frame into the guest if there is enough
    // rate limiting budget.
    // Returns true on successful frame delivery.
    fn rate_limited_rx_single_frame(&mut self) -> bool {
        // If limiter.consume() fails it means there is no more TokenType::Ops
        // budget and rate limiting is in effect.
        if !self.rx_rate_limiter.consume(1, TokenType::Ops) {
            METRICS.net.rx_rate_limiter_throttled.inc();
            return false;
        }
        // If limiter.consume() fails it means there is no more TokenType::Bytes
        // budget and rate limiting is in effect.
        if !self
            .rx_rate_limiter
            .consume(self.rx_bytes_read as u64, TokenType::Bytes)
        {
            // revert the OPS consume()
            self.rx_rate_limiter.manual_replenish(1, TokenType::Ops);
            METRICS.net.rx_rate_limiter_throttled.inc();
            return false;
        }

        // Attempt frame delivery.
        let success = self.rx_single_frame();

        // Undo the tokens consumption if guest delivery failed.
        if !success {
            // revert the OPS consume()
            self.rx_rate_limiter.manual_replenish(1, TokenType::Ops);
            // revert the BYTES consume()
            self.rx_rate_limiter
                .manual_replenish(self.rx_bytes_read as u64, TokenType::Bytes);
        }
        success
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        let rx_queue = &mut self.queues[RX_INDEX];
        let mut next_desc = rx_queue.pop(mem);
        if next_desc.is_none() {
            METRICS.net.no_rx_avail_buffer.inc();
            return false;
        }

        // We just checked that the head descriptor exists.
        let head_index = next_desc.as_ref().unwrap().index;
        let mut write_count = 0;

        // Copy from frame into buffer, which may span multiple descriptors.
        loop {
            match next_desc {
                Some(desc) => {
                    if !desc.is_write_only() {
                        break;
                    }

                    let limit = cmp::min(write_count + desc.len as usize, self.rx_bytes_read);
                    let source_slice = &self.rx_frame_buf[write_count..limit];
                    let write_result = mem.write_slice(source_slice, desc.addr);

                    match write_result {
                        Ok(()) => {
                            METRICS.net.rx_count.inc();
                            write_count += source_slice.len();
                        }
                        Err(e) => {
                            error!("Failed to write slice: {:?}", e);
                            if let GuestMemoryError::PartialBuffer { completed, .. } = e {
                                write_count += completed;
                                METRICS.net.rx_partial_writes.inc();
                            } else {
                                METRICS.net.rx_fails.inc();
                            }
                            break;
                        }
                    };

                    if write_count >= self.rx_bytes_read {
                        break;
                    }
                    next_desc = desc.next_descriptor();
                }
                None => {
                    warn!("Receiving buffer is too small to hold frame of current size");
                    METRICS.net.rx_fails.inc();
                    break;
                }
            }
        }

        rx_queue.add_used(mem, head_index, write_count as u32);

        // Mark that we have at least one pending packet and we need to interrupt the guest.
        self.rx_deferred_irqs = true;

        if write_count >= self.rx_bytes_read {
            METRICS.net.rx_bytes_count.add(write_count);
            METRICS.net.rx_packets_count.inc();
            true
        } else {
            false
        }
    }

    // Tries to detour the frame to MMDS and if MMDS doesn't accept it, sends it on the host TAP.
    //
    // `frame_buf` should contain the frame bytes in a slice of exact length.
    // Returns whether MMDS consumed the frame.
    fn write_to_mmds_or_tap(
        mmds_ns: Option<&mut MmdsNetworkStack>,
        rate_limiter: &mut RateLimiter,
        frame_buf: &[u8],
        tap: &mut Tap,
        guest_mac: Option<MacAddr>,
    ) -> Result<bool> {
        let checked_frame = |frame_buf| {
            frame_bytes_from_buf(frame_buf).map_err(|e| {
                error!("VNET header missing in the TX frame.");
                METRICS.net.tx_malformed_frames.inc();
                e
            })
        };
        if let Some(ns) = mmds_ns {
            if ns.detour_frame(checked_frame(frame_buf)?) {
                METRICS.mmds.rx_accepted.inc();

                // MMDS frames are not accounted by the rate limiter.
                rate_limiter.manual_replenish(frame_buf.len() as u64, TokenType::Bytes);
                rate_limiter.manual_replenish(1, TokenType::Ops);

                // MMDS consumed the frame.
                return Ok(true);
            }
        }

        // This frame goes to the TAP.

        // Check for guest MAC spoofing.
        if let Some(mac) = guest_mac {
            let _ = EthernetFrame::from_bytes(checked_frame(frame_buf)?).and_then(|eth_frame| {
                if mac != eth_frame.src_mac() {
                    METRICS.net.tx_spoofed_mac_count.inc();
                }
                Ok(())
            });
        }

        match tap.write(frame_buf) {
            Ok(_) => {
                METRICS.net.tx_bytes_count.add(frame_buf.len());
                METRICS.net.tx_packets_count.inc();
                METRICS.net.tx_count.inc();
            }
            Err(e) => {
                error!("Failed to write to tap: {:?}", e);
                METRICS.net.tap_write_fails.inc();
            }
        };
        Ok(false)
    }

    // We currently prioritize packets from the MMDS over regular network packets.
    fn read_from_mmds_or_tap(&mut self) -> Result<usize> {
        if let Some(ns) = self.mmds_ns.as_mut() {
            if let Some(len) =
                ns.write_next_frame(frame_bytes_from_buf_mut(&mut self.rx_frame_buf)?)
            {
                let len = len.get();
                METRICS.mmds.tx_frames.inc();
                METRICS.mmds.tx_bytes.add(len);
                init_vnet_hdr(&mut self.rx_frame_buf);
                return Ok(vnet_hdr_len() + len);
            }
        }

        self.read_tap().map_err(Error::IO)
    }

    fn process_rx(&mut self) -> result::Result<(), DeviceError> {
        // Read as many frames as possible.
        loop {
            match self.read_from_mmds_or_tap() {
                Ok(count) => {
                    self.rx_bytes_read = count;
                    METRICS.net.rx_count.inc();
                    if !self.rate_limited_rx_single_frame() {
                        self.rx_deferred_frame = true;
                        break;
                    }
                }
                Err(Error::IO(e)) => {
                    // The tap device is non-blocking, so any error aside from EAGAIN is
                    // unexpected.
                    match e.raw_os_error() {
                        Some(err) if err == EAGAIN => (),
                        _ => {
                            error!("Failed to read tap: {:?}", e);
                            METRICS.net.tap_read_fails.inc();
                            return Err(DeviceError::FailedReadTap);
                        }
                    };
                    break;
                }
                Err(e) => {
                    error!("Spurious error in network RX: {:?}", e);
                }
            }
        }

        if self.rx_deferred_irqs {
            self.rx_deferred_irqs = false;
            self.signal_used_queue()
        } else {
            Ok(())
        }
    }

    // Process the deferred frame first, then continue reading from tap.
    fn handle_deferred_frame(&mut self) -> result::Result<(), DeviceError> {
        if self.rate_limited_rx_single_frame() {
            self.rx_deferred_frame = false;
            // process_rx() was interrupted possibly before consuming all
            // packets in the tap; try continuing now.
            self.process_rx()
        } else if self.rx_deferred_irqs {
            self.rx_deferred_irqs = false;
            self.signal_used_queue()
        } else {
            Ok(())
        }
    }

    fn resume_rx(&mut self) -> result::Result<(), DeviceError> {
        if self.rx_deferred_frame {
            self.handle_deferred_frame()
        } else {
            Ok(())
        }
    }

    fn process_tx(&mut self) -> result::Result<(), DeviceError> {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        // The MMDS network stack works like a state machine, based on synchronous calls, and
        // without being added to any event loop. If any frame is accepted by the MMDS, we also
        // trigger a process_rx() which checks if there are any new frames to be sent, starting
        // with the MMDS network stack.
        let mut process_rx_for_mmds = false;
        let mut raise_irq = false;
        let tx_queue = &mut self.queues[TX_INDEX];

        while let Some(head) = tx_queue.pop(mem) {
            // If limiter.consume() fails it means there is no more TokenType::Ops
            // budget and rate limiting is in effect.
            if !self.tx_rate_limiter.consume(1, TokenType::Ops) {
                // Stop processing the queue and return this descriptor chain to the
                // avail ring, for later processing.
                tx_queue.undo_pop();
                METRICS.net.tx_rate_limiter_throttled.inc();
                break;
            }

            let head_index = head.index;
            let mut read_count = 0;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                read_count += desc.len as usize;
                next_desc = desc.next_descriptor();
            }

            // If limiter.consume() fails it means there is no more TokenType::Bytes
            // budget and rate limiting is in effect.
            if !self
                .tx_rate_limiter
                .consume(read_count as u64, TokenType::Bytes)
            {
                // revert the OPS consume()
                self.tx_rate_limiter.manual_replenish(1, TokenType::Ops);
                // Stop processing the queue and return this descriptor chain to the
                // avail ring, for later processing.
                tx_queue.undo_pop();
                METRICS.net.tx_rate_limiter_throttled.inc();
                break;
            }

            read_count = 0;
            // Copy buffer from across multiple descriptors.
            // TODO(performance - Issue #420): change this to use `writev()` instead of `write()`
            // and get rid of the intermediate buffer.
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min((read_count + desc_len) as usize, self.tx_frame_buf.len());

                let read_result = mem.read_slice(
                    &mut self.tx_frame_buf[read_count..limit as usize],
                    desc_addr,
                );
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                        METRICS.net.tx_count.inc();
                    }
                    Err(e) => {
                        error!("Failed to read slice: {:?}", e);
                        if let GuestMemoryError::PartialBuffer { completed, .. } = e {
                            read_count += completed;
                            METRICS.net.tx_partial_reads.inc();
                        } else {
                            METRICS.net.tx_fails.inc();
                        }
                        break;
                    }
                }
            }

            let frame_consumed_by_mmds = Self::write_to_mmds_or_tap(
                self.mmds_ns.as_mut(),
                &mut self.tx_rate_limiter,
                &self.tx_frame_buf[..read_count],
                &mut self.tap,
                self.guest_mac,
            )
            .unwrap_or_else(|_| false);
            if frame_consumed_by_mmds && !self.rx_deferred_frame {
                // MMDS consumed this frame/request, let's also try to process the response.
                process_rx_for_mmds = true;
            }

            tx_queue.add_used(mem, head_index, 0);
            raise_irq = true;
        }

        if raise_irq {
            self.signal_used_queue()?;
        } else {
            METRICS.net.no_tx_avail_buffer.inc();
        }

        // An incoming frame for the MMDS may trigger the transmission of a new message.
        if process_rx_for_mmds {
            self.process_rx()
        } else {
            Ok(())
        }
    }

    /// Updates the parameters for the rate limiters
    pub fn patch_rate_limiters(
        &mut self,
        rx_bytes: BucketUpdate,
        rx_ops: BucketUpdate,
        tx_bytes: BucketUpdate,
        tx_ops: BucketUpdate,
    ) {
        self.rx_rate_limiter.update_buckets(rx_bytes, rx_ops);
        self.tx_rate_limiter.update_buckets(tx_bytes, tx_ops);
    }

    #[cfg(not(test))]
    fn read_tap(&mut self) -> io::Result<usize> {
        self.tap.read(&mut self.rx_frame_buf)
    }

    pub fn process_rx_queue_event(&mut self) {
        METRICS.net.rx_queue_event_count.inc();

        if let Err(e) = self.queue_evts[RX_INDEX].read() {
            // rate limiters present but with _very high_ allowed rate
            error!("Failed to get rx queue event: {:?}", e);
            METRICS.net.event_fails.inc();
        } else {
            // If the limiter is not blocked, resume the receiving of bytes.
            if !self.rx_rate_limiter.is_blocked() {
                self.resume_rx().unwrap_or_else(report_net_event_fail);
            } else {
                METRICS.net.rx_rate_limiter_throttled.inc();
            }
        }
    }

    pub fn process_tap_rx_event(&mut self) {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        METRICS.net.rx_tap_event_count.inc();
        if self.queues[RX_INDEX].is_empty(mem) {
            METRICS.net.no_rx_avail_buffer.inc();
            return;
        }

        // While limiter is blocked, don't process any more incoming.
        if self.rx_rate_limiter.is_blocked() {
            METRICS.net.rx_rate_limiter_throttled.inc();
            return;
        }

        if self.rx_deferred_frame
        // Process a deferred frame first if available. Don't read from tap again
        // until we manage to receive this deferred frame.
        {
            self.handle_deferred_frame()
                .unwrap_or_else(report_net_event_fail);
        } else {
            self.process_rx().unwrap_or_else(report_net_event_fail);
        }
    }

    pub fn process_tx_queue_event(&mut self) {
        METRICS.net.tx_queue_event_count.inc();
        if let Err(e) = self.queue_evts[TX_INDEX].read() {
            error!("Failed to get tx queue event: {:?}", e);
            METRICS.net.event_fails.inc();
        } else if !self.tx_rate_limiter.is_blocked()
        // If the limiter is not blocked, continue transmitting bytes.
        {
            self.process_tx().unwrap_or_else(report_net_event_fail);
        } else {
            METRICS.net.tx_rate_limiter_throttled.inc();
        }
    }

    pub fn process_rx_rate_limiter_event(&mut self) {
        METRICS.net.rx_event_rate_limiter_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.

        match self.rx_rate_limiter.event_handler() {
            Ok(_) => {
                // There might be enough budget now to receive the frame.
                self.resume_rx().unwrap_or_else(report_net_event_fail);
            }
            Err(e) => {
                error!("Failed to get rx rate-limiter event: {:?}", e);
                METRICS.net.event_fails.inc();
            }
        }
    }

    pub fn process_tx_rate_limiter_event(&mut self) {
        METRICS.net.tx_rate_limiter_event_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        match self.tx_rate_limiter.event_handler() {
            Ok(_) => {
                // There might be enough budget now to send the frame.
                self.process_tx().unwrap_or_else(report_net_event_fail);
            }
            Err(e) => {
                error!("Failed to get tx rate-limiter event: {:?}", e);
                METRICS.net.event_fails.inc();
            }
        }
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_space_bytes = self.config_space.as_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            METRICS.net.cfg_fails.inc();
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(
                &config_space_bytes[offset as usize..cmp::min(end, config_len) as usize],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_space_bytes = self.config_space.as_mut_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            METRICS.net.cfg_fails.inc();
            return;
        }

        config_space_bytes[offset as usize..(offset + data_len) as usize].copy_from_slice(data);
        self.guest_mac = Some(MacAddr::from_bytes_unchecked(
            &self.config_space.guest_mac[..MAC_ADDR_LEN],
        ));
        METRICS.net.mac_address_updates.inc();
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            error!("Net: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}

#[cfg(test)]
#[macro_use]
pub mod tests {
    use std::net::Ipv4Addr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use std::{io, mem, thread};

    use super::*;
    use crate::virtio::net::device::{
        frame_bytes_from_buf, frame_bytes_from_buf_mut, init_vnet_hdr, vnet_hdr_len,
    };

    use crate::virtio::net::tap::tests::TapTrafficSimulator;
    use crate::virtio::net::QUEUE_SIZES;
    use crate::virtio::queue::tests::{VirtQueue, VirtqDesc};
    use crate::virtio::{
        Net, Queue, VirtioDevice, MAX_BUFFER_SIZE, RX_INDEX, TX_INDEX, TYPE_NET,
        VIRTIO_MMIO_INT_VRING, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    };
    use dumbo::pdu::arp::{EthIPv4ArpFrame, ETH_IPV4_FRAME_LEN};
    use dumbo::pdu::ethernet::ETHERTYPE_ARP;
    use logger::{Metric, METRICS};
    use polly::event_manager::{EventManager, Subscriber};
    use rate_limiter::{RateLimiter, TokenBucket, TokenType};
    use std::sync::{Mutex, MutexGuard};
    use utils::epoll::{EpollEvent, EventSet};
    use virtio_gen::virtio_net::{
        virtio_net_hdr_v1, VIRTIO_F_VERSION_1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM,
        VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4,
        VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MAC,
    };
    use vm_memory::{Address, GuestMemory};

    static NEXT_INDEX: AtomicUsize = AtomicUsize::new(1);

    macro_rules! check_metric_after_block {
        ($metric:expr, $delta:expr, $block:expr) => {{
            let before = $metric.count();
            let _ = $block;
            assert_eq!($metric.count(), before + $delta, "unexpected metric value");
        }};
    }

    pub enum ReadTapMock {
        Failure,
        MockFrame(Vec<u8>),
        TapFrame,
    }

    impl ReadTapMock {
        fn mock_frame(&self) -> Vec<u8> {
            if let ReadTapMock::MockFrame(frame) = self {
                return frame.clone();
            }
            panic!("Can't get last mock frame");
        }
    }

    // Used to simulate tap read fails in tests.
    pub struct Mocks {
        read_tap: ReadTapMock,
    }

    impl Mocks {
        fn set_read_tap(&mut self, read_tap: ReadTapMock) {
            self.read_tap = read_tap;
        }
    }

    impl Default for Mocks {
        fn default() -> Mocks {
            Mocks {
                read_tap: ReadTapMock::MockFrame(
                    utils::rand::rand_alphanumerics(1234).as_bytes().to_vec(),
                ),
            }
        }
    }

    impl Net {
        pub fn default_net() -> Net {
            let next_tap = NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
            let tap_dev_name = format!("net-device{}", next_tap);

            let guest_mac = Net::default_guest_mac();

            let net = Net::new_with_tap(
                format!("net-device{}", next_tap),
                tap_dev_name,
                Some(&guest_mac),
                RateLimiter::default(),
                RateLimiter::default(),
                true,
            )
            .unwrap();
            net.tap.enable();

            net
        }

        pub fn default_guest_mac() -> MacAddr {
            MacAddr::parse_str("11:22:33:44:55:66").unwrap()
        }

        pub fn default_guest_memory() -> GuestMemoryMmap {
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
        }

        pub fn set_mac(&mut self, mac: MacAddr) {
            self.guest_mac = Some(mac);
            self.config_space.guest_mac.copy_from_slice(mac.get_bytes());
        }

        // Assigns "guest virtio driver" activated queues to the net device.
        pub fn assign_queues(&mut self, rxq: Queue, txq: Queue) {
            self.queues.clear();
            self.queues.push(rxq);
            self.queues.push(txq);
        }

        // Check that the used queue event has been generated `count` times.
        pub fn check_used_queue_signal(&self, count: u64) {
            // Leave at least one event here so that reading it later won't block.
            self.interrupt_evt.write(1).unwrap();
            assert_eq!(self.interrupt_evt.read().unwrap(), count + 1);
        }

        fn inject_tap_tx_frame(&self, len: usize) -> Vec<u8> {
            assert!(len >= vnet_hdr_len());
            let tap_traffic_simulator = TapTrafficSimulator::new(self.tap.if_index());
            let mut frame = utils::rand::rand_alphanumerics(len - vnet_hdr_len())
                .as_bytes()
                .to_vec();
            tap_traffic_simulator.push_tx_packet(&frame);
            frame.splice(0..0, vec![b'\0'; vnet_hdr_len()]);

            frame
        }
    }

    impl Net {
        pub fn read_tap(&mut self) -> io::Result<usize> {
            match &self.mocks.read_tap {
                ReadTapMock::MockFrame(frame) => {
                    self.rx_frame_buf[..frame.len()].copy_from_slice(&frame);
                    Ok(frame.len())
                }
                ReadTapMock::Failure => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Read tap synthetically failed.",
                )),
                ReadTapMock::TapFrame => self.tap.read(&mut self.rx_frame_buf),
            }
        }
    }

    pub enum NetQueue {
        Rx,
        Tx,
    }

    pub enum NetEvent {
        Custom(i32),
        RxQueue,
        RxRateLimiter,
        Tap,
        TxQueue,
        TxRateLimiter,
    }

    pub struct TestHelper<'a> {
        pub event_manager: EventManager,
        pub net: Arc<Mutex<Net>>,
        pub mem: GuestMemoryMmap,
        pub rxq: VirtQueue<'a>,
        pub txq: VirtQueue<'a>,
    }

    impl<'a> TestHelper<'a> {
        const QUEUE_SIZE: u16 = 16;

        pub fn default() -> TestHelper<'a> {
            let mut event_manager = EventManager::new().unwrap();
            let mut net = Net::default_net();
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MAX_BUFFER_SIZE)]).unwrap();
            // transmute mem_ref lifetime to 'a
            let mem_ref = unsafe { mem::transmute::<&GuestMemoryMmap, &'a GuestMemoryMmap>(&mem) };

            let rxq = VirtQueue::new(GuestAddress(0), mem_ref, Self::QUEUE_SIZE);
            let txq = VirtQueue::new(
                rxq.end().unchecked_align_up(VirtqDesc::ALIGNMENT),
                mem_ref,
                Self::QUEUE_SIZE,
            );
            net.assign_queues(rxq.create_queue(), txq.create_queue());

            let net = Arc::new(Mutex::new(net));
            event_manager.add_subscriber(net.clone()).unwrap();

            Self {
                event_manager,
                net,
                mem,
                rxq,
                txq,
            }
        }

        pub fn net(&mut self) -> MutexGuard<Net> {
            self.net.lock().unwrap()
        }

        pub fn activate_net(&mut self) {
            self.net.lock().unwrap().activate(self.mem.clone()).unwrap();
            // Process the activate event.
            let ev_count = self.event_manager.run_with_timeout(100).unwrap();
            assert_eq!(ev_count, 1);
        }

        pub fn simulate_event(&mut self, event: NetEvent) {
            let event_fd = match event {
                NetEvent::Custom(event_fd) => event_fd,
                NetEvent::RxQueue => self.net().queue_evts[RX_INDEX].as_raw_fd(),
                NetEvent::RxRateLimiter => self.net().rx_rate_limiter.as_raw_fd(),
                NetEvent::Tap => self.net().tap.as_raw_fd(),
                NetEvent::TxQueue => self.net().queue_evts[TX_INDEX].as_raw_fd(),
                NetEvent::TxRateLimiter => self.net().tx_rate_limiter.as_raw_fd(),
            };
            self.net.lock().unwrap().process(
                &EpollEvent::new(EventSet::IN, event_fd as u64),
                &mut self.event_manager,
            );
        }

        fn data_addr(&self) -> u64 {
            self.txq.end().raw_value()
        }

        pub fn add_desc_chain(
            &mut self,
            queue: NetQueue,
            addr_offset: u64,
            desc_list: &[(u16, u32, u16)],
        ) {
            // Get queue and event_fd.
            let net = self.net.lock().unwrap();
            let (queue, event_fd) = match queue {
                NetQueue::Rx => (&self.rxq, &net.queue_evts[RX_INDEX]),
                NetQueue::Tx => (&self.txq, &net.queue_evts[TX_INDEX]),
            };

            // Create the descriptor chain.
            let mut iter = desc_list.iter().peekable();
            let mut addr = self.data_addr() + addr_offset;
            while let Some(&(index, len, flags)) = iter.next() {
                let desc = &queue.dtable[index as usize];
                desc.set(addr, len, flags, 0);
                if let Some(&&(next_index, _, _)) = iter.peek() {
                    desc.flags.set(flags | VIRTQ_DESC_F_NEXT);
                    desc.next.set(next_index);
                }

                addr += len as u64;
                // Add small random gaps between descriptor addresses in order to make sure we
                // don't blindly read contiguous memory.
                addr += utils::rand::xor_psuedo_rng_u32() as u64 % 10;
            }

            // Mark the chain as available.
            if let Some(&(index, _, _)) = desc_list.first() {
                let ring_index = queue.avail.idx.get();
                queue.avail.ring[ring_index as usize].set(index);
                queue.avail.idx.set(ring_index + 1);
            }
            event_fd.write(1).unwrap();
        }

        /// Generate a tap frame of `frame_len` and check that it is deferred
        fn check_rx_deferred_frame(&mut self, frame_len: usize) -> Vec<u8> {
            self.net().mocks.set_read_tap(ReadTapMock::TapFrame);
            let used_idx = self.rxq.used.idx.get();

            // Inject frame to tap and run epoll.
            let frame = self.net().inject_tap_tx_frame(frame_len);
            check_metric_after_block!(
                METRICS.net.rx_packets_count,
                0,
                self.event_manager.run_with_timeout(100).unwrap()
            );
            // Check that the frame has been deferred.
            assert!(self.net().rx_deferred_frame);
            // Check that the descriptor chain has been discarded.
            assert_eq!(self.rxq.used.idx.get(), used_idx + 1);
            self.net().check_used_queue_signal(1);

            frame
        }

        /// Check that after adding a valid Rx queue descriptor chain a previously deferred frame
        /// is eventually received by the guest
        fn check_rx_queue_resume(&mut self, expected_frame: &[u8]) {
            let used_idx = self.rxq.used.idx.get();
            // Add a valid Rx avail descriptor chain and run epoll.
            self.add_desc_chain(
                NetQueue::Rx,
                0,
                &[(0, expected_frame.len() as u32, VIRTQ_DESC_F_WRITE)],
            );
            check_metric_after_block!(
                METRICS.net.rx_packets_count,
                1,
                self.event_manager.run_with_timeout(100).unwrap()
            );
            // Check that the expected frame was sent to the Rx queue eventually.
            assert_eq!(self.rxq.used.idx.get(), used_idx + 1);
            self.net().check_used_queue_signal(1);
            self.rxq
                .check_used_elem(used_idx, 0, expected_frame.len() as u32);
            self.rxq.dtable[0].check_data(&expected_frame);
        }
    }

    #[test]
    fn test_vnet_helpers() {
        let mut frame_buf = vec![42u8; vnet_hdr_len() - 1];
        assert_eq!(
            format!("{:?}", frame_bytes_from_buf(&frame_buf)),
            "Err(VnetHeaderMissing)"
        );
        assert_eq!(
            format!("{:?}", frame_bytes_from_buf_mut(&mut frame_buf)),
            "Err(VnetHeaderMissing)"
        );

        let mut frame_buf: [u8; MAX_BUFFER_SIZE] = [42u8; MAX_BUFFER_SIZE];

        let vnet_hdr_len_ = mem::size_of::<virtio_net_hdr_v1>();
        assert_eq!(vnet_hdr_len_, vnet_hdr_len());

        init_vnet_hdr(&mut frame_buf);
        let zero_vnet_hdr = vec![0u8; vnet_hdr_len_];
        assert_eq!(zero_vnet_hdr, &frame_buf[..vnet_hdr_len_]);

        let payload = vec![42u8; MAX_BUFFER_SIZE - vnet_hdr_len_];
        assert_eq!(payload, frame_bytes_from_buf(&frame_buf).unwrap());

        {
            let payload = frame_bytes_from_buf_mut(&mut frame_buf).unwrap();
            payload[0] = 15;
        }
        assert_eq!(frame_buf[vnet_hdr_len_], 15);
    }

    #[test]
    fn test_virtio_device_type() {
        let mut net = Net::default_net();
        net.set_mac(MacAddr::parse_str("11:22:33:44:55:66").unwrap());
        assert_eq!(net.device_type(), TYPE_NET);
    }

    #[test]
    fn test_virtio_device_features() {
        let mut net = Net::default_net();
        net.set_mac(MacAddr::parse_str("11:22:33:44:55:66").unwrap());

        // Test `features()` and `ack_features()`.
        let features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_MAC
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        assert_eq!(net.avail_features_by_page(0), features as u32);
        assert_eq!(net.avail_features_by_page(1), (features >> 32) as u32);
        for i in 2..10 {
            assert_eq!(net.avail_features_by_page(i), 0u32);
        }

        for i in 0..10 {
            net.ack_features_by_page(i, std::u32::MAX);
        }

        assert_eq!(net.acked_features, features);
    }

    #[test]
    fn test_virtio_device_read_config() {
        let mut net = Net::default_net();
        net.set_mac(MacAddr::parse_str("11:22:33:44:55:66").unwrap());

        // Test `read_config()`. This also validates the MAC was properly configured.
        let mac = MacAddr::parse_str("11:22:33:44:55:66").unwrap();
        let mut config_mac = [0u8; MAC_ADDR_LEN];
        net.read_config(0, &mut config_mac);
        assert_eq!(config_mac, mac.get_bytes());

        // Invalid read.
        config_mac = [0u8; MAC_ADDR_LEN];
        net.read_config(MAC_ADDR_LEN as u64 + 1, &mut config_mac);
        assert_eq!(config_mac, [0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
    }

    #[test]
    fn test_virtio_device_rewrite_config() {
        let mut net = Net::default_net();
        net.set_mac(MacAddr::parse_str("11:22:33:44:55:66").unwrap());

        let new_config: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        net.write_config(0, &new_config);
        let mut new_config_read = [0u8; 6];
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);

        // Check that the guest MAC was updated.
        let expected_guest_mac = MacAddr::from_bytes_unchecked(&new_config);
        assert_eq!(expected_guest_mac, net.guest_mac.unwrap());
        assert_eq!(METRICS.net.mac_address_updates.count(), 1);

        // Partial write (this is how the kernel sets a new mac address) - byte by byte.
        let new_config = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        for i in 0..new_config.len() {
            net.write_config(i as u64, &new_config[i..=i]);
        }
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);

        // Invalid write.
        net.write_config(5, &new_config);
        // Verify old config was untouched.
        new_config_read = [0u8; 6];
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);
    }

    #[test]
    fn test_rx_missing_queue_signal() {
        let mut th = TestHelper::default();
        th.activate_net();

        th.add_desc_chain(NetQueue::Rx, 0, &[(0, 4096, VIRTQ_DESC_F_WRITE)]);
        th.net().queue_evts[RX_INDEX].read().unwrap();
        check_metric_after_block!(
            METRICS.net.event_fails,
            1,
            th.simulate_event(NetEvent::RxQueue)
        );

        // Check that the used queue didn't advance.
        assert_eq!(th.rxq.used.idx.get(), 0);
    }

    #[test]
    fn test_rx_read_only_descriptor() {
        let mut th = TestHelper::default();
        th.activate_net();

        th.add_desc_chain(
            NetQueue::Rx,
            0,
            &[
                (0, 100, VIRTQ_DESC_F_WRITE),
                (1, 100, 0),
                (2, 1000, VIRTQ_DESC_F_WRITE),
            ],
        );
        let frame = th.check_rx_deferred_frame(1000);
        th.rxq.check_used_elem(0, 0, 100);

        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_short_writable_descriptor() {
        let mut th = TestHelper::default();
        th.activate_net();

        th.add_desc_chain(NetQueue::Rx, 0, &[(0, 100, VIRTQ_DESC_F_WRITE)]);
        let frame = th.check_rx_deferred_frame(1000);
        th.rxq.check_used_elem(0, 0, 100);

        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_partial_write() {
        let mut th = TestHelper::default();
        th.activate_net();

        // The descriptor chain is created so that the last descriptor doesn't fit in the
        // guest memory.
        let offset = th.mem.last_addr().raw_value() - th.data_addr() - 300;
        th.add_desc_chain(
            NetQueue::Rx,
            offset,
            &[
                (0, 100, VIRTQ_DESC_F_WRITE),
                (1, 50, VIRTQ_DESC_F_WRITE),
                (2, 4096, VIRTQ_DESC_F_WRITE),
            ],
        );
        let expected_len = 150 + th.mem.last_addr().raw_value() + 1 - th.rxq.dtable[2].addr.get();
        let frame = th.check_rx_deferred_frame(1000);
        th.rxq.check_used_elem(0, 0, expected_len as u32);

        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_complex_desc_chain() {
        let mut th = TestHelper::default();
        th.activate_net();
        th.net().mocks.set_read_tap(ReadTapMock::TapFrame);

        // Create a valid Rx avail descriptor chain with multiple descriptors.
        th.add_desc_chain(
            NetQueue::Rx,
            0,
            // Add gaps between the descriptor ids in order to ensure that we follow
            // the `next` field.
            &[
                (3, 100, VIRTQ_DESC_F_WRITE),
                (5, 50, VIRTQ_DESC_F_WRITE),
                (11, 4096, VIRTQ_DESC_F_WRITE),
            ],
        );
        // Inject frame to tap and run epoll.
        let frame = th.net().inject_tap_tx_frame(1000);
        check_metric_after_block!(
            METRICS.net.rx_packets_count,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the frame wasn't deferred.
        assert!(!th.net().rx_deferred_frame);
        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 1);
        th.net().check_used_queue_signal(1);
        // Check that the frame has been written successfully to the Rx descriptor chain.
        th.rxq.check_used_elem(0, 3, frame.len() as u32);
        th.rxq.dtable[3].check_data(&frame[..100]);
        th.rxq.dtable[5].check_data(&frame[100..150]);
        th.rxq.dtable[11].check_data(&frame[150..]);
    }

    #[test]
    fn test_rx_multiple_frames() {
        let mut th = TestHelper::default();
        th.activate_net();
        th.net().mocks.set_read_tap(ReadTapMock::TapFrame);

        // Create 2 valid Rx avail descriptor chains. Each one has enough space to fit the
        // following 2 frames. But only 1 frame has to be written to each chain.
        th.add_desc_chain(
            NetQueue::Rx,
            0,
            &[(0, 500, VIRTQ_DESC_F_WRITE), (1, 500, VIRTQ_DESC_F_WRITE)],
        );
        th.add_desc_chain(
            NetQueue::Rx,
            1000,
            &[(2, 500, VIRTQ_DESC_F_WRITE), (3, 500, VIRTQ_DESC_F_WRITE)],
        );
        // Inject 2 frames to tap and run epoll.
        let frame_1 = th.net().inject_tap_tx_frame(200);
        let frame_2 = th.net().inject_tap_tx_frame(300);
        check_metric_after_block!(
            METRICS.net.rx_packets_count,
            2,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the frames weren't deferred.
        assert!(!th.net().rx_deferred_frame);
        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 2);
        th.net().check_used_queue_signal(1);
        // Check that the 1st frame was written successfully to the 1st Rx descriptor chain.
        th.rxq.check_used_elem(0, 0, frame_1.len() as u32);
        th.rxq.dtable[0].check_data(&frame_1);
        th.rxq.dtable[1].check_data(&[0; 500]);
        // Check that the 2nd frame was written successfully to the 2nd Rx descriptor chain.
        th.rxq.check_used_elem(1, 2, frame_2.len() as u32);
        th.rxq.dtable[2].check_data(&frame_2);
        th.rxq.dtable[3].check_data(&[0; 500]);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_event_processing() {
        let mut th = TestHelper::default();
        th.activate_net();

        // Some corner cases for rx_single_frame().
        {
            assert_eq!(th.net().rx_bytes_read, 0);

            // Let's imagine we received some data.
            th.net().rx_bytes_read = MAX_BUFFER_SIZE;
            {
                // a read only descriptor
                th.add_desc_chain(NetQueue::Rx, 0, &[(0, 4096, 0)]);
                assert!(!th.net().rx_single_frame());
                assert!(th.net().rx_deferred_irqs);
                assert_eq!(th.rxq.used.idx.get(), 1);
                th.net().check_used_queue_signal(0);

                // resetting values
                th.net().rx_deferred_irqs = false;
                th.rxq.used.idx.set(0);
                th.net().queues[RX_INDEX] = th.rxq.create_queue();
            }

            {
                // We make the prev desc write_only (with no other flag) to get a chain which is
                // writable, but too short.
                th.rxq.dtable[0].flags.set(VIRTQ_DESC_F_WRITE);
                check_metric_after_block!(
                    &METRICS.net.rx_fails,
                    1,
                    assert!(!th.net().rx_single_frame())
                );
                assert_eq!(th.rxq.used.idx.get(), 1);
                assert!(th.net().rx_deferred_irqs);
                th.net().check_used_queue_signal(0);

                // resetting values
                th.rxq.used.idx.set(0);
                th.net().queues[RX_INDEX] = th.rxq.create_queue();
                th.net().rx_deferred_irqs = false;
                th.net().rx_bytes_read = 0;
            }
        }

        {
            // Send an invalid frame (too small, VNET header missing).
            th.add_desc_chain(NetQueue::Tx, 0, &[(0, 1, 0)]);
            // Trigger the TX handler.
            check_metric_after_block!(
                &METRICS.net.tx_malformed_frames,
                1,
                th.simulate_event(NetEvent::TxQueue)
            );

            // Make sure the data queue advanced.
            assert_eq!(th.txq.used.idx.get(), 1);
        }

        // Now let's move on to the actual device events.
        {
            // testing TX_QUEUE_EVENT
            th.add_desc_chain(NetQueue::Tx, 0, &[(1, 4096, 0)]);
            th.simulate_event(NetEvent::TxQueue);
            // Make sure the data queue advanced.
            assert_eq!(th.txq.used.idx.get(), 2);
        }

        {
            // testing RX_TAP_EVENT

            assert!(!th.net().rx_deferred_frame);

            let frame = &th.net().mocks.read_tap.mock_frame();
            // this should work just fine
            th.simulate_event(NetEvent::Tap);
            assert!(th.net().rx_deferred_frame);
            th.net().check_used_queue_signal(3);
            th.rxq.check_used_elem(0, 0, frame.len() as u32);
            th.rxq.dtable[0].check_data(&frame);

            // // Since deferred_frame is now true, activating the same event again will trigger
            // a different execution path.

            // reset some parts of the queue first
            th.net().queues[RX_INDEX] = th.rxq.create_queue();
            th.rxq.used.idx.set(0);

            // this should also be successful
            th.simulate_event(NetEvent::Tap);
            assert!(th.net().rx_deferred_frame);
            th.net().check_used_queue_signal(1);

            // ... but the following shouldn't, because we emulate receiving much more data than
            // we can fit inside a single descriptor

            th.net().rx_bytes_read = MAX_BUFFER_SIZE;
            th.net().queues[RX_INDEX] = th.rxq.create_queue();
            th.rxq.used.idx.set(0);

            check_metric_after_block!(&METRICS.net.rx_fails, 1, th.simulate_event(NetEvent::Tap));
            assert!(th.net().rx_deferred_frame);
            th.net().check_used_queue_signal(1);

            // A mismatch shows the reception was unsuccessful.
            let rx_bytes_read = th.net().rx_bytes_read;
            assert_ne!(th.rxq.used.ring[0].get().len as usize, rx_bytes_read);

            // We set this back to a manageable size, for the following test.
            th.net().rx_bytes_read = 1234;
        }

        {
            // now also try an RX_QUEUE_EVENT
            th.add_desc_chain(NetQueue::Rx, 4096, &[(1, 4096, VIRTQ_DESC_F_WRITE)]);
            // rx_count increments 1 from rx_single_frame() and 1 from process_rx()
            check_metric_after_block!(
                &METRICS.net.rx_count,
                2,
                th.simulate_event(NetEvent::RxQueue)
            );
            th.net().check_used_queue_signal(1);
        }

        {
            let mut net = Net::default_net();
            net.mocks.set_read_tap(ReadTapMock::Failure);
            check_metric_after_block!(&METRICS.net.tap_read_fails, 1, net.process_rx());
        }
    }

    fn create_arp_request(
        src_mac: MacAddr,
        src_ip: Ipv4Addr,
        dst_mac: MacAddr,
        dst_ip: Ipv4Addr,
    ) -> ([u8; MAX_BUFFER_SIZE], usize) {
        let mut frame_buf = [b'\0'; MAX_BUFFER_SIZE];
        let frame_len;
        // Create an ethernet frame.
        let incomplete_frame = EthernetFrame::write_incomplete(
            frame_bytes_from_buf_mut(&mut frame_buf).unwrap(),
            dst_mac,
            src_mac,
            ETHERTYPE_ARP,
        )
        .ok()
        .unwrap();
        // Set its length to hold an ARP request.
        let mut frame = incomplete_frame.with_payload_len_unchecked(ETH_IPV4_FRAME_LEN);

        // Save the total frame length.
        frame_len = vnet_hdr_len() + frame.payload_offset() + ETH_IPV4_FRAME_LEN;

        // Create the ARP request.
        let arp_request =
            EthIPv4ArpFrame::write_request(frame.payload_mut(), src_mac, src_ip, dst_mac, dst_ip);
        // Validate success.
        assert!(arp_request.is_ok());

        (frame_buf, frame_len)
    }

    #[test]
    fn test_mmds_detour_and_injection() {
        let mut net = Net::default_net();

        let src_mac = MacAddr::parse_str("11:11:11:11:11:11").unwrap();
        let src_ip = Ipv4Addr::new(10, 1, 2, 3);
        let dst_mac = MacAddr::parse_str("22:22:22:22:22:22").unwrap();
        let dst_ip = Ipv4Addr::new(169, 254, 169, 254);

        let (frame_buf, frame_len) = create_arp_request(src_mac, src_ip, dst_mac, dst_ip);

        // Call the code which sends the packet to the host or MMDS.
        // Validate the frame was consumed by MMDS and that the metrics reflect that.
        check_metric_after_block!(
            &METRICS.mmds.rx_accepted,
            1,
            assert!(Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &frame_buf[..frame_len],
                &mut net.tap,
                Some(src_mac),
            )
            .unwrap())
        );

        // Validate that MMDS has a response and we can retrieve it.
        check_metric_after_block!(
            &METRICS.mmds.tx_frames,
            1,
            net.read_from_mmds_or_tap().unwrap()
        );
    }

    #[test]
    fn test_mac_spoofing_detection() {
        let mut net = Net::default_net();

        let guest_mac = MacAddr::parse_str("11:11:11:11:11:11").unwrap();
        let not_guest_mac = MacAddr::parse_str("33:33:33:33:33:33").unwrap();
        let guest_ip = Ipv4Addr::new(10, 1, 2, 3);
        let dst_mac = MacAddr::parse_str("22:22:22:22:22:22").unwrap();
        let dst_ip = Ipv4Addr::new(10, 1, 1, 1);

        let (frame_buf, frame_len) = create_arp_request(guest_mac, guest_ip, dst_mac, dst_ip);

        // Check that a legit MAC doesn't affect the spoofed MAC metric.
        check_metric_after_block!(
            &METRICS.net.tx_spoofed_mac_count,
            0,
            Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &frame_buf[..frame_len],
                &mut net.tap,
                Some(guest_mac),
            )
        );

        // Check that a spoofed MAC increases our spoofed MAC metric.
        check_metric_after_block!(
            &METRICS.net.tx_spoofed_mac_count,
            1,
            Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &frame_buf[..frame_len],
                &mut net.tap,
                Some(not_guest_mac),
            )
        );
    }

    #[test]
    fn test_process_error_cases() {
        let mut th = TestHelper::default();
        th.activate_net();

        // RX rate limiter events should error since the limiter is not blocked.
        // Validate that the event failed and failure was properly accounted for.
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            th.simulate_event(NetEvent::RxRateLimiter)
        );

        // TX rate limiter events should error since the limiter is not blocked.
        // Validate that the event failed and failure was properly accounted for.
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            th.simulate_event(NetEvent::TxRateLimiter)
        );
    }

    // Cannot easily test failures for:
    //  * queue_evt.read (rx and tx)
    //  * interrupt_evt.write
    #[test]
    fn test_read_tap_fail_event_handler() {
        let mut th = TestHelper::default();
        th.activate_net();
        th.net().mocks.set_read_tap(ReadTapMock::Failure);

        // The RX queue is empty.
        check_metric_after_block!(
            &METRICS.net.no_rx_avail_buffer,
            1,
            th.simulate_event(NetEvent::Tap)
        );

        // Fake an avail buffer; this time, tap reading should error out.
        th.rxq.avail.idx.set(1);
        check_metric_after_block!(
            &METRICS.net.tap_read_fails,
            1,
            th.simulate_event(NetEvent::Tap)
        );
    }

    #[test]
    fn test_rx_rate_limiter_handling() {
        let mut th = TestHelper::default();
        th.activate_net();

        th.net().rx_rate_limiter = RateLimiter::new(0, 0, 0, 0, 0, 0).unwrap();
        // There is no actual event on the rate limiter's timerfd.
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            th.simulate_event(NetEvent::RxRateLimiter)
        );
    }

    #[test]
    fn test_tx_rate_limiter_handling() {
        let mut th = TestHelper::default();
        th.activate_net();

        th.net().tx_rate_limiter = RateLimiter::new(0, 0, 0, 0, 0, 0).unwrap();
        th.simulate_event(NetEvent::TxRateLimiter);
        // There is no actual event on the rate limiter's timerfd.
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            th.simulate_event(NetEvent::TxRateLimiter)
        );
    }

    #[test]
    fn test_bandwidth_rate_limiter() {
        let mut th = TestHelper::default();
        th.activate_net();

        // Test TX bandwidth rate limiting
        {
            // create bandwidth rate limiter that allows 40960 bytes/s with bucket size 4096 bytes
            let mut rl = RateLimiter::new(0x1000, 0, 100, 0, 0, 0).unwrap();
            // use up the budget
            assert!(rl.consume(0x1000, TokenType::Bytes));

            // set this tx rate limiter to be used
            th.net().tx_rate_limiter = rl;

            // try doing TX
            // following TX procedure should fail because of bandwidth rate limiting
            {
                // trigger the TX handler
                th.add_desc_chain(NetQueue::Tx, 0, &[(0, 4096, 0)]);
                th.simulate_event(NetEvent::TxQueue);

                // assert that limiter is blocked
                assert!(th.net().tx_rate_limiter.is_blocked());
                assert_eq!(METRICS.net.tx_rate_limiter_throttled.count(), 1);
                // make sure the data is still queued for processing
                assert_eq!(th.txq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following TX procedure should succeed because bandwidth should now be available
            {
                // tx_count increments 1 from process_tx() and 1 from write_to_mmds_or_tap()
                check_metric_after_block!(
                    &METRICS.net.tx_count,
                    2,
                    th.simulate_event(NetEvent::TxRateLimiter)
                );
                // validate the rate_limiter is no longer blocked
                assert!(!th.net().tx_rate_limiter.is_blocked());
                // make sure the data queue advanced
                assert_eq!(th.txq.used.idx.get(), 1);
            }
        }

        // Test RX bandwidth rate limiting
        {
            // create bandwidth rate limiter that allows 40960 bytes/s with bucket size 4096 bytes
            let mut rl = RateLimiter::new(0x1000, 0, 100, 0, 0, 0).unwrap();
            // use up the budget
            assert!(rl.consume(0x1000, TokenType::Bytes));

            // set this rx rate limiter to be used
            th.net().rx_rate_limiter = rl;

            // set up RX
            assert!(!th.net().rx_deferred_frame);
            th.add_desc_chain(NetQueue::Rx, 0, &[(0, 4096, VIRTQ_DESC_F_WRITE)]);

            // following RX procedure should fail because of bandwidth rate limiting
            {
                // trigger the RX handler
                th.simulate_event(NetEvent::Tap);

                // assert that limiter is blocked
                assert!(th.net().rx_rate_limiter.is_blocked());
                assert_eq!(METRICS.net.rx_rate_limiter_throttled.count(), 1);
                assert!(th.net().rx_deferred_frame);
                // assert that no operation actually completed (limiter blocked it)
                th.net().check_used_queue_signal(1);
                // make sure the data is still queued for processing
                assert_eq!(th.rxq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following RX procedure should succeed because bandwidth should now be available
            {
                let frame = &th.net().mocks.read_tap.mock_frame();
                // no longer throttled
                check_metric_after_block!(
                    &METRICS.net.rx_rate_limiter_throttled,
                    0,
                    th.simulate_event(NetEvent::RxRateLimiter)
                );
                // validate the rate_limiter is no longer blocked
                assert!(!th.net().rx_rate_limiter.is_blocked());
                // make sure the virtio queue operation completed this time
                th.net().check_used_queue_signal(1);
                // make sure the data queue advanced
                assert_eq!(th.rxq.used.idx.get(), 1);
                th.rxq.check_used_elem(0, 0, frame.len() as u32);
                th.rxq.dtable[0].check_data(&frame);
            }
        }
    }

    #[test]
    fn test_ops_rate_limiter() {
        let mut th = TestHelper::default();
        th.activate_net();

        // Test TX ops rate limiting
        {
            // create ops rate limiter that allows 10 ops/s with bucket size 1 ops
            let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 100).unwrap();
            // use up the budget
            assert!(rl.consume(1, TokenType::Ops));

            // set this tx rate limiter to be used
            th.net().tx_rate_limiter = rl;

            // try doing TX
            // following TX procedure should fail because of ops rate limiting
            {
                // trigger the TX handler
                th.add_desc_chain(NetQueue::Tx, 0, &[(0, 4096, 0)]);
                check_metric_after_block!(
                    METRICS.net.tx_rate_limiter_throttled,
                    1,
                    th.simulate_event(NetEvent::TxQueue)
                );

                // assert that limiter is blocked
                assert!(th.net().tx_rate_limiter.is_blocked());
                // make sure the data is still queued for processing
                assert_eq!(th.txq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following TX procedure should succeed because ops should now be available
            {
                // no longer throttled
                check_metric_after_block!(
                    &METRICS.net.tx_rate_limiter_throttled,
                    0,
                    th.simulate_event(NetEvent::TxRateLimiter)
                );
                // validate the rate_limiter is no longer blocked
                assert!(!th.net().tx_rate_limiter.is_blocked());
                // make sure the data queue advanced
                assert_eq!(th.txq.used.idx.get(), 1);
            }
        }

        // Test RX ops rate limiting
        {
            // create ops rate limiter that allows 10 ops/s with bucket size 1 ops
            let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 100).unwrap();
            // use up the budget
            assert!(rl.consume(0x800, TokenType::Ops));

            // set this rx rate limiter to be used
            th.net().rx_rate_limiter = rl;

            // set up RX
            assert!(!th.net().rx_deferred_frame);
            th.add_desc_chain(NetQueue::Rx, 0, &[(0, 4096, VIRTQ_DESC_F_WRITE)]);

            // following RX procedure should fail because of ops rate limiting
            {
                // trigger the RX handler
                check_metric_after_block!(
                    METRICS.net.rx_rate_limiter_throttled,
                    1,
                    th.simulate_event(NetEvent::Tap)
                );

                // assert that limiter is blocked
                assert!(th.net().rx_rate_limiter.is_blocked());
                assert!(METRICS.net.rx_rate_limiter_throttled.count() >= 1);
                assert!(th.net().rx_deferred_frame);
                // assert that no operation actually completed (limiter blocked it)
                th.net().check_used_queue_signal(1);
                // make sure the data is still queued for processing
                assert_eq!(th.rxq.used.idx.get(), 0);

                // trigger the RX handler again, this time it should do the limiter fast path exit
                th.simulate_event(NetEvent::Tap);
                // assert that no operation actually completed, that the limiter blocked it
                th.net().check_used_queue_signal(0);
                // make sure the data is still queued for processing
                assert_eq!(th.rxq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following RX procedure should succeed because ops should now be available
            {
                let frame = &th.net().mocks.read_tap.mock_frame();
                th.simulate_event(NetEvent::RxRateLimiter);
                // make sure the virtio queue operation completed this time
                th.net().check_used_queue_signal(1);
                // make sure the data queue advanced
                assert_eq!(th.rxq.used.idx.get(), 1);
                th.rxq.check_used_elem(0, 0, frame.len() as u32);
                th.rxq.dtable[0].check_data(&frame);
            }
        }
    }

    #[test]
    fn test_patch_rate_limiters() {
        let mut th = TestHelper::default();
        th.activate_net();

        th.net().rx_rate_limiter = RateLimiter::new(10, 0, 10, 2, 0, 2).unwrap();
        th.net().tx_rate_limiter = RateLimiter::new(10, 0, 10, 2, 0, 2).unwrap();

        let rx_bytes = TokenBucket::new(1000, 1001, 1002).unwrap();
        let rx_ops = TokenBucket::new(1003, 1004, 1005).unwrap();
        let tx_bytes = TokenBucket::new(1006, 1007, 1008).unwrap();
        let tx_ops = TokenBucket::new(1009, 1010, 1011).unwrap();

        th.net().patch_rate_limiters(
            BucketUpdate::Update(rx_bytes.clone()),
            BucketUpdate::Update(rx_ops.clone()),
            BucketUpdate::Update(tx_bytes.clone()),
            BucketUpdate::Update(tx_ops.clone()),
        );
        let compare_buckets = |a: &TokenBucket, b: &TokenBucket| {
            assert_eq!(a.capacity(), b.capacity());
            assert_eq!(a.one_time_burst(), b.one_time_burst());
            assert_eq!(a.refill_time_ms(), b.refill_time_ms());
        };
        compare_buckets(th.net().rx_rate_limiter.bandwidth().unwrap(), &rx_bytes);
        compare_buckets(th.net().rx_rate_limiter.ops().unwrap(), &rx_ops);
        compare_buckets(th.net().tx_rate_limiter.bandwidth().unwrap(), &tx_bytes);
        compare_buckets(th.net().tx_rate_limiter.ops().unwrap(), &tx_ops);

        th.net().patch_rate_limiters(
            BucketUpdate::Disabled,
            BucketUpdate::Disabled,
            BucketUpdate::Disabled,
            BucketUpdate::Disabled,
        );
        assert!(th.net().rx_rate_limiter.bandwidth().is_none());
        assert!(th.net().rx_rate_limiter.ops().is_none());
        assert!(th.net().tx_rate_limiter.bandwidth().is_none());
        assert!(th.net().tx_rate_limiter.ops().is_none());
    }

    #[test]
    fn test_tx_queue_interrupt() {
        // Regression test for https://github.com/firecracker-microvm/firecracker/issues/1436 .
        let mut th = TestHelper::default();
        th.activate_net();

        // Do some TX.
        // trigger the TX handler
        th.add_desc_chain(NetQueue::Tx, 0, &[(0, 4096, 0)]);
        th.simulate_event(NetEvent::TxQueue);

        // Verify if TX queue was processed.
        assert_eq!(th.txq.used.idx.get(), 1);
        // Check if interrupt was triggered.
        th.net().check_used_queue_signal(1);
    }

    #[test]
    fn test_virtio_device() {
        let mut th = TestHelper::default();
        th.activate_net();
        let net = th.net.lock().unwrap();

        // Test queues count (TX and RX).
        let queues = net.queues();
        assert_eq!(queues.len(), QUEUE_SIZES.len());
        assert_eq!(queues[RX_INDEX].size, th.rxq.size());
        assert_eq!(queues[TX_INDEX].size, th.txq.size());

        // Test corresponding queues events.
        assert_eq!(net.queue_events().len(), QUEUE_SIZES.len());

        // Test interrupts.
        let interrupt_status = net.interrupt_status();
        interrupt_status.fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        assert_eq!(
            interrupt_status.load(Ordering::SeqCst),
            VIRTIO_MMIO_INT_VRING as usize
        );

        net.check_used_queue_signal(0);
    }
}
