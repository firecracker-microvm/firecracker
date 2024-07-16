// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(not(test))]
use std::io::Read;
use std::mem;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use libc::EAGAIN;
use log::{error, warn};
use utils::eventfd::EventFd;
use utils::net::mac::MacAddr;
use utils::u64_to_usize;
use vm_memory::GuestMemoryError;

use crate::devices::virtio::device::{DeviceState, IrqTrigger, IrqType, VirtioDevice};
use crate::devices::virtio::gen::virtio_blk::VIRTIO_F_VERSION_1;
use crate::devices::virtio::gen::virtio_net::{
    virtio_net_hdr_v1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4,
    VIRTIO_NET_F_GUEST_TSO6, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4,
    VIRTIO_NET_F_HOST_TSO6, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MAC,
};
use crate::devices::virtio::gen::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::iovec::IoVecBuffer;
use crate::devices::virtio::net::metrics::{NetDeviceMetrics, NetMetricsPerDevice};
use crate::devices::virtio::net::tap::Tap;
use crate::devices::virtio::net::{
    gen, NetError, NetQueue, MAX_BUFFER_SIZE, NET_QUEUE_SIZES, RX_INDEX, TX_INDEX,
};
use crate::devices::virtio::queue::{DescriptorChain, Queue};
use crate::devices::virtio::{ActivateError, TYPE_NET};
use crate::devices::{report_net_event_fail, DeviceError};
use crate::dumbo::pdu::arp::ETH_IPV4_FRAME_LEN;
use crate::dumbo::pdu::ethernet::{EthernetFrame, PAYLOAD_OFFSET};
use crate::logger::{IncMetric, METRICS};
use crate::mmds::data_store::Mmds;
use crate::mmds::ns::MmdsNetworkStack;
use crate::rate_limiter::{BucketUpdate, RateLimiter, TokenType};
use crate::vstate::memory::{ByteValued, Bytes, GuestMemoryMmap};

const FRAME_HEADER_MAX_LEN: usize = PAYLOAD_OFFSET + ETH_IPV4_FRAME_LEN;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum FrontendError {
    /// Add user.
    AddUsed,
    /// Descriptor chain too mall.
    DescriptorChainTooSmall,
    /// Empty queue.
    EmptyQueue,
    /// Guest memory error: {0}
    GuestMemory(GuestMemoryError),
    /// Read only descriptor.
    ReadOnlyDescriptor,
}

pub(crate) const fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

// This returns the maximum frame header length. This includes the VNET header plus
// the maximum L2 frame header bytes which includes the ethernet frame header plus
// the header IPv4 ARP header which is 28 bytes long.
const fn frame_hdr_len() -> usize {
    vnet_hdr_len() + FRAME_HEADER_MAX_LEN
}

// Frames being sent/received through the network device model have a VNET header. This
// function returns a slice which holds the L2 frame bytes without this header.
fn frame_bytes_from_buf(buf: &[u8]) -> Result<&[u8], NetError> {
    if buf.len() < vnet_hdr_len() {
        Err(NetError::VnetHeaderMissing)
    } else {
        Ok(&buf[vnet_hdr_len()..])
    }
}

fn frame_bytes_from_buf_mut(buf: &mut [u8]) -> Result<&mut [u8], NetError> {
    if buf.len() < vnet_hdr_len() {
        Err(NetError::VnetHeaderMissing)
    } else {
        Ok(&mut buf[vnet_hdr_len()..])
    }
}

// This initializes to all 0 the VNET hdr part of a buf.
fn init_vnet_hdr(buf: &mut [u8]) {
    // The buffer should be larger than vnet_hdr_len.
    buf[0..vnet_hdr_len()].fill(0);
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct ConfigSpace {
    pub guest_mac: MacAddr,
}

// SAFETY: `ConfigSpace` contains only PODs in `repr(C)` or `repr(transparent)`, without padding.
unsafe impl ByteValued for ConfigSpace {}

/// VirtIO network device.
///
/// It emulates a network device able to exchange L2 frames between the guest
/// and a host-side tap device.
#[derive(Debug)]
pub struct Net {
    pub(crate) id: String,

    /// The backend for this device: a tap.
    pub tap: Tap,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,

    pub(crate) rx_rate_limiter: RateLimiter,
    pub(crate) tx_rate_limiter: RateLimiter,

    pub(crate) rx_deferred_frame: bool,

    rx_bytes_read: usize,
    rx_frame_buf: [u8; MAX_BUFFER_SIZE],

    tx_frame_headers: [u8; frame_hdr_len()],

    pub(crate) irq_trigger: IrqTrigger,

    pub(crate) config_space: ConfigSpace,
    pub(crate) guest_mac: Option<MacAddr>,

    pub(crate) device_state: DeviceState,
    pub(crate) activate_evt: EventFd,

    /// The MMDS stack corresponding to this interface.
    /// Only if MMDS transport has been associated with it.
    pub mmds_ns: Option<MmdsNetworkStack>,
    pub(crate) metrics: Arc<NetDeviceMetrics>,
}

impl Net {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(
        id: String,
        tap: Tap,
        guest_mac: Option<MacAddr>,
        rx_rate_limiter: RateLimiter,
        tx_rate_limiter: RateLimiter,
    ) -> Result<Self, NetError> {
        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_TSO6
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_TSO6
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_EVENT_IDX;

        let mut config_space = ConfigSpace::default();
        if let Some(mac) = guest_mac {
            config_space.guest_mac = mac;
            // Enabling feature for MAC address configuration
            // If not set, the driver will generates a random MAC address
            avail_features |= 1 << VIRTIO_NET_F_MAC;
        }

        let mut queue_evts = Vec::new();
        let mut queues = Vec::new();
        for size in NET_QUEUE_SIZES {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(NetError::EventFd)?);
            queues.push(Queue::new(size));
        }

        Ok(Net {
            id: id.clone(),
            tap,
            avail_features,
            acked_features: 0u64,
            queues,
            queue_evts,
            rx_rate_limiter,
            tx_rate_limiter,
            rx_deferred_frame: false,
            rx_bytes_read: 0,
            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_headers: [0u8; frame_hdr_len()],
            irq_trigger: IrqTrigger::new().map_err(NetError::EventFd)?,
            config_space,
            guest_mac,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(NetError::EventFd)?,
            mmds_ns: None,
            metrics: NetMetricsPerDevice::alloc(id),
        })
    }

    /// Create a new virtio network device given the interface name.
    pub fn new(
        id: String,
        tap_if_name: &str,
        guest_mac: Option<MacAddr>,
        rx_rate_limiter: RateLimiter,
        tx_rate_limiter: RateLimiter,
    ) -> Result<Self, NetError> {
        let tap = Tap::open_named(tap_if_name).map_err(NetError::TapOpen)?;

        let vnet_hdr_size = i32::try_from(vnet_hdr_len()).unwrap();
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(NetError::TapSetVnetHdrSize)?;

        Self::new_with_tap(id, tap, guest_mac, rx_rate_limiter, tx_rate_limiter)
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the MAC of this net device.
    pub fn guest_mac(&self) -> Option<&MacAddr> {
        self.guest_mac.as_ref()
    }

    /// Provides the host IFACE name of this net device.
    pub fn iface_name(&self) -> String {
        self.tap.if_name_as_str().to_string()
    }

    /// Provides the MmdsNetworkStack of this net device.
    pub fn mmds_ns(&self) -> Option<&MmdsNetworkStack> {
        self.mmds_ns.as_ref()
    }

    /// Configures the `MmdsNetworkStack` to allow device to forward MMDS requests.
    /// If the device already supports MMDS, updates the IPv4 address.
    pub fn configure_mmds_network_stack(&mut self, ipv4_addr: Ipv4Addr, mmds: Arc<Mutex<Mmds>>) {
        if let Some(mmds_ns) = self.mmds_ns.as_mut() {
            mmds_ns.set_ipv4_addr(ipv4_addr);
        } else {
            self.mmds_ns = Some(MmdsNetworkStack::new_with_defaults(Some(ipv4_addr), mmds))
        }
    }

    /// Disables the `MmdsNetworkStack` to prevent device to forward MMDS requests.
    pub fn disable_mmds_network_stack(&mut self) {
        self.mmds_ns = None
    }

    /// Provides a reference to the configured RX rate limiter.
    pub fn rx_rate_limiter(&self) -> &RateLimiter {
        &self.rx_rate_limiter
    }

    /// Provides a reference to the configured TX rate limiter.
    pub fn tx_rate_limiter(&self) -> &RateLimiter {
        &self.tx_rate_limiter
    }

    /// Trigger queue notification for the guest if we used enough descriptors
    /// for the notification to be enabled.
    /// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-320005
    /// 2.6.7.1 Driver Requirements: Used Buffer Notification Suppression
    fn try_signal_queue(&mut self, queue_type: NetQueue) -> Result<(), DeviceError> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();

        let queue = match queue_type {
            NetQueue::Rx => &mut self.queues[RX_INDEX],
            NetQueue::Tx => &mut self.queues[TX_INDEX],
        };

        if queue.prepare_kick(mem) {
            self.irq_trigger
                .trigger_irq(IrqType::Vring)
                .map_err(|err| {
                    self.metrics.event_fails.inc();
                    DeviceError::FailedSignalingIrq(err)
                })?;
        }

        Ok(())
    }

    // Helper function to consume one op with `size` bytes from a rate limiter
    fn rate_limiter_consume_op(rate_limiter: &mut RateLimiter, size: u64) -> bool {
        if !rate_limiter.consume(1, TokenType::Ops) {
            return false;
        }

        if !rate_limiter.consume(size, TokenType::Bytes) {
            rate_limiter.manual_replenish(1, TokenType::Ops);
            return false;
        }

        true
    }

    // Helper function to replenish one operation with `size` bytes from a rate limiter
    fn rate_limiter_replenish_op(rate_limiter: &mut RateLimiter, size: u64) {
        rate_limiter.manual_replenish(1, TokenType::Ops);
        rate_limiter.manual_replenish(size, TokenType::Bytes);
    }

    // Attempts to copy a single frame into the guest if there is enough
    // rate limiting budget.
    // Returns true on successful frame delivery.
    fn rate_limited_rx_single_frame(&mut self) -> bool {
        if !Self::rate_limiter_consume_op(&mut self.rx_rate_limiter, self.rx_bytes_read as u64) {
            self.metrics.rx_rate_limiter_throttled.inc();
            return false;
        }

        // Attempt frame delivery.
        let success = self.write_frame_to_guest();

        // Undo the tokens consumption if guest delivery failed.
        if !success {
            // revert the rate limiting budget consumption
            Self::rate_limiter_replenish_op(&mut self.rx_rate_limiter, self.rx_bytes_read as u64);
        }

        success
    }

    /// Write a slice in a descriptor chain
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor chain is too short or
    /// an inappropriate (read only) descriptor is found in the chain
    fn write_to_descriptor_chain(
        mem: &GuestMemoryMmap,
        data: &[u8],
        head: DescriptorChain,
        net_metrics: &NetDeviceMetrics,
    ) -> Result<(), FrontendError> {
        let mut chunk = data;
        let mut next_descriptor = Some(head);

        while let Some(descriptor) = &next_descriptor {
            if !descriptor.is_write_only() {
                return Err(FrontendError::ReadOnlyDescriptor);
            }

            let len = std::cmp::min(chunk.len(), descriptor.len as usize);
            match mem.write_slice(&chunk[..len], descriptor.addr) {
                Ok(()) => {
                    net_metrics.rx_count.inc();
                    chunk = &chunk[len..];
                }
                Err(err) => {
                    error!("Failed to write slice: {:?}", err);
                    if let GuestMemoryError::PartialBuffer { .. } = err {
                        net_metrics.rx_partial_writes.inc();
                    }
                    return Err(FrontendError::GuestMemory(err));
                }
            }

            // If chunk is empty we are done here.
            if chunk.is_empty() {
                let len = data.len() as u64;
                net_metrics.rx_bytes_count.add(len);
                net_metrics.rx_packets_count.inc();
                return Ok(());
            }

            next_descriptor = descriptor.next_descriptor();
        }

        warn!("Receiving buffer is too small to hold frame of current size");
        Err(FrontendError::DescriptorChainTooSmall)
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn do_write_frame_to_guest(&mut self) -> Result<(), FrontendError> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();

        let queue = &mut self.queues[RX_INDEX];
        let head_descriptor = queue.pop_or_enable_notification(mem).ok_or_else(|| {
            self.metrics.no_rx_avail_buffer.inc();
            FrontendError::EmptyQueue
        })?;
        let head_index = head_descriptor.index;

        let result = Self::write_to_descriptor_chain(
            mem,
            &self.rx_frame_buf[..self.rx_bytes_read],
            head_descriptor,
            &self.metrics,
        );
        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() {
            self.metrics.rx_fails.inc();
            0
        } else {
            // Safe to unwrap because a frame must be smaller than 2^16 bytes.
            u32::try_from(self.rx_bytes_read).unwrap()
        };
        queue.add_used(mem, head_index, used_len).map_err(|err| {
            error!("Failed to add available descriptor {}: {}", head_index, err);
            FrontendError::AddUsed
        })?;

        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. In case of an error retries
    // the operation if possible. Returns true if the operation was successfull.
    fn write_frame_to_guest(&mut self) -> bool {
        let max_iterations = self.queues[RX_INDEX].actual_size();
        for _ in 0..max_iterations {
            match self.do_write_frame_to_guest() {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) | Err(FrontendError::AddUsed) => {
                    return false;
                }
                Err(_) => {
                    // retry
                    continue;
                }
            }
        }

        false
    }

    // Tries to detour the frame to MMDS and if MMDS doesn't accept it, sends it on the host TAP.
    //
    // Returns whether MMDS consumed the frame.
    fn write_to_mmds_or_tap(
        mmds_ns: Option<&mut MmdsNetworkStack>,
        rate_limiter: &mut RateLimiter,
        headers: &mut [u8],
        frame_iovec: &IoVecBuffer,
        tap: &mut Tap,
        guest_mac: Option<MacAddr>,
        net_metrics: &NetDeviceMetrics,
    ) -> Result<bool, NetError> {
        // Read the frame headers from the IoVecBuffer
        let max_header_len = headers.len();
        let header_len = frame_iovec
            .read_volatile_at(&mut &mut *headers, 0, max_header_len)
            .map_err(|err| {
                error!("Received malformed TX buffer: {:?}", err);
                net_metrics.tx_malformed_frames.inc();
                NetError::VnetHeaderMissing
            })?;

        let headers = frame_bytes_from_buf(&headers[..header_len]).map_err(|e| {
            error!("VNET headers missing in TX frame");
            net_metrics.tx_malformed_frames.inc();
            e
        })?;

        if let Some(ns) = mmds_ns {
            if ns.is_mmds_frame(headers) {
                let mut frame = vec![0u8; frame_iovec.len() as usize - vnet_hdr_len()];
                // Ok to unwrap here, because we are passing a buffer that has the exact size
                // of the `IoVecBuffer` minus the VNET headers.
                frame_iovec
                    .read_exact_volatile_at(&mut frame, vnet_hdr_len())
                    .unwrap();
                let _ = ns.detour_frame(&frame);
                METRICS.mmds.rx_accepted.inc();

                // MMDS frames are not accounted by the rate limiter.
                Self::rate_limiter_replenish_op(rate_limiter, u64::from(frame_iovec.len()));

                // MMDS consumed the frame.
                return Ok(true);
            }
        }

        // This frame goes to the TAP.

        // Check for guest MAC spoofing.
        if let Some(guest_mac) = guest_mac {
            let _ = EthernetFrame::from_bytes(headers).map(|eth_frame| {
                if guest_mac != eth_frame.src_mac() {
                    net_metrics.tx_spoofed_mac_count.inc();
                }
            });
        }

        let _metric = net_metrics.tap_write_agg.record_latency_metrics();
        match Self::write_tap(tap, frame_iovec) {
            Ok(_) => {
                let len = u64::from(frame_iovec.len());
                net_metrics.tx_bytes_count.add(len);
                net_metrics.tx_packets_count.inc();
                net_metrics.tx_count.inc();
            }
            Err(err) => {
                error!("Failed to write to tap: {:?}", err);
                net_metrics.tap_write_fails.inc();
            }
        };
        Ok(false)
    }

    // We currently prioritize packets from the MMDS over regular network packets.
    fn read_from_mmds_or_tap(&mut self) -> Result<usize, NetError> {
        if let Some(ns) = self.mmds_ns.as_mut() {
            if let Some(len) =
                ns.write_next_frame(frame_bytes_from_buf_mut(&mut self.rx_frame_buf)?)
            {
                let len = len.get();
                METRICS.mmds.tx_frames.inc();
                METRICS.mmds.tx_bytes.add(len as u64);
                init_vnet_hdr(&mut self.rx_frame_buf);
                return Ok(vnet_hdr_len() + len);
            }
        }

        self.read_tap().map_err(NetError::IO)
    }

    fn process_rx(&mut self) -> Result<(), DeviceError> {
        // Read as many frames as possible.
        loop {
            match self.read_from_mmds_or_tap() {
                Ok(count) => {
                    self.rx_bytes_read = count;
                    self.metrics.rx_count.inc();
                    if !self.rate_limited_rx_single_frame() {
                        self.rx_deferred_frame = true;
                        break;
                    }
                }
                Err(NetError::IO(err)) => {
                    // The tap device is non-blocking, so any error aside from EAGAIN is
                    // unexpected.
                    match err.raw_os_error() {
                        Some(err) if err == EAGAIN => (),
                        _ => {
                            error!("Failed to read tap: {:?}", err);
                            self.metrics.tap_read_fails.inc();
                            return Err(DeviceError::FailedReadTap);
                        }
                    };
                    break;
                }
                Err(err) => {
                    error!("Spurious error in network RX: {:?}", err);
                }
            }
        }

        self.try_signal_queue(NetQueue::Rx)
    }

    // Process the deferred frame first, then continue reading from tap.
    fn handle_deferred_frame(&mut self) -> Result<(), DeviceError> {
        if self.rate_limited_rx_single_frame() {
            self.rx_deferred_frame = false;
            // process_rx() was interrupted possibly before consuming all
            // packets in the tap; try continuing now.
            return self.process_rx();
        }

        self.try_signal_queue(NetQueue::Rx)
    }

    fn resume_rx(&mut self) -> Result<(), DeviceError> {
        if self.rx_deferred_frame {
            self.handle_deferred_frame()
        } else {
            Ok(())
        }
    }

    fn process_tx(&mut self) -> Result<(), DeviceError> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();

        // The MMDS network stack works like a state machine, based on synchronous calls, and
        // without being added to any event loop. If any frame is accepted by the MMDS, we also
        // trigger a process_rx() which checks if there are any new frames to be sent, starting
        // with the MMDS network stack.
        let mut process_rx_for_mmds = false;
        let mut used_any = false;
        let tx_queue = &mut self.queues[TX_INDEX];

        while let Some(head) = tx_queue.pop_or_enable_notification(mem) {
            self.metrics
                .tx_remaining_reqs_count
                .add(tx_queue.len(mem).into());
            let head_index = head.index;
            // Parse IoVecBuffer from descriptor head
            let buffer = match IoVecBuffer::from_descriptor_chain(head) {
                Ok(buffer) => buffer,
                Err(_) => {
                    self.metrics.tx_fails.inc();
                    tx_queue
                        .add_used(mem, head_index, 0)
                        .map_err(DeviceError::QueueError)?;
                    continue;
                }
            };

            // We only handle frames that are up to MAX_BUFFER_SIZE
            if buffer.len() as usize > MAX_BUFFER_SIZE {
                error!("net: received too big frame from driver");
                self.metrics.tx_malformed_frames.inc();
                tx_queue
                    .add_used(mem, head_index, 0)
                    .map_err(DeviceError::QueueError)?;
                continue;
            }

            if !Self::rate_limiter_consume_op(&mut self.tx_rate_limiter, u64::from(buffer.len())) {
                tx_queue.undo_pop();
                self.metrics.tx_rate_limiter_throttled.inc();
                break;
            }

            let frame_consumed_by_mmds = Self::write_to_mmds_or_tap(
                self.mmds_ns.as_mut(),
                &mut self.tx_rate_limiter,
                &mut self.tx_frame_headers,
                &buffer,
                &mut self.tap,
                self.guest_mac,
                &self.metrics,
            )
            .unwrap_or(false);
            if frame_consumed_by_mmds && !self.rx_deferred_frame {
                // MMDS consumed this frame/request, let's also try to process the response.
                process_rx_for_mmds = true;
            }

            tx_queue
                .add_used(mem, head_index, 0)
                .map_err(DeviceError::QueueError)?;
            used_any = true;
        }

        if !used_any {
            self.metrics.no_tx_avail_buffer.inc();
        }

        self.try_signal_queue(NetQueue::Tx)?;

        // An incoming frame for the MMDS may trigger the transmission of a new message.
        if process_rx_for_mmds {
            self.process_rx()
        } else {
            Ok(())
        }
    }

    /// Builds the offload features we will setup on the TAP device based on the features that the
    /// guest supports.
    fn build_tap_offload_features(guest_supported_features: u64) -> u32 {
        let add_if_supported =
            |tap_features: &mut u32, supported_features: u64, tap_flag: u32, virtio_flag: u32| {
                if supported_features & (1 << virtio_flag) != 0 {
                    *tap_features |= tap_flag;
                }
            };

        let mut tap_features: u32 = 0;

        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            gen::TUN_F_CSUM,
            VIRTIO_NET_F_CSUM,
        );
        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            gen::TUN_F_UFO,
            VIRTIO_NET_F_GUEST_UFO,
        );
        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            gen::TUN_F_TSO4,
            VIRTIO_NET_F_GUEST_TSO4,
        );
        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            gen::TUN_F_TSO6,
            VIRTIO_NET_F_GUEST_TSO6,
        );

        tap_features
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
    fn read_tap(&mut self) -> std::io::Result<usize> {
        self.tap.read(&mut self.rx_frame_buf)
    }

    #[cfg(not(test))]
    fn write_tap(tap: &mut Tap, buf: &IoVecBuffer) -> std::io::Result<usize> {
        tap.write_iovec(buf)
    }

    /// Process a single RX queue event.
    ///
    /// This is called by the event manager responding to the guest adding a new
    /// buffer in the RX queue.
    pub fn process_rx_queue_event(&mut self) {
        self.metrics.rx_queue_event_count.inc();

        if let Err(err) = self.queue_evts[RX_INDEX].read() {
            // rate limiters present but with _very high_ allowed rate
            error!("Failed to get rx queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if self.rx_rate_limiter.is_blocked() {
            self.metrics.rx_rate_limiter_throttled.inc();
        } else {
            // If the limiter is not blocked, resume the receiving of bytes.
            self.resume_rx()
                .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
        }
    }

    pub fn process_tap_rx_event(&mut self) {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();
        self.metrics.rx_tap_event_count.inc();

        // While there are no available RX queue buffers and there's a deferred_frame
        // don't process any more incoming. Otherwise start processing a frame. In the
        // process the deferred_frame flag will be set in order to avoid freezing the
        // RX queue.
        if self.queues[RX_INDEX].is_empty(mem) && self.rx_deferred_frame {
            self.metrics.no_rx_avail_buffer.inc();
            return;
        }

        // While limiter is blocked, don't process any more incoming.
        if self.rx_rate_limiter.is_blocked() {
            self.metrics.rx_rate_limiter_throttled.inc();
            return;
        }

        if self.rx_deferred_frame
        // Process a deferred frame first if available. Don't read from tap again
        // until we manage to receive this deferred frame.
        {
            self.handle_deferred_frame()
                .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
        } else {
            self.process_rx()
                .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
        }
    }

    /// Process a single TX queue event.
    ///
    /// This is called by the event manager responding to the guest adding a new
    /// buffer in the TX queue.
    pub fn process_tx_queue_event(&mut self) {
        self.metrics.tx_queue_event_count.inc();
        if let Err(err) = self.queue_evts[TX_INDEX].read() {
            error!("Failed to get tx queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if !self.tx_rate_limiter.is_blocked()
        // If the limiter is not blocked, continue transmitting bytes.
        {
            self.process_tx()
                .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
        } else {
            self.metrics.tx_rate_limiter_throttled.inc();
        }
    }

    pub fn process_rx_rate_limiter_event(&mut self) {
        self.metrics.rx_event_rate_limiter_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.

        match self.rx_rate_limiter.event_handler() {
            Ok(_) => {
                // There might be enough budget now to receive the frame.
                self.resume_rx()
                    .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
            }
            Err(err) => {
                error!("Failed to get rx rate-limiter event: {:?}", err);
                self.metrics.event_fails.inc();
            }
        }
    }

    pub fn process_tx_rate_limiter_event(&mut self) {
        self.metrics.tx_rate_limiter_event_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        match self.tx_rate_limiter.event_handler() {
            Ok(_) => {
                // There might be enough budget now to send the frame.
                self.process_tx()
                    .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
            }
            Err(err) => {
                error!("Failed to get tx rate-limiter event: {:?}", err);
                self.metrics.event_fails.inc();
            }
        }
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) {
        let _ = self.resume_rx();
        let _ = self.process_tx();
    }
}

impl VirtioDevice for Net {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

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

    fn interrupt_trigger(&self) -> &IrqTrigger {
        &self.irq_trigger
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Some(config_space_bytes) = self.config_space.as_slice().get(u64_to_usize(offset)..) {
            let len = config_space_bytes.len().min(data.len());
            data[..len].copy_from_slice(&config_space_bytes[..len]);
        } else {
            error!("Failed to read config space");
            self.metrics.cfg_fails.inc();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let config_space_bytes = self.config_space.as_mut_slice();
        let start = usize::try_from(offset).ok();
        let end = start.and_then(|s| s.checked_add(data.len()));
        let Some(dst) = start
            .zip(end)
            .and_then(|(start, end)| config_space_bytes.get_mut(start..end))
        else {
            error!("Failed to write config space");
            self.metrics.cfg_fails.inc();
            return;
        };

        dst.copy_from_slice(data);
        self.guest_mac = Some(self.config_space.guest_mac);
        self.metrics.mac_address_updates.inc();
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError> {
        let event_idx = self.has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX));
        if event_idx {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        let supported_flags: u32 = Net::build_tap_offload_features(self.acked_features);
        self.tap
            .set_offload(supported_flags)
            .map_err(super::super::ActivateError::TapSetOffload)?;

        if self.activate_evt.write(1).is_err() {
            self.metrics.activate_fails.inc();
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
#[macro_use]
pub mod tests {
    use std::io::Read;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;
    use std::{io, mem, thread};

    use utils::net::mac::{MacAddr, MAC_ADDR_LEN};

    use super::*;
    use crate::check_metric_after_block;
    use crate::devices::virtio::gen::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
    use crate::devices::virtio::iovec::IoVecBuffer;
    use crate::devices::virtio::net::device::{
        frame_bytes_from_buf, frame_bytes_from_buf_mut, frame_hdr_len, init_vnet_hdr, vnet_hdr_len,
    };
    use crate::devices::virtio::net::test_utils::test::TestHelper;
    use crate::devices::virtio::net::test_utils::{
        default_net, if_index, inject_tap_tx_frame, set_mac, NetEvent, NetQueue, ReadTapMock,
        TapTrafficSimulator, WriteTapMock,
    };
    use crate::devices::virtio::net::NET_QUEUE_SIZES;
    use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::dumbo::pdu::arp::{EthIPv4ArpFrame, ETH_IPV4_FRAME_LEN};
    use crate::dumbo::pdu::ethernet::ETHERTYPE_ARP;
    use crate::dumbo::EthernetFrame;
    use crate::logger::IncMetric;
    use crate::rate_limiter::{BucketUpdate, RateLimiter, TokenBucket, TokenType};
    use crate::vstate::memory::{Address, GuestMemory};

    impl Net {
        pub(crate) fn read_tap(&mut self) -> io::Result<usize> {
            match &self.tap.mocks.read_tap {
                ReadTapMock::MockFrame(frame) => {
                    self.rx_frame_buf[..frame.len()].copy_from_slice(frame);
                    Ok(frame.len())
                }
                ReadTapMock::Failure => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Read tap synthetically failed.",
                )),
                ReadTapMock::TapFrame => self.tap.read(&mut self.rx_frame_buf),
            }
        }

        pub(crate) fn write_tap(tap: &mut Tap, buf: &IoVecBuffer) -> io::Result<usize> {
            match tap.mocks.write_tap {
                WriteTapMock::Success => tap.write_iovec(buf),
                WriteTapMock::Failure => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Write tap mock failure.",
                )),
            }
        }
    }

    #[test]
    fn test_vnet_helpers() {
        let mut frame_buf = vec![42u8; vnet_hdr_len() - 1];
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
        let mut net = default_net();
        set_mac(&mut net, MacAddr::from_str("11:22:33:44:55:66").unwrap());
        assert_eq!(net.device_type(), TYPE_NET);
    }

    #[test]
    fn test_virtio_device_features() {
        let mut net = default_net();
        set_mac(&mut net, MacAddr::from_str("11:22:33:44:55:66").unwrap());

        // Test `features()` and `ack_features()`.
        let features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_TSO6
            | 1 << VIRTIO_NET_F_MAC
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_TSO6
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_EVENT_IDX;

        assert_eq!(
            net.avail_features_by_page(0),
            (features & 0xFFFFFFFF) as u32,
        );
        assert_eq!(net.avail_features_by_page(1), (features >> 32) as u32);
        for i in 2..10 {
            assert_eq!(net.avail_features_by_page(i), 0u32);
        }

        for i in 0..10 {
            net.ack_features_by_page(i, u32::MAX);
        }

        assert_eq!(net.acked_features, features);
    }

    #[test]
    // Test that `Net::build_tap_offload_features` creates the TAP offload features that we expect
    // it to do, based on the available guest features
    fn test_build_tap_offload_features_all() {
        let supported_features = 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_TSO6;
        let expected_tap_features =
            gen::TUN_F_CSUM | gen::TUN_F_UFO | gen::TUN_F_TSO4 | gen::TUN_F_TSO6;
        let supported_flags = Net::build_tap_offload_features(supported_features);

        assert_eq!(supported_flags, expected_tap_features);
    }

    #[test]
    // Same as before, however, using each supported feature one by one.
    fn test_build_tap_offload_features_one_by_one() {
        let features = [
            (1 << VIRTIO_NET_F_CSUM, gen::TUN_F_CSUM),
            (1 << VIRTIO_NET_F_GUEST_UFO, gen::TUN_F_UFO),
            (1 << VIRTIO_NET_F_GUEST_TSO4, gen::TUN_F_TSO4),
        ];
        for (virtio_flag, tap_flag) in features {
            let supported_flags = Net::build_tap_offload_features(virtio_flag);
            assert_eq!(supported_flags, tap_flag);
        }
    }

    #[test]
    fn test_virtio_device_read_config() {
        let mut net = default_net();
        set_mac(&mut net, MacAddr::from_str("11:22:33:44:55:66").unwrap());

        // Test `read_config()`. This also validates the MAC was properly configured.
        let mac = MacAddr::from_str("11:22:33:44:55:66").unwrap();
        let mut config_mac = [0u8; MAC_ADDR_LEN as usize];
        net.read_config(0, &mut config_mac);
        assert_eq!(&config_mac, mac.get_bytes());

        // Invalid read.
        config_mac = [0u8; MAC_ADDR_LEN as usize];
        net.read_config(u64::from(MAC_ADDR_LEN), &mut config_mac);
        assert_eq!(config_mac, [0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
    }

    #[test]
    fn test_virtio_device_rewrite_config() {
        let mut net = default_net();
        set_mac(&mut net, MacAddr::from_str("11:22:33:44:55:66").unwrap());

        let new_config: [u8; MAC_ADDR_LEN as usize] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        net.write_config(0, &new_config);
        let mut new_config_read = [0u8; MAC_ADDR_LEN as usize];
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);

        // Check that the guest MAC was updated.
        let expected_guest_mac = MacAddr::from_bytes_unchecked(&new_config);
        assert_eq!(expected_guest_mac, net.guest_mac.unwrap());
        assert_eq!(net.metrics.mac_address_updates.count(), 1);

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
        new_config_read = [0u8; MAC_ADDR_LEN as usize];
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);

        // Large offset that may cause an overflow.
        net.write_config(u64::MAX, &new_config);
        // Verify old config was untouched.
        new_config_read = [0u8; MAC_ADDR_LEN as usize];
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);
    }

    #[test]
    fn test_rx_missing_queue_signal() {
        let mut th = TestHelper::get_default();
        th.activate_net();

        th.add_desc_chain(NetQueue::Rx, 0, &[(0, 4096, VIRTQ_DESC_F_WRITE)]);
        th.net().queue_evts[RX_INDEX].read().unwrap();
        check_metric_after_block!(
            th.net().metrics.event_fails,
            1,
            th.simulate_event(NetEvent::RxQueue)
        );

        // Check that the used queue didn't advance.
        assert_eq!(th.rxq.used.idx.get(), 0);
    }

    #[test]
    fn test_rx_read_only_descriptor() {
        let mut th = TestHelper::get_default();
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
        th.rxq.check_used_elem(0, 0, 0);

        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_short_writable_descriptor() {
        let mut th = TestHelper::get_default();
        th.activate_net();

        th.add_desc_chain(NetQueue::Rx, 0, &[(0, 100, VIRTQ_DESC_F_WRITE)]);
        let frame = th.check_rx_deferred_frame(1000);
        th.rxq.check_used_elem(0, 0, 0);

        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_partial_write() {
        let mut th = TestHelper::get_default();
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
        let frame = th.check_rx_deferred_frame(1000);
        th.rxq.check_used_elem(0, 0, 0);

        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_retry() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        th.net().tap.mocks.set_read_tap(ReadTapMock::TapFrame);

        // Add invalid descriptor chain - read only descriptor.
        th.add_desc_chain(
            NetQueue::Rx,
            0,
            &[
                (0, 100, VIRTQ_DESC_F_WRITE),
                (1, 100, 0),
                (2, 1000, VIRTQ_DESC_F_WRITE),
            ],
        );
        // Add invalid descriptor chain - too short.
        th.add_desc_chain(NetQueue::Rx, 1200, &[(3, 100, VIRTQ_DESC_F_WRITE)]);
        // Add invalid descriptor chain - invalid memory offset.
        th.add_desc_chain(
            NetQueue::Rx,
            th.mem.last_addr().raw_value(),
            &[(4, 1000, VIRTQ_DESC_F_WRITE)],
        );

        // Add valid descriptor chain.
        th.add_desc_chain(NetQueue::Rx, 1300, &[(5, 1000, VIRTQ_DESC_F_WRITE)]);

        // Inject frame to tap and run epoll.
        let frame = inject_tap_tx_frame(&th.net(), 1000);
        check_metric_after_block!(
            th.net().metrics.rx_packets_count,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 4);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        // Check that the invalid descriptor chains have been discarded
        th.rxq.check_used_elem(0, 0, 0);
        th.rxq.check_used_elem(1, 3, 0);
        th.rxq.check_used_elem(2, 4, 0);
        // Check that the frame wasn't deferred.
        assert!(!th.net().rx_deferred_frame);
        // Check that the frame has been written successfully to the valid Rx descriptor chain.
        th.rxq
            .check_used_elem(3, 5, frame.len().try_into().unwrap());
        th.rxq.dtable[5].check_data(&frame);
    }

    #[test]
    fn test_rx_complex_desc_chain() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        th.net().tap.mocks.set_read_tap(ReadTapMock::TapFrame);

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
        let frame = inject_tap_tx_frame(&th.net(), 1000);
        check_metric_after_block!(
            th.net().metrics.rx_packets_count,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the frame wasn't deferred.
        assert!(!th.net().rx_deferred_frame);
        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 1);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        // Check that the frame has been written successfully to the Rx descriptor chain.
        th.rxq
            .check_used_elem(0, 3, frame.len().try_into().unwrap());
        th.rxq.dtable[3].check_data(&frame[..100]);
        th.rxq.dtable[5].check_data(&frame[100..150]);
        th.rxq.dtable[11].check_data(&frame[150..]);
    }

    #[test]
    fn test_rx_multiple_frames() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        th.net().tap.mocks.set_read_tap(ReadTapMock::TapFrame);

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
        let frame_1 = inject_tap_tx_frame(&th.net(), 200);
        let frame_2 = inject_tap_tx_frame(&th.net(), 300);
        check_metric_after_block!(
            th.net().metrics.rx_packets_count,
            2,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the frames weren't deferred.
        assert!(!th.net().rx_deferred_frame);
        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 2);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        // Check that the 1st frame was written successfully to the 1st Rx descriptor chain.
        th.rxq
            .check_used_elem(0, 0, frame_1.len().try_into().unwrap());
        th.rxq.dtable[0].check_data(&frame_1);
        th.rxq.dtable[1].check_data(&[0; 500]);
        // Check that the 2nd frame was written successfully to the 2nd Rx descriptor chain.
        th.rxq
            .check_used_elem(1, 2, frame_2.len().try_into().unwrap());
        th.rxq.dtable[2].check_data(&frame_2);
        th.rxq.dtable[3].check_data(&[0; 500]);
    }

    #[test]
    fn test_tx_missing_queue_signal() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        th.add_desc_chain(NetQueue::Tx, 0, &[(0, 4096, 0)]);
        th.net().queue_evts[TX_INDEX].read().unwrap();
        check_metric_after_block!(
            th.net().metrics.event_fails,
            1,
            th.simulate_event(NetEvent::TxQueue)
        );

        // Check that the used queue didn't advance.
        assert_eq!(th.txq.used.idx.get(), 0);
        // Check that the frame wasn't sent to the tap.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut [0; 1000]));
    }

    #[test]
    fn test_tx_writeable_descriptor() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        let desc_list = [(0, 100, 0), (1, 100, VIRTQ_DESC_F_WRITE), (2, 500, 0)];
        th.add_desc_chain(NetQueue::Tx, 0, &desc_list);
        th.write_tx_frame(&desc_list, 700);
        th.event_manager.run_with_timeout(100).unwrap();

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        th.txq.check_used_elem(0, 0, 0);
        // Check that the frame was skipped.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut []));
    }

    #[test]
    fn test_tx_short_frame() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // Send an invalid frame (too small, VNET header missing).
        th.add_desc_chain(NetQueue::Tx, 0, &[(0, 1, 0)]);
        check_metric_after_block!(
            th.net().metrics.tx_malformed_frames,
            1,
            th.event_manager.run_with_timeout(100)
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        th.txq.check_used_elem(0, 0, 0);
        // Check that the frame was skipped.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut []));
    }

    #[test]
    fn test_tx_big_frame() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // Send an invalid frame (too big, maximum buffer is MAX_BUFFER_SIZE).
        th.add_desc_chain(
            NetQueue::Tx,
            0,
            &[(0, (MAX_BUFFER_SIZE + 1).try_into().unwrap(), 0)],
        );
        check_metric_after_block!(
            th.net().metrics.tx_malformed_frames,
            1,
            th.event_manager.run_with_timeout(100)
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        th.txq.check_used_elem(0, 0, 0);
        // Check that the frame was skipped.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut []));
    }

    #[test]
    fn test_tx_empty_frame() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // Send an invalid frame (too small, VNET header missing).
        th.add_desc_chain(NetQueue::Tx, 0, &[(0, 0, 0)]);
        check_metric_after_block!(
            th.net().metrics.tx_malformed_frames,
            1,
            th.event_manager.run_with_timeout(100)
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        th.txq.check_used_elem(0, 0, 0);
        // Check that the frame was skipped.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut []));
    }

    #[test]
    fn test_tx_retry() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // Add invalid descriptor chain - writeable descriptor.
        th.add_desc_chain(
            NetQueue::Tx,
            0,
            &[(0, 100, 0), (1, 100, VIRTQ_DESC_F_WRITE), (2, 500, 0)],
        );
        // Add invalid descriptor chain - invalid memory.
        th.add_desc_chain(NetQueue::Tx, th.mem.last_addr().raw_value(), &[(3, 100, 0)]);
        // Add invalid descriptor chain - too short.
        th.add_desc_chain(NetQueue::Tx, 700, &[(0, 1, 0)]);

        // Add valid descriptor chain
        let desc_list = [(4, 1000, 0)];
        th.add_desc_chain(NetQueue::Tx, 0, &desc_list);
        let frame = th.write_tx_frame(&desc_list, 1000);

        // One frame is valid, one will not be handled because it includes write-only memory
        // so that leaves us with 2 malformed (no vnet header) frames.
        check_metric_after_block!(
            th.net().metrics.tx_malformed_frames,
            2,
            th.event_manager.run_with_timeout(100)
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 4);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        th.txq.check_used_elem(3, 4, 0);
        // Check that the valid frame was sent to the tap.
        let mut buf = vec![0; 1000];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut buf[vnet_hdr_len()..]));
        assert_eq!(&buf, &frame);
        // Check that no other frame was sent to the tap.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut []));
    }

    #[test]
    fn test_tx_complex_descriptor() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // Add gaps between the descriptor ids in order to ensure that we follow
        // the `next` field.
        let desc_list = [(3, 100, 0), (5, 50, 0), (11, 850, 0)];
        th.add_desc_chain(NetQueue::Tx, 0, &desc_list);
        let frame = th.write_tx_frame(&desc_list, 1000);

        check_metric_after_block!(
            th.net().metrics.tx_packets_count,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        th.txq.check_used_elem(0, 3, 0);
        // Check that the frame was sent to the tap.
        let mut buf = vec![0; 1000];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut buf[vnet_hdr_len()..]));
        assert_eq!(&buf[..1000], &frame[..1000]);
    }

    #[test]
    fn test_tx_tap_failure() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        th.net().tap.mocks.set_write_tap(WriteTapMock::Failure);

        let desc_list = [(0, 1000, 0)];
        th.add_desc_chain(NetQueue::Tx, 0, &desc_list);
        let _ = th.write_tx_frame(&desc_list, 1000);

        check_metric_after_block!(
            th.net().metrics.tap_write_fails,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        th.txq.check_used_elem(0, 0, 0);
    }

    #[test]
    fn test_tx_multiple_frame() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // Write the first frame to the Tx queue
        let desc_list = [(0, 50, 0), (1, 100, 0), (2, 150, 0)];
        th.add_desc_chain(NetQueue::Tx, 0, &desc_list);
        let frame_1 = th.write_tx_frame(&desc_list, 300);
        // Write the second frame to the Tx queue
        let desc_list = [(3, 100, 0), (4, 200, 0), (5, 300, 0)];
        th.add_desc_chain(NetQueue::Tx, 500, &desc_list);
        let frame_2 = th.write_tx_frame(&desc_list, 600);

        check_metric_after_block!(
            th.net().metrics.tx_packets_count,
            2,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 2);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        th.txq.check_used_elem(0, 0, 0);
        th.txq.check_used_elem(1, 3, 0);
        // Check that the first frame was sent to the tap.
        let mut buf = vec![0; 300];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut buf[vnet_hdr_len()..]));
        assert_eq!(&buf[..300], &frame_1[..300]);
        // Check that the second frame was sent to the tap.
        let mut buf = vec![0; 600];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut buf[vnet_hdr_len()..]));
        assert_eq!(&buf[..600], &frame_2[..600]);
    }

    fn create_arp_request(
        src_mac: MacAddr,
        src_ip: Ipv4Addr,
        dst_mac: MacAddr,
        dst_ip: Ipv4Addr,
    ) -> ([u8; MAX_BUFFER_SIZE], usize) {
        let mut frame_buf = [b'\0'; MAX_BUFFER_SIZE];

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
        let frame_len = vnet_hdr_len() + frame.payload_offset() + ETH_IPV4_FRAME_LEN;

        // Create the ARP request.
        let arp_request =
            EthIPv4ArpFrame::write_request(frame.payload_mut(), src_mac, src_ip, dst_mac, dst_ip);
        // Validate success.
        arp_request.unwrap();

        (frame_buf, frame_len)
    }

    #[test]
    fn test_mmds_detour_and_injection() {
        let mut net = default_net();

        let src_mac = MacAddr::from_str("11:11:11:11:11:11").unwrap();
        let src_ip = Ipv4Addr::new(10, 1, 2, 3);
        let dst_mac = MacAddr::from_str("22:22:22:22:22:22").unwrap();
        let dst_ip = Ipv4Addr::new(169, 254, 169, 254);

        let (frame_buf, frame_len) = create_arp_request(src_mac, src_ip, dst_mac, dst_ip);
        let buffer = IoVecBuffer::from(&frame_buf[..frame_len]);

        let mut headers = vec![0; frame_hdr_len()];
        buffer.read_exact_volatile_at(&mut headers, 0).unwrap();

        // Call the code which sends the packet to the host or MMDS.
        // Validate the frame was consumed by MMDS and that the metrics reflect that.
        check_metric_after_block!(
            &METRICS.mmds.rx_accepted,
            1,
            assert!(Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &mut headers,
                &buffer,
                &mut net.tap,
                Some(src_mac),
                &net.metrics,
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
        let mut net = default_net();

        let guest_mac = MacAddr::from_str("11:11:11:11:11:11").unwrap();
        let not_guest_mac = MacAddr::from_str("33:33:33:33:33:33").unwrap();
        let guest_ip = Ipv4Addr::new(10, 1, 2, 3);
        let dst_mac = MacAddr::from_str("22:22:22:22:22:22").unwrap();
        let dst_ip = Ipv4Addr::new(10, 1, 1, 1);

        let (frame_buf, frame_len) = create_arp_request(guest_mac, guest_ip, dst_mac, dst_ip);
        let buffer = IoVecBuffer::from(&frame_buf[..frame_len]);
        let mut headers = vec![0; frame_hdr_len()];

        // Check that a legit MAC doesn't affect the spoofed MAC metric.
        check_metric_after_block!(
            net.metrics.tx_spoofed_mac_count,
            0,
            Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &mut headers,
                &buffer,
                &mut net.tap,
                Some(guest_mac),
                &net.metrics,
            )
        );

        // Check that a spoofed MAC increases our spoofed MAC metric.
        check_metric_after_block!(
            net.metrics.tx_spoofed_mac_count,
            1,
            Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &mut headers,
                &buffer,
                &mut net.tap,
                Some(not_guest_mac),
                &net.metrics,
            )
        );
    }

    #[test]
    fn test_process_error_cases() {
        let mut th = TestHelper::get_default();
        th.activate_net();

        // RX rate limiter events should error since the limiter is not blocked.
        // Validate that the event failed and failure was properly accounted for.
        check_metric_after_block!(
            th.net().metrics.event_fails,
            1,
            th.simulate_event(NetEvent::RxRateLimiter)
        );

        // TX rate limiter events should error since the limiter is not blocked.
        // Validate that the event failed and failure was properly accounted for.
        check_metric_after_block!(
            th.net().metrics.event_fails,
            1,
            th.simulate_event(NetEvent::TxRateLimiter)
        );
    }

    // Cannot easily test failures for:
    //  * queue_evt.read (rx and tx)
    //  * interrupt_evt.write
    #[test]
    fn test_read_tap_fail_event_handler() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        th.net().tap.mocks.set_read_tap(ReadTapMock::Failure);

        // The RX queue is empty and rx_deffered_frame is set.
        th.net().rx_deferred_frame = true;
        check_metric_after_block!(
            th.net().metrics.no_rx_avail_buffer,
            1,
            th.simulate_event(NetEvent::Tap)
        );

        // We need to set this here to false, otherwise the device will try to
        // handle a deferred frame, it will fail and will never try to read from
        // the tap.
        th.net().rx_deferred_frame = false;

        // Fake an avail buffer; this time, tap reading should error out.
        th.rxq.avail.idx.set(1);
        check_metric_after_block!(
            th.net().metrics.tap_read_fails,
            1,
            th.simulate_event(NetEvent::Tap)
        );
    }

    #[test]
    fn test_deferred_frame() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        th.net().tap.mocks.set_read_tap(ReadTapMock::TapFrame);

        let rx_packets_count = th.net().metrics.rx_packets_count.count();
        let _ = inject_tap_tx_frame(&th.net(), 1000);
        // Trigger a Tap event that. This should fail since there
        // are not any available descriptors in the queue
        check_metric_after_block!(
            th.net().metrics.no_rx_avail_buffer,
            1,
            th.simulate_event(NetEvent::Tap)
        );
        // The frame we read from the tap should be deferred now and
        // no frames should have been transmitted
        assert!(th.net().rx_deferred_frame);
        assert_eq!(th.net().metrics.rx_packets_count.count(), rx_packets_count);

        // Let's add a second frame, which should really have the same
        // fate.
        let _ = inject_tap_tx_frame(&th.net(), 1000);

        // Adding a descriptor in the queue. This should handle the first deferred
        // frame. However, this should try to handle the second tap as well and fail
        // since there's only one Descriptor Chain in the queue.
        th.add_desc_chain(NetQueue::Rx, 0, &[(0, 4096, VIRTQ_DESC_F_WRITE)]);
        check_metric_after_block!(
            th.net().metrics.no_rx_avail_buffer,
            1,
            th.simulate_event(NetEvent::Tap)
        );
        // We should still have a deferred frame
        assert!(th.net().rx_deferred_frame);
        // However, we should have delivered the first frame
        assert_eq!(
            th.net().metrics.rx_packets_count.count(),
            rx_packets_count + 1
        );

        // Let's add one more descriptor and try to handle the last frame as well.
        th.add_desc_chain(NetQueue::Rx, 0, &[(0, 4096, VIRTQ_DESC_F_WRITE)]);
        check_metric_after_block!(
            th.net().metrics.rx_packets_count,
            1,
            th.simulate_event(NetEvent::RxQueue)
        );

        // We should be done with any deferred frame
        assert!(!th.net().rx_deferred_frame);
    }

    #[test]
    fn test_rx_rate_limiter_handling() {
        let mut th = TestHelper::get_default();
        th.activate_net();

        th.net().rx_rate_limiter = RateLimiter::new(0, 0, 0, 0, 0, 0).unwrap();
        // There is no actual event on the rate limiter's timerfd.
        check_metric_after_block!(
            th.net().metrics.event_fails,
            1,
            th.simulate_event(NetEvent::RxRateLimiter)
        );
    }

    #[test]
    fn test_tx_rate_limiter_handling() {
        let mut th = TestHelper::get_default();
        th.activate_net();

        th.net().tx_rate_limiter = RateLimiter::new(0, 0, 0, 0, 0, 0).unwrap();
        th.simulate_event(NetEvent::TxRateLimiter);
        // There is no actual event on the rate limiter's timerfd.
        check_metric_after_block!(
            th.net().metrics.event_fails,
            1,
            th.simulate_event(NetEvent::TxRateLimiter)
        );
    }

    #[test]
    fn test_bandwidth_rate_limiter() {
        let mut th = TestHelper::get_default();
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
                assert_eq!(th.net().metrics.tx_rate_limiter_throttled.count(), 1);
                // make sure the data is still queued for processing
                assert_eq!(th.txq.used.idx.get(), 0);
            }

            // A second TX queue event should be throttled too
            {
                th.add_desc_chain(NetQueue::Tx, 0, &[(1, 1024, 0)]);
                // trigger the RX queue event handler
                th.simulate_event(NetEvent::TxQueue);

                assert_eq!(th.net().metrics.tx_rate_limiter_throttled.count(), 2);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following TX procedure should succeed because bandwidth should now be available
            {
                // tx_count increments 1 from write_to_mmds_or_tap()
                check_metric_after_block!(
                    th.net().metrics.tx_count,
                    1,
                    th.simulate_event(NetEvent::TxRateLimiter)
                );
                // This should be still blocked. We managed to send the first frame, but
                // not enough budget for the second
                assert!(th.net().tx_rate_limiter.is_blocked());
                // make sure the data queue advanced
                assert_eq!(th.txq.used.idx.get(), 1);
            }

            thread::sleep(Duration::from_millis(200));

            // following TX procedure should succeed to handle the second frame as well
            {
                // tx_count increments 1 from write_to_mmds_or_tap()
                check_metric_after_block!(
                    th.net().metrics.tx_count,
                    1,
                    th.simulate_event(NetEvent::TxRateLimiter)
                );
                // validate the rate_limiter is no longer blocked
                assert!(!th.net().tx_rate_limiter.is_blocked());
                // make sure the data queue advance one more place
                assert_eq!(th.txq.used.idx.get(), 2);
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
                assert_eq!(th.net().metrics.rx_rate_limiter_throttled.count(), 1);
                assert!(th.net().rx_deferred_frame);
                // assert that no operation actually completed (limiter blocked it)
                assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
                // make sure the data is still queued for processing
                assert_eq!(th.rxq.used.idx.get(), 0);
            }

            // An RX queue event should be throttled too
            {
                // trigger the RX queue event handler
                th.simulate_event(NetEvent::RxQueue);

                assert_eq!(th.net().metrics.rx_rate_limiter_throttled.count(), 2);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following RX procedure should succeed because bandwidth should now be available
            {
                let frame = &th.net().tap.mocks.read_tap.mock_frame();
                // no longer throttled
                check_metric_after_block!(
                    th.net().metrics.rx_rate_limiter_throttled,
                    0,
                    th.simulate_event(NetEvent::RxRateLimiter)
                );
                // validate the rate_limiter is no longer blocked
                assert!(!th.net().rx_rate_limiter.is_blocked());
                // make sure the virtio queue operation completed this time
                assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
                // make sure the data queue advanced
                assert_eq!(th.rxq.used.idx.get(), 1);
                th.rxq
                    .check_used_elem(0, 0, frame.len().try_into().unwrap());
                th.rxq.dtable[0].check_data(frame);
            }
        }
    }

    #[test]
    fn test_ops_rate_limiter() {
        let mut th = TestHelper::get_default();
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
                    th.net().metrics.tx_rate_limiter_throttled,
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
                    th.net().metrics.tx_rate_limiter_throttled,
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
            // use up the initial budget
            assert!(rl.consume(1, TokenType::Ops));

            // set this rx rate limiter to be used
            th.net().rx_rate_limiter = rl;

            // set up RX
            assert!(!th.net().rx_deferred_frame);
            th.add_desc_chain(NetQueue::Rx, 0, &[(0, 4096, VIRTQ_DESC_F_WRITE)]);

            // following RX procedure should fail because of ops rate limiting
            {
                // trigger the RX handler
                check_metric_after_block!(
                    th.net().metrics.rx_rate_limiter_throttled,
                    1,
                    th.simulate_event(NetEvent::Tap)
                );

                // assert that limiter is blocked
                assert!(th.net().rx_rate_limiter.is_blocked());
                assert!(th.net().metrics.rx_rate_limiter_throttled.count() >= 1);
                assert!(th.net().rx_deferred_frame);
                // assert that no operation actually completed (limiter blocked it)
                assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
                // make sure the data is still queued for processing
                assert_eq!(th.rxq.used.idx.get(), 0);

                // trigger the RX handler again, this time it should do the limiter fast path exit
                th.simulate_event(NetEvent::Tap);
                // assert that no operation actually completed, that the limiter blocked it
                assert!(!&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
                // make sure the data is still queued for processing
                assert_eq!(th.rxq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following RX procedure should succeed because ops should now be available
            {
                let frame = &th.net().tap.mocks.read_tap.mock_frame();
                th.simulate_event(NetEvent::RxRateLimiter);
                // make sure the virtio queue operation completed this time
                assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
                // make sure the data queue advanced
                assert_eq!(th.rxq.used.idx.get(), 1);
                th.rxq
                    .check_used_elem(0, 0, frame.len().try_into().unwrap());
                th.rxq.dtable[0].check_data(frame);
            }
        }
    }

    #[test]
    fn test_patch_rate_limiters() {
        let mut th = TestHelper::get_default();
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
    fn test_virtio_device() {
        let mut th = TestHelper::get_default();
        th.activate_net();
        let net = th.net.lock().unwrap();

        // Test queues count (TX and RX).
        let queues = net.queues();
        assert_eq!(queues.len(), NET_QUEUE_SIZES.len());
        assert_eq!(queues[RX_INDEX].size, th.rxq.size());
        assert_eq!(queues[TX_INDEX].size, th.txq.size());

        // Test corresponding queues events.
        assert_eq!(net.queue_events().len(), NET_QUEUE_SIZES.len());

        // Test interrupts.
        assert!(!&net.irq_trigger.has_pending_irq(IrqType::Vring));
    }

    #[test]
    fn test_queues_notification_suppression() {
        let features = 1 << VIRTIO_RING_F_EVENT_IDX;

        let mut th = TestHelper::get_default();
        th.net().set_acked_features(features);
        th.activate_net();

        let net = th.net();
        let queues = net.queues();
        assert!(queues[RX_INDEX].uses_notif_suppression);
        assert!(queues[TX_INDEX].uses_notif_suppression);
    }
}
