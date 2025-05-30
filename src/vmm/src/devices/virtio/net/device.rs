// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::VecDeque;
use std::mem::{self};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use libc::{EAGAIN, iovec};
use log::error;
use vmm_sys_util::eventfd::EventFd;

use super::NET_QUEUE_MAX_SIZE;
use crate::devices::virtio::device::{DeviceState, IrqTrigger, IrqType, VirtioDevice};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_net::{
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_TSO6, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF, virtio_net_hdr_v1,
};
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::iovec::{
    IoVecBuffer, IoVecBufferMut, IoVecError, ParsedDescriptorChain,
};
use crate::devices::virtio::net::metrics::{NetDeviceMetrics, NetMetricsPerDevice};
use crate::devices::virtio::net::tap::Tap;
use crate::devices::virtio::net::{
    MAX_BUFFER_SIZE, NET_QUEUE_SIZES, NetError, NetQueue, RX_INDEX, TX_INDEX, generated,
};
use crate::devices::virtio::queue::{DescriptorChain, Queue};
use crate::devices::virtio::{ActivateError, TYPE_NET};
use crate::devices::{DeviceError, report_net_event_fail};
use crate::dumbo::pdu::arp::ETH_IPV4_FRAME_LEN;
use crate::dumbo::pdu::ethernet::{EthernetFrame, PAYLOAD_OFFSET};
use crate::logger::{IncMetric, METRICS};
use crate::mmds::data_store::Mmds;
use crate::mmds::ns::MmdsNetworkStack;
use crate::rate_limiter::{BucketUpdate, RateLimiter, TokenType};
use crate::utils::net::mac::MacAddr;
use crate::utils::u64_to_usize;
use crate::vstate::memory::{ByteValued, GuestMemoryMmap};

const FRAME_HEADER_MAX_LEN: usize = PAYLOAD_OFFSET + ETH_IPV4_FRAME_LEN;

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

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum AddRxBufferError {
    /// Error while parsing new buffer: {0}
    Parsing(#[from] IoVecError),
    /// RX buffer is too small
    BufferTooSmall,
}

/// A map of all the memory the guest has provided us with for performing RX
#[derive(Debug)]
pub struct RxBuffers {
    // minimum size of a usable buffer for doing RX
    pub min_buffer_size: u32,
    // An [`IoVecBufferMut`] covering all the memory we have available for receiving network
    // frames.
    pub iovec: IoVecBufferMut<NET_QUEUE_MAX_SIZE>,
    // A map of which part of the memory belongs to which `DescriptorChain` object
    pub parsed_descriptors: VecDeque<ParsedDescriptorChain>,
    // Buffers that we have used and they are ready to be given back to the guest.
    pub used_descriptors: u16,
    pub used_bytes: u32,
}

impl RxBuffers {
    /// Create a new [`RxBuffers`] object for storing guest memory for performing RX
    fn new() -> Result<Self, IoVecError> {
        Ok(Self {
            min_buffer_size: 0,
            iovec: IoVecBufferMut::new()?,
            parsed_descriptors: VecDeque::with_capacity(NET_QUEUE_MAX_SIZE.into()),
            used_descriptors: 0,
            used_bytes: 0,
        })
    }

    /// Add a new `DescriptorChain` that we received from the RX queue in the buffer.
    ///
    /// SAFETY: The `DescriptorChain` cannot be referencing the same memory location as any other
    /// `DescriptorChain`. (See also related comment in
    /// [`IoVecBufferMut::append_descriptor_chain`]).
    unsafe fn add_buffer(
        &mut self,
        mem: &GuestMemoryMmap,
        head: DescriptorChain,
    ) -> Result<(), AddRxBufferError> {
        // SAFETY: descriptor chain cannot be referencing the same memory location as another chain
        let parsed_dc = unsafe { self.iovec.append_descriptor_chain(mem, head)? };
        if parsed_dc.length < self.min_buffer_size {
            self.iovec.drop_chain_back(&parsed_dc);
            return Err(AddRxBufferError::BufferTooSmall);
        }
        self.parsed_descriptors.push_back(parsed_dc);
        Ok(())
    }

    /// Returns the total size of available space in the buffer.
    #[inline(always)]
    fn capacity(&self) -> u32 {
        self.iovec.len()
    }

    /// Mark the first `size` bytes of available memory as used.
    ///
    /// # Safety:
    ///
    /// * The `RxBuffers` should include at least one parsed `DescriptorChain`.
    /// * `size` needs to be smaller or equal to total length of the first `DescriptorChain` stored
    ///   in the `RxBuffers`.
    unsafe fn mark_used(&mut self, mut bytes_written: u32, rx_queue: &mut Queue) {
        self.used_bytes = bytes_written;

        let mut used_heads: u16 = 0;
        for parsed_dc in self.parsed_descriptors.iter() {
            let used_bytes = bytes_written.min(parsed_dc.length);
            // Safe because we know head_index isn't out of bounds
            rx_queue
                .write_used_element(self.used_descriptors, parsed_dc.head_index, used_bytes)
                .unwrap();
            bytes_written -= used_bytes;
            self.used_descriptors += 1;
            used_heads += 1;

            if bytes_written == 0 {
                break;
            }
        }

        // We need to set num_buffers before dropping chains from `self.iovec`. Otherwise
        // when we set headers, we will iterate over new, yet unused chains instead of the ones
        // we need.
        self.header_set_num_buffers(used_heads);
        for _ in 0..used_heads {
            let parsed_dc = self
                .parsed_descriptors
                .pop_front()
                .expect("This should never happen if write to the buffer succeeded.");
            self.iovec.drop_chain_front(&parsed_dc);
        }
    }

    /// Write the number of descriptors used in VirtIO header
    fn header_set_num_buffers(&mut self, nr_descs: u16) {
        // We can unwrap here, because we have checked before that the `IoVecBufferMut` holds at
        // least one buffer with the proper size, depending on the feature negotiation. In any
        // case, the buffer holds memory of at least `std::mem::size_of::<virtio_net_hdr_v1>()`
        // bytes.
        self.iovec
            .write_all_volatile_at(
                &nr_descs.to_le_bytes(),
                std::mem::offset_of!(virtio_net_hdr_v1, num_buffers),
            )
            .unwrap()
    }

    /// This will let the guest know that about all the `DescriptorChain` object that has been
    /// used to receive a frame from the TAP.
    fn finish_frame(&mut self, rx_queue: &mut Queue) {
        rx_queue.advance_used_ring(self.used_descriptors);
        self.used_descriptors = 0;
        self.used_bytes = 0;
    }

    /// Return a slice of iovecs for the first slice in the buffer.
    /// Panics if there are no parsed descriptors.
    fn single_chain_slice_mut(&mut self) -> &mut [iovec] {
        let nr_iovecs = self.parsed_descriptors[0].nr_iovecs as usize;
        &mut self.iovec.as_iovec_mut_slice()[..nr_iovecs]
    }

    /// Return a slice of iovecs for all descriptor chains in the buffer.
    fn all_chains_slice_mut(&mut self) -> &mut [iovec] {
        self.iovec.as_iovec_mut_slice()
    }
}

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

    tx_buffer: IoVecBuffer,
    pub(crate) rx_buffer: RxBuffers,
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
        let mut avail_features = (1 << VIRTIO_NET_F_GUEST_CSUM)
            | (1 << VIRTIO_NET_F_CSUM)
            | (1 << VIRTIO_NET_F_GUEST_TSO4)
            | (1 << VIRTIO_NET_F_GUEST_TSO6)
            | (1 << VIRTIO_NET_F_GUEST_UFO)
            | (1 << VIRTIO_NET_F_HOST_TSO4)
            | (1 << VIRTIO_NET_F_HOST_TSO6)
            | (1 << VIRTIO_NET_F_HOST_UFO)
            | (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_NET_F_MRG_RXBUF)
            | (1 << VIRTIO_RING_F_EVENT_IDX);

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
            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_headers: [0u8; frame_hdr_len()],
            irq_trigger: IrqTrigger::new().map_err(NetError::EventFd)?,
            config_space,
            guest_mac,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(NetError::EventFd)?,
            mmds_ns: None,
            metrics: NetMetricsPerDevice::alloc(id),
            tx_buffer: Default::default(),
            rx_buffer: RxBuffers::new()?,
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
        let queue = match queue_type {
            NetQueue::Rx => &mut self.queues[RX_INDEX],
            NetQueue::Tx => &mut self.queues[TX_INDEX],
        };

        if queue.prepare_kick() {
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
    pub fn rate_limited_rx_single_frame(&mut self, frame_size: u32) -> bool {
        let rx_queue = &mut self.queues[RX_INDEX];
        if !Self::rate_limiter_consume_op(&mut self.rx_rate_limiter, frame_size as u64) {
            self.metrics.rx_rate_limiter_throttled.inc();
            return false;
        }

        self.rx_buffer.finish_frame(rx_queue);
        true
    }

    /// Returns the minimum size of buffer we expect the guest to provide us depending on the
    /// features we have negotiated with it
    fn minimum_rx_buffer_size(&self) -> u32 {
        if !self.has_feature(VIRTIO_NET_F_MRG_RXBUF as u64) {
            if self.has_feature(VIRTIO_NET_F_GUEST_TSO4 as u64)
                || self.has_feature(VIRTIO_NET_F_GUEST_TSO6 as u64)
                || self.has_feature(VIRTIO_NET_F_GUEST_UFO as u64)
            {
                MAX_BUFFER_SIZE.try_into().unwrap()
            } else {
                1526
            }
        } else {
            vnet_hdr_len().try_into().unwrap()
        }
    }

    /// Parse available RX `DescriptorChains` from the queue
    pub fn parse_rx_descriptors(&mut self) {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();
        let queue = &mut self.queues[RX_INDEX];
        while let Some(head) = queue.pop_or_enable_notification() {
            let index = head.index;
            // SAFETY: we are only using this `DescriptorChain` here.
            if let Err(err) = unsafe { self.rx_buffer.add_buffer(mem, head) } {
                self.metrics.rx_fails.inc();

                // If guest uses dirty tricks to make us add more descriptors than
                // we can hold, just stop processing.
                if matches!(err, AddRxBufferError::Parsing(IoVecError::IovDequeOverflow)) {
                    error!("net: Could not add an RX descriptor: {err}");
                    queue.undo_pop();
                    break;
                }

                error!("net: Could not parse an RX descriptor: {err}");

                // Add this broken chain to the used_ring. It will be
                // reported to the quest on the next `rx_buffer.finish_frame` call.
                // SAFETY:
                // index is verified on `DescriptorChain` creation.
                queue
                    .write_used_element(self.rx_buffer.used_descriptors, index, 0)
                    .unwrap();
                self.rx_buffer.used_descriptors += 1;
            }
        }
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

        let headers = frame_bytes_from_buf(&headers[..header_len]).inspect_err(|_| {
            error!("VNET headers missing in TX frame");
            net_metrics.tx_malformed_frames.inc();
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
    fn read_from_mmds_or_tap(&mut self) -> Result<Option<u32>, NetError> {
        // We only want to read from TAP (or mmds) if we have at least 64K of available capacity as
        // this is the max size of 1 packet.
        // SAFETY:
        // * MAX_BUFFER_SIZE is constant and fits into u32
        #[allow(clippy::cast_possible_truncation)]
        if self.rx_buffer.capacity() < MAX_BUFFER_SIZE as u32 {
            self.parse_rx_descriptors();

            // If after parsing the RX queue we still don't have enough capacity, stop processing RX
            // frames.
            if self.rx_buffer.capacity() < MAX_BUFFER_SIZE as u32 {
                return Ok(None);
            }
        }

        if let Some(ns) = self.mmds_ns.as_mut() {
            if let Some(len) =
                ns.write_next_frame(frame_bytes_from_buf_mut(&mut self.rx_frame_buf)?)
            {
                let len = len.get();
                METRICS.mmds.tx_frames.inc();
                METRICS.mmds.tx_bytes.add(len as u64);
                init_vnet_hdr(&mut self.rx_frame_buf);
                self.rx_buffer
                    .iovec
                    .write_all_volatile_at(&self.rx_frame_buf[..vnet_hdr_len() + len], 0)?;
                // SAFETY:
                // * len will never be bigger that u32::MAX because mmds is bound
                // by the size of `self.rx_frame_buf` which is MAX_BUFFER_SIZE size.
                let len: u32 = (vnet_hdr_len() + len).try_into().unwrap();

                // SAFETY:
                // * We checked that `rx_buffer` includes at least one `DescriptorChain`
                // * `rx_frame_buf` has size of `MAX_BUFFER_SIZE` and all `DescriptorChain` objects
                //   are at least that big.
                unsafe {
                    self.rx_buffer.mark_used(len, &mut self.queues[RX_INDEX]);
                }
                return Ok(Some(len));
            }
        }

        // SAFETY:
        // * We ensured that `self.rx_buffer` has at least one DescriptorChain parsed in it.
        let len = unsafe { self.read_tap().map_err(NetError::IO) }?;
        // SAFETY:
        // * len will never be bigger that u32::MAX
        let len: u32 = len.try_into().unwrap();

        // SAFETY:
        // * `rx_buffer` has at least one `DescriptorChain`
        // * `read_tap` passes the first `DescriptorChain` to `readv` so we can't have read more
        //   bytes than its capacity.
        unsafe {
            self.rx_buffer.mark_used(len, &mut self.queues[RX_INDEX]);
        }
        Ok(Some(len))
    }

    /// Read as many frames as possible.
    fn process_rx(&mut self) -> Result<(), DeviceError> {
        loop {
            match self.read_from_mmds_or_tap() {
                Ok(None) => {
                    self.metrics.no_rx_avail_buffer.inc();
                    break;
                }
                Ok(Some(bytes)) => {
                    self.metrics.rx_count.inc();
                    self.metrics.rx_bytes_count.add(bytes as u64);
                    self.metrics.rx_packets_count.inc();
                    if !self.rate_limited_rx_single_frame(bytes) {
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

    fn resume_rx(&mut self) -> Result<(), DeviceError> {
        // First try to handle any deferred frame
        if self.rx_buffer.used_bytes != 0 {
            // If can't finish sending this frame, re-set it as deferred and return; we can't
            // process any more frames from the TAP.
            if !self.rate_limited_rx_single_frame(self.rx_buffer.used_bytes) {
                return Ok(());
            }
        }

        self.process_rx()
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

        while let Some(head) = tx_queue.pop_or_enable_notification() {
            self.metrics
                .tx_remaining_reqs_count
                .add(tx_queue.len().into());
            let head_index = head.index;
            // Parse IoVecBuffer from descriptor head
            // SAFETY: This descriptor chain is only loaded once
            // virtio requests are handled sequentially so no two IoVecBuffers
            // are live at the same time, meaning this has exclusive ownership over the memory
            if unsafe { self.tx_buffer.load_descriptor_chain(mem, head).is_err() } {
                self.metrics.tx_fails.inc();
                tx_queue
                    .add_used(head_index, 0)
                    .map_err(DeviceError::QueueError)?;
                continue;
            };

            // We only handle frames that are up to MAX_BUFFER_SIZE
            if self.tx_buffer.len() as usize > MAX_BUFFER_SIZE {
                error!("net: received too big frame from driver");
                self.metrics.tx_malformed_frames.inc();
                tx_queue
                    .add_used(head_index, 0)
                    .map_err(DeviceError::QueueError)?;
                continue;
            }

            if !Self::rate_limiter_consume_op(
                &mut self.tx_rate_limiter,
                u64::from(self.tx_buffer.len()),
            ) {
                tx_queue.undo_pop();
                self.metrics.tx_rate_limiter_throttled.inc();
                break;
            }

            let frame_consumed_by_mmds = Self::write_to_mmds_or_tap(
                self.mmds_ns.as_mut(),
                &mut self.tx_rate_limiter,
                &mut self.tx_frame_headers,
                &self.tx_buffer,
                &mut self.tap,
                self.guest_mac,
                &self.metrics,
            )
            .unwrap_or(false);
            if frame_consumed_by_mmds && self.rx_buffer.used_bytes == 0 {
                // MMDS consumed this frame/request, let's also try to process the response.
                process_rx_for_mmds = true;
            }

            tx_queue
                .add_used(head_index, 0)
                .map_err(DeviceError::QueueError)?;
            used_any = true;
        }

        if !used_any {
            self.metrics.no_tx_avail_buffer.inc();
        }

        // Cleanup tx_buffer to ensure no two buffers point at the same memory
        self.tx_buffer.clear();
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
    pub fn build_tap_offload_features(guest_supported_features: u64) -> u32 {
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
            generated::TUN_F_CSUM,
            VIRTIO_NET_F_GUEST_CSUM,
        );
        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            generated::TUN_F_UFO,
            VIRTIO_NET_F_GUEST_UFO,
        );
        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            generated::TUN_F_TSO4,
            VIRTIO_NET_F_GUEST_TSO4,
        );
        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            generated::TUN_F_TSO6,
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

    /// Reads a frame from the TAP device inside the first descriptor held by `self.rx_buffer`.
    ///
    /// # Safety
    ///
    /// `self.rx_buffer` needs to have at least one descriptor chain parsed
    pub unsafe fn read_tap(&mut self) -> std::io::Result<usize> {
        let slice = if self.has_feature(VIRTIO_NET_F_MRG_RXBUF as u64) {
            self.rx_buffer.all_chains_slice_mut()
        } else {
            self.rx_buffer.single_chain_slice_mut()
        };
        self.tap.read_iovec(slice)
    }

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
            return;
        } else {
            self.parse_rx_descriptors();
        }

        if self.rx_rate_limiter.is_blocked() {
            self.metrics.rx_rate_limiter_throttled.inc();
        } else {
            // If the limiter is not blocked, resume the receiving of bytes.
            self.resume_rx()
                .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
        }
    }

    pub fn process_tap_rx_event(&mut self) {
        // This is safe since we checked in the event handler that the device is activated.
        self.metrics.rx_tap_event_count.inc();

        // While limiter is blocked, don't process any more incoming.
        if self.rx_rate_limiter.is_blocked() {
            self.metrics.rx_rate_limiter_throttled.inc();
            return;
        }

        self.resume_rx()
            .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
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

    #[cfg(target_arch = "riscv64")]
    fn interrupt_trigger_mut(&mut self) -> &mut IrqTrigger {
        &mut self.irq_trigger
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
        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

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

        self.rx_buffer.min_buffer_size = self.minimum_rx_buffer_size();

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
#[allow(clippy::cast_possible_truncation)]
pub mod tests {
    use std::net::Ipv4Addr;
    use std::os::fd::AsRawFd;
    use std::str::FromStr;
    use std::time::Duration;
    use std::{mem, thread};

    use vm_memory::GuestAddress;

    use super::*;
    use crate::check_metric_after_block;
    use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
    use crate::devices::virtio::iovec::IoVecBuffer;
    use crate::devices::virtio::net::NET_QUEUE_SIZES;
    use crate::devices::virtio::net::device::{
        frame_bytes_from_buf, frame_bytes_from_buf_mut, frame_hdr_len, init_vnet_hdr, vnet_hdr_len,
    };
    use crate::devices::virtio::net::test_utils::test::TestHelper;
    use crate::devices::virtio::net::test_utils::{
        NetEvent, NetQueue, TapTrafficSimulator, default_net, if_index, inject_tap_tx_frame,
        set_mac,
    };
    use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::devices::virtio::test_utils::VirtQueue;
    use crate::dumbo::EthernetFrame;
    use crate::dumbo::pdu::arp::{ETH_IPV4_FRAME_LEN, EthIPv4ArpFrame};
    use crate::dumbo::pdu::ethernet::ETHERTYPE_ARP;
    use crate::logger::IncMetric;
    use crate::rate_limiter::{BucketUpdate, RateLimiter, TokenBucket, TokenType};
    use crate::test_utils::single_region_mem;
    use crate::utils::net::mac::{MAC_ADDR_LEN, MacAddr};
    use crate::vstate::memory::{Address, GuestMemory};

    impl Net {
        pub fn finish_frame(&mut self) {
            self.rx_buffer.finish_frame(&mut self.queues[RX_INDEX]);
        }
    }

    /// Write the number of descriptors used in VirtIO header
    fn header_set_num_buffers(frame: &mut [u8], nr_descs: u16) {
        let bytes = nr_descs.to_le_bytes();
        let offset = std::mem::offset_of!(virtio_net_hdr_v1, num_buffers);
        frame[offset] = bytes[0];
        frame[offset + 1] = bytes[1];
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
        let features = (1 << VIRTIO_NET_F_GUEST_CSUM)
            | (1 << VIRTIO_NET_F_CSUM)
            | (1 << VIRTIO_NET_F_GUEST_TSO4)
            | (1 << VIRTIO_NET_F_GUEST_TSO6)
            | (1 << VIRTIO_NET_F_MAC)
            | (1 << VIRTIO_NET_F_GUEST_UFO)
            | (1 << VIRTIO_NET_F_HOST_TSO4)
            | (1 << VIRTIO_NET_F_HOST_TSO6)
            | (1 << VIRTIO_NET_F_HOST_UFO)
            | (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_NET_F_MRG_RXBUF)
            | (1 << VIRTIO_RING_F_EVENT_IDX);

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
        let supported_features = (1 << VIRTIO_NET_F_GUEST_CSUM)
            | (1 << VIRTIO_NET_F_GUEST_UFO)
            | (1 << VIRTIO_NET_F_GUEST_TSO4)
            | (1 << VIRTIO_NET_F_GUEST_TSO6);
        let expected_tap_features = generated::TUN_F_CSUM
            | generated::TUN_F_UFO
            | generated::TUN_F_TSO4
            | generated::TUN_F_TSO6;
        let supported_flags = Net::build_tap_offload_features(supported_features);

        assert_eq!(supported_flags, expected_tap_features);
    }

    #[test]
    // Same as before, however, using each supported feature one by one.
    fn test_build_tap_offload_features_one_by_one() {
        let features = [
            (1 << VIRTIO_NET_F_GUEST_CSUM, generated::TUN_F_CSUM),
            (1 << VIRTIO_NET_F_GUEST_UFO, generated::TUN_F_UFO),
            (1 << VIRTIO_NET_F_GUEST_TSO4, generated::TUN_F_TSO4),
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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

    fn rx_read_only_descriptor(mut th: TestHelper) {
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
        let mut frame = inject_tap_tx_frame(&th.net(), 1000);
        check_metric_after_block!(
            th.net().metrics.rx_fails,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );
        th.rxq.check_used_elem(0, 0, 0);
        header_set_num_buffers(frame.as_mut_slice(), 1);
        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_read_only_descriptor() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let th = TestHelper::get_default(&mem);
        rx_read_only_descriptor(th);
    }

    #[test]
    fn test_rx_read_only_descriptor_mrg() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
        // VIRTIO_NET_F_MRG_RXBUF is not enabled by default
        th.net().acked_features = 1 << VIRTIO_NET_F_MRG_RXBUF;
        rx_read_only_descriptor(th);
    }

    fn rx_short_descriptor(mut th: TestHelper) {
        th.activate_net();

        th.add_desc_chain(NetQueue::Rx, 0, &[(0, 10, VIRTQ_DESC_F_WRITE)]);
        let mut frame = th.check_rx_discarded_buffer(1000);
        th.rxq.check_used_elem(0, 0, 0);

        header_set_num_buffers(frame.as_mut_slice(), 1);
        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_short_descriptor() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let th = TestHelper::get_default(&mem);
        rx_short_descriptor(th);
    }

    #[test]
    fn test_rx_short_descriptor_mrg() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
        // VIRTIO_NET_F_MRG_RXBUF is not enabled by default
        th.net().acked_features = 1 << VIRTIO_NET_F_MRG_RXBUF;
        rx_short_descriptor(th);
    }

    fn rx_invalid_descriptor(mut th: TestHelper) {
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
        let mut frame = th.check_rx_discarded_buffer(1000);
        th.rxq.check_used_elem(0, 0, 0);

        header_set_num_buffers(frame.as_mut_slice(), 1);
        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_invalid_descriptor() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let th = TestHelper::get_default(&mem);
        rx_invalid_descriptor(th);
    }

    #[test]
    fn test_rx_invalid_descriptor_mrg() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
        // VIRTIO_NET_F_MRG_RXBUF is not enabled by default
        th.net().acked_features = 1 << VIRTIO_NET_F_MRG_RXBUF;
        rx_invalid_descriptor(th);
    }

    fn rx_retry(mut th: TestHelper) {
        th.activate_net();

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
        th.add_desc_chain(NetQueue::Rx, 1200, &[(3, 10, VIRTQ_DESC_F_WRITE)]);
        // Add invalid descriptor chain - invalid memory offset.
        th.add_desc_chain(
            NetQueue::Rx,
            th.mem.last_addr().raw_value(),
            &[(4, 1000, VIRTQ_DESC_F_WRITE)],
        );

        // Add valid descriptor chain. TestHelper does not negotiate any feature offloading so the
        // buffers need to be at least 1526 bytes long.
        th.add_desc_chain(
            NetQueue::Rx,
            1300,
            &[(5, MAX_BUFFER_SIZE as u32, VIRTQ_DESC_F_WRITE)],
        );

        // Inject frame to tap and run epoll.
        let mut frame = inject_tap_tx_frame(&th.net(), 1000);
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
        assert!(th.net().rx_buffer.used_descriptors == 0);
        // Check that the frame has been written successfully to the valid Rx descriptor chain.
        th.rxq
            .check_used_elem(3, 5, frame.len().try_into().unwrap());
        header_set_num_buffers(frame.as_mut_slice(), 1);
        th.rxq.dtable[5].check_data(&frame);
    }

    #[test]
    fn test_rx_retry() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let th = TestHelper::get_default(&mem);
        rx_retry(th);
    }

    #[test]
    fn test_rx_retry_mrg() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
        // VIRTIO_NET_F_MRG_RXBUF is not enabled by default
        th.net().acked_features = 1 << VIRTIO_NET_F_MRG_RXBUF;
        rx_retry(th);
    }

    fn rx_complex_desc_chain(mut th: TestHelper) {
        th.activate_net();

        // Create a valid Rx avail descriptor chain with multiple descriptors.
        th.add_desc_chain(
            NetQueue::Rx,
            0,
            // Add gaps between the descriptor ids in order to ensure that we follow
            // the `next` field.
            &[
                (3, 100, VIRTQ_DESC_F_WRITE),
                (5, 50, VIRTQ_DESC_F_WRITE),
                (11, MAX_BUFFER_SIZE as u32 - 100 - 50, VIRTQ_DESC_F_WRITE),
            ],
        );
        // Inject frame to tap and run epoll.
        let mut frame = inject_tap_tx_frame(&th.net(), 1000);
        check_metric_after_block!(
            th.net().metrics.rx_packets_count,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the frame wasn't deferred.
        assert!(th.net().rx_buffer.used_descriptors == 0);
        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 1);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        // Check that the frame has been written successfully to the Rx descriptor chain.
        header_set_num_buffers(frame.as_mut_slice(), 1);
        th.rxq
            .check_used_elem(0, 3, frame.len().try_into().unwrap());
        th.rxq.dtable[3].check_data(&frame[..100]);
        th.rxq.dtable[5].check_data(&frame[100..150]);
        th.rxq.dtable[11].check_data(&frame[150..]);
    }

    #[test]
    fn test_rx_complex_desc_chain() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let th = TestHelper::get_default(&mem);
        rx_complex_desc_chain(th);
    }

    #[test]
    fn test_rx_complex_desc_chain_mrg() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
        // VIRTIO_NET_F_MRG_RXBUF is not enabled by default
        th.net().acked_features = 1 << VIRTIO_NET_F_MRG_RXBUF;
        rx_complex_desc_chain(th);
    }

    fn rx_multiple_frames(mut th: TestHelper) {
        th.activate_net();

        // Create 2 valid Rx avail descriptor chains. Each one has enough space to fit the
        // following 2 frames. But only 1 frame has to be written to each chain.
        th.add_desc_chain(
            NetQueue::Rx,
            0,
            &[
                (0, 500, VIRTQ_DESC_F_WRITE),
                (1, 500, VIRTQ_DESC_F_WRITE),
                (2, MAX_BUFFER_SIZE as u32 - 1000, VIRTQ_DESC_F_WRITE),
            ],
        );
        // Second chain needs at least MAX_BUFFER_SIZE offset
        th.add_desc_chain(
            NetQueue::Rx,
            MAX_BUFFER_SIZE as u64 + 1000,
            &[
                (3, 500, VIRTQ_DESC_F_WRITE),
                (4, 500, VIRTQ_DESC_F_WRITE),
                (5, MAX_BUFFER_SIZE as u32 - 1000, VIRTQ_DESC_F_WRITE),
            ],
        );
        // Inject 2 frames to tap and run epoll.
        let mut frame_1 = inject_tap_tx_frame(&th.net(), 200);
        let mut frame_2 = inject_tap_tx_frame(&th.net(), 300);
        check_metric_after_block!(
            th.net().metrics.rx_packets_count,
            2,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the frames weren't deferred.
        assert!(th.net().rx_buffer.used_bytes == 0);
        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 2);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        // Check that the 1st frame was written successfully to the 1st Rx descriptor chain.
        header_set_num_buffers(frame_1.as_mut_slice(), 1);
        th.rxq
            .check_used_elem(0, 0, frame_1.len().try_into().unwrap());
        th.rxq.dtable[0].check_data(&frame_1);
        th.rxq.dtable[1].check_data(&[0; 500]);
        th.rxq.dtable[2].check_data(&[0; MAX_BUFFER_SIZE - 1000]);
        // Check that the 2nd frame was written successfully to the 2nd Rx descriptor chain.
        header_set_num_buffers(frame_2.as_mut_slice(), 1);
        th.rxq
            .check_used_elem(1, 3, frame_2.len().try_into().unwrap());
        th.rxq.dtable[3].check_data(&frame_2);
        th.rxq.dtable[4].check_data(&[0; 500]);
        th.rxq.dtable[5].check_data(&[0; MAX_BUFFER_SIZE - 1000]);
    }

    #[test]
    fn test_rx_multiple_frames() {
        let mem = single_region_mem(3 * MAX_BUFFER_SIZE);
        let th = TestHelper::get_default(&mem);
        rx_multiple_frames(th);
    }

    #[test]
    fn test_rx_multiple_frames_mrg() {
        let mem = single_region_mem(3 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
        // VIRTIO_NET_F_MRG_RXBUF is not enabled by default
        th.net().acked_features = 1 << VIRTIO_NET_F_MRG_RXBUF;
        rx_multiple_frames(th);
    }

    fn rx_mrg_rxbuf_only(mut th: TestHelper) {
        th.activate_net();

        // Create 2 valid Rx avail descriptor chains. The total size should
        // be at least 64K to pass the capacity check for rx_buffers.
        // First chain is intentionally small, so non VIRTIO_NET_F_MRG_RXBUF
        // version will skip it.
        th.add_desc_chain(NetQueue::Rx, 0, &[(0, 500, VIRTQ_DESC_F_WRITE)]);
        th.add_desc_chain(
            NetQueue::Rx,
            1000,
            &[(1, MAX_BUFFER_SIZE as u32, VIRTQ_DESC_F_WRITE)],
        );
        // Inject frame to tap and run epoll.
        let mut frame = inject_tap_tx_frame(&th.net(), 1000);
        check_metric_after_block!(
            th.net().metrics.rx_packets_count,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the frame wasn't deferred.
        assert!(th.net().rx_buffer.used_bytes == 0);
        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 2);
        assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
        // 2 chains should be used for the packet.
        header_set_num_buffers(frame.as_mut_slice(), 2);

        // Here non VIRTIO_NET_F_MRG_RXBUF version should panic as
        // first descriptor will be discarded by it.
        th.rxq.check_used_elem(0, 0, 500);

        th.rxq.check_used_elem(1, 1, 500);
        th.rxq.dtable[0].check_data(&frame[0..500]);
        th.rxq.dtable[1].check_data(&frame[500..]);
    }

    #[test]
    #[should_panic]
    fn test_rx_mrg_rxbuf_only() {
        let mem = single_region_mem(3 * MAX_BUFFER_SIZE);
        let th = TestHelper::get_default(&mem);
        rx_mrg_rxbuf_only(th);
    }

    #[test]
    fn test_rx_mrg_rxbuf_only_mrg() {
        let mem = single_region_mem(3 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
        // VIRTIO_NET_F_MRG_RXBUF is not enabled by default
        th.net().acked_features = 1 << VIRTIO_NET_F_MRG_RXBUF;
        rx_mrg_rxbuf_only(th);
    }

    #[test]
    fn test_tx_missing_queue_signal() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
        th.activate_net();
        // force the next write to the tap to return an error by simply closing the fd
        // SAFETY: its a valid fd
        unsafe { libc::close(th.net.lock().unwrap().tap.as_raw_fd()) };

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

        // dropping th would double close the tap fd, so leak it
        std::mem::forget(th);
    }

    #[test]
    fn test_tx_multiple_frame() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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

        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let rxq = VirtQueue::new(GuestAddress(0), &mem, 16);
        net.queues[RX_INDEX] = rxq.create_queue();

        // Inject a fake buffer in the devices buffers, otherwise we won't be able to receive the
        // MMDS frame. One iovec will be just fine.
        let mut fake_buffer = vec![0u8; MAX_BUFFER_SIZE];
        let iov_buffer = IoVecBufferMut::from(fake_buffer.as_mut_slice());
        net.rx_buffer.iovec = iov_buffer;
        net.rx_buffer
            .parsed_descriptors
            .push_back(ParsedDescriptorChain {
                head_index: 1,
                length: 1024,
                nr_iovecs: 1,
            });

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
            assert!(
                Net::write_to_mmds_or_tap(
                    net.mmds_ns.as_mut(),
                    &mut net.tx_rate_limiter,
                    &mut headers,
                    &buffer,
                    &mut net.tap,
                    Some(src_mac),
                    &net.metrics,
                )
                .unwrap()
            )
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
        th.activate_net();
        // force the next write to the tap to return an error by simply closing the fd
        // SAFETY: its a valid fd
        unsafe { libc::close(th.net.lock().unwrap().tap.as_raw_fd()) };

        // The RX queue is empty and there is a deferred frame.
        th.net().rx_buffer.used_descriptors = 1;
        th.net().rx_buffer.used_bytes = 100;
        check_metric_after_block!(
            th.net().metrics.no_rx_avail_buffer,
            1,
            th.simulate_event(NetEvent::Tap)
        );

        // We need to set this here to false, otherwise the device will try to
        // handle a deferred frame, it will fail and will never try to read from
        // the tap.
        th.net().rx_buffer.used_descriptors = 0;
        th.net().rx_buffer.used_bytes = 0;

        th.add_desc_chain(
            NetQueue::Rx,
            0,
            &[(0, MAX_BUFFER_SIZE as u32, VIRTQ_DESC_F_WRITE)],
        );
        check_metric_after_block!(
            th.net().metrics.tap_read_fails,
            1,
            th.simulate_event(NetEvent::Tap)
        );

        // dropping th would double close the tap fd, so leak it
        std::mem::forget(th);
    }

    #[test]
    fn test_rx_rate_limiter_handling() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
            // create bandwidth rate limiter that allows 2000 bytes/s with bucket size 1000 bytes
            let mut rl = RateLimiter::new(1000, 0, 1000, 0, 0, 0).unwrap();

            // set up RX
            assert!(th.net().rx_buffer.used_descriptors == 0);
            th.add_desc_chain(
                NetQueue::Rx,
                0,
                &[(0, MAX_BUFFER_SIZE as u32, VIRTQ_DESC_F_WRITE)],
            );

            let mut frame = inject_tap_tx_frame(&th.net(), 1000);

            // use up the budget (do it after injecting the tx frame, as socket communication is
            // slow enough that the ratelimiter could replenish in the meantime).
            assert!(rl.consume(1000, TokenType::Bytes));

            // set this rx rate limiter to be used
            th.net().rx_rate_limiter = rl;

            // following RX procedure should fail because of bandwidth rate limiting
            {
                // trigger the RX handler
                th.simulate_event(NetEvent::Tap);

                // assert that limiter is blocked
                assert!(th.net().rx_rate_limiter.is_blocked());
                assert_eq!(th.net().metrics.rx_rate_limiter_throttled.count(), 1);
                assert!(th.net().rx_buffer.used_descriptors != 0);
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

            // wait for 1000ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 1000ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(2000));

            // following RX procedure should succeed because bandwidth should now be available
            {
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
                header_set_num_buffers(frame.as_mut_slice(), 1);
                th.rxq.dtable[0].check_data(&frame);
            }
        }
    }

    #[test]
    fn test_ops_rate_limiter() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
            // create ops rate limiter that allows 2 ops/s with bucket size 1 ops
            let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 1000).unwrap();

            // set up RX
            assert!(th.net().rx_buffer.used_descriptors == 0);
            th.add_desc_chain(
                NetQueue::Rx,
                0,
                &[(0, MAX_BUFFER_SIZE as u32, VIRTQ_DESC_F_WRITE)],
            );
            let mut frame = inject_tap_tx_frame(&th.net(), 1234);

            // use up the initial budget
            assert!(rl.consume(1, TokenType::Ops));

            // set this rx rate limiter to be used
            th.net().rx_rate_limiter = rl;

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
                assert!(th.net().rx_buffer.used_descriptors != 0);
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

            // wait for 1000ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 1000ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(2000));

            // following RX procedure should succeed because ops should now be available
            {
                th.simulate_event(NetEvent::RxRateLimiter);
                // make sure the virtio queue operation completed this time
                assert!(&th.net().irq_trigger.has_pending_irq(IrqType::Vring));
                // make sure the data queue advanced
                assert_eq!(th.rxq.used.idx.get(), 1);
                th.rxq
                    .check_used_elem(0, 0, frame.len().try_into().unwrap());
                header_set_num_buffers(frame.as_mut_slice(), 1);
                th.rxq.dtable[0].check_data(&frame);
            }
        }
    }

    #[test]
    fn test_patch_rate_limiters() {
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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
        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
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

        let mem = single_region_mem(2 * MAX_BUFFER_SIZE);
        let mut th = TestHelper::get_default(&mem);
        th.net().set_acked_features(features);
        th.activate_net();

        let net = th.net();
        let queues = net.queues();
        assert!(queues[RX_INDEX].uses_notif_suppression);
        assert!(queues[TX_INDEX].uses_notif_suppression);
    }
}
