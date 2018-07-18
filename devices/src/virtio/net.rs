// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use epoll;
use libc::EAGAIN;
use std::cmp;
#[cfg(not(test))]
use std::io::Read;
use std::io::{self, Write};
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::vec::Vec;

use super::{ActivateError, ActivateResult, Queue, VirtioDevice, TYPE_NET, VIRTIO_MMIO_INT_VRING};
use fc_util::ratelimiter::{RateLimiter, TokenType};
use logger::{Metric, METRICS};
use net_sys;
use net_util::{MacAddr, Tap, TapError, MAC_ADDR_LEN};
use sys_util::{Error as SysError, EventFd, GuestAddress, GuestMemory};
use virtio_sys::virtio_config::*;
use virtio_sys::virtio_net::*;
use {DeviceEventT, EpollHandler};

/// The maximum buffer size when segmentation offload is enabled. This
/// includes the 12-byte virtio net header.
/// http://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html#x1-1740003
const MAX_BUFFER_SIZE: usize = 65562;
const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &'static [u16] = &[QUEUE_SIZE; NUM_QUEUES];

// A frame is available for reading from the tap device to receive in the guest.
const RX_TAP_EVENT: DeviceEventT = 0;
// The guest has made a buffer available to receive a frame into.
const RX_QUEUE_EVENT: DeviceEventT = 1;
// The transmit queue has a frame that is ready to send from the guest.
const TX_QUEUE_EVENT: DeviceEventT = 2;
// Device shutdown has been requested.
const KILL_EVENT: DeviceEventT = 3;
// rx rate limiter budget is now available.
const RX_RATE_LIMITER_EVENT: DeviceEventT = 4;
// tx rate limiter budget is now available.
const TX_RATE_LIMITER_EVENT: DeviceEventT = 5;
// Number of DeviceEventT events supported by this implementation.
pub const NET_EVENTS_COUNT: usize = 6;

#[derive(Debug)]
pub enum Error {
    /// Creating kill eventfd failed.
    CreateKillEventFd(SysError),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(SysError),
    /// Open tap device failed.
    TapOpen(TapError),
    /// Setting tap IP failed.
    TapSetIp(TapError),
    /// Setting tap netmask failed.
    TapSetNetmask(TapError),
    /// Setting tap interface offload flags failed.
    TapSetOffload(TapError),
    /// Setting vnet header size failed.
    TapSetVnetHdrSize(TapError),
    /// Enabling tap interface failed.
    TapEnable(TapError),
}

pub type Result<T> = result::Result<T, Error>;

struct TxVirtio {
    queue_evt: EventFd,
    rate_limiter: RateLimiter,
    queue: Queue,
    iovec: Vec<(GuestAddress, usize)>,
    used_desc_heads: [u16; QUEUE_SIZE as usize],
    frame_buf: [u8; MAX_BUFFER_SIZE],
}

impl TxVirtio {
    fn new(queue: Queue, queue_evt: EventFd, rate_limiter: RateLimiter) -> Self {
        let tx_queue_max_size = queue.get_max_size() as usize;
        TxVirtio {
            queue_evt,
            rate_limiter,
            queue,
            iovec: Vec::with_capacity(tx_queue_max_size),
            used_desc_heads: [0u16; QUEUE_SIZE as usize],
            frame_buf: [0u8; MAX_BUFFER_SIZE],
        }
    }
}

struct RxVirtio {
    queue_evt: EventFd,
    rate_limiter: RateLimiter,
    deferred_frame: bool,
    deferred_irqs: bool,
    queue: Queue,
    bytes_read: usize,
    frame_buf: [u8; MAX_BUFFER_SIZE],
}

impl RxVirtio {
    fn new(queue: Queue, queue_evt: EventFd, rate_limiter: RateLimiter) -> Self {
        RxVirtio {
            queue_evt,
            rate_limiter,
            deferred_frame: false,
            deferred_irqs: false,
            queue,
            bytes_read: 0,
            frame_buf: [0u8; MAX_BUFFER_SIZE],
        }
    }
}

struct NetEpollHandler {
    rx: RxVirtio,
    tap: Tap,
    mem: GuestMemory,
    tx: TxVirtio,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    // TODO(smbarber): http://crbug.com/753630
    // Remove once MRG_RXBUF is supported and this variable is actually used.
    #[allow(dead_code)]
    acked_features: u64,
}

impl NetEpollHandler {
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        if let Err(e) = self.interrupt_evt.write(1) {
            error!("Failed to signal used queue: {:?}", e);
            METRICS.net.event_fails.inc();
        }
    }

    // Attempts to copy a single frame into the guest if there is enough
    // rate limiting budget.
    // Returns true on successful frame delivery.
    fn rate_limited_rx_single_frame(&mut self) -> bool {
        // If limiter.consume() fails it means there is no more TokenType::Ops
        // budget and rate limiting is in effect.
        if !self.rx.rate_limiter.consume(1, TokenType::Ops) {
            return false;
        }
        // If limiter.consume() fails it means there is no more TokenType::Bytes
        // budget and rate limiting is in effect.
        if !self.rx
            .rate_limiter
            .consume(self.rx.bytes_read as u64, TokenType::Bytes)
        {
            // revert the OPS consume()
            self.rx.rate_limiter.manual_replenish(1, TokenType::Ops);
            return false;
        }

        // Attempt frame delivery.
        let success = self.rx_single_frame();

        // Undo the tokens consumption if guest delivery failed.
        if !success {
            // revert the OPS consume()
            self.rx.rate_limiter.manual_replenish(1, TokenType::Ops);
            // revert the BYTES consume()
            self.rx
                .rate_limiter
                .manual_replenish(self.rx.bytes_read as u64, TokenType::Bytes);
        }
        return success;
    }

    // Copies a single frame from `self.rx.frame_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self) -> bool {
        let mut next_desc = self.rx.queue.iter(&self.mem).next();

        if next_desc.is_none() {
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
                    let limit = cmp::min(write_count + desc.len as usize, self.rx.bytes_read);
                    let source_slice = &self.rx.frame_buf[write_count..limit];
                    let write_result = self.mem.write_slice_at_addr(source_slice, desc.addr);

                    match write_result {
                        Ok(sz) => {
                            write_count += sz;
                        }
                        Err(e) => {
                            error!("Failed to write slice: {:?}", e);
                            METRICS.net.rx_fails.inc();
                            break;
                        }
                    };

                    if write_count >= self.rx.bytes_read {
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

        self.rx
            .queue
            .add_used(&self.mem, head_index, write_count as u32);

        // Mark that we have at least one pending packet and we need to interrupt the guest.
        self.rx.deferred_irqs = true;

        if write_count >= self.rx.bytes_read {
            METRICS.net.rx_bytes_count.add(write_count);
            METRICS.net.rx_packets_count.inc();
            return true;
        } else {
            return false;
        }
    }

    fn process_rx(&mut self) {
        // Read as many frames as possible.
        loop {
            match self.read_tap() {
                Ok(count) => {
                    self.rx.bytes_read = count;
                    if !self.rate_limited_rx_single_frame() {
                        self.rx.deferred_frame = true;
                        break;
                    }
                }
                Err(e) => {
                    // The tap device is non-blocking, so any error aside from EAGAIN is
                    // unexpected.
                    if let Some(err) = e.raw_os_error() {
                        if err != EAGAIN {
                            error!("Failed to read tap: {:?}", e);
                            METRICS.net.rx_fails.inc();
                        }
                    } else {
                        error!("Failed to read tap: {:?}", e);
                        METRICS.net.rx_fails.inc();
                    }
                    break;
                }
            }
        }
        if self.rx.deferred_irqs {
            self.rx.deferred_irqs = false;
            self.signal_used_queue();
        }
    }

    fn resume_rx(&mut self) {
        if self.rx.deferred_frame {
            if self.rate_limited_rx_single_frame() {
                self.rx.deferred_frame = false;
                // process_rx() was interrupted possibly before consuming all
                // packets in the tap; try continuing now.
                self.process_rx();
            } else if self.rx.deferred_irqs {
                self.rx.deferred_irqs = false;
                self.signal_used_queue();
            }
        }
    }

    fn process_tx(&mut self) {
        let mut rate_limited = false;
        let mut used_count = 0;

        for avail_desc in self.tx.queue.iter(&self.mem) {
            // If limiter.consume() fails it means there is no more TokenType::Ops
            // budget and rate limiting is in effect.
            if !self.tx.rate_limiter.consume(1, TokenType::Ops) {
                rate_limited = true;
                // Stop processing the queue.
                break;
            }

            let head_index = avail_desc.index;
            let mut read_count = 0;
            let mut next_desc = Some(avail_desc);

            self.tx.iovec.clear();
            loop {
                match next_desc {
                    Some(desc) => {
                        if desc.is_write_only() {
                            break;
                        }
                        self.tx.iovec.push((desc.addr, desc.len as usize));
                        read_count += desc.len as usize;
                        next_desc = desc.next_descriptor();
                    }
                    None => {
                        break;
                    }
                }
            }

            // If limiter.consume() fails it means there is no more TokenType::Bytes
            // budget and rate limiting is in effect.
            if !self.tx
                .rate_limiter
                .consume(read_count as u64, TokenType::Bytes)
            {
                rate_limited = true;
                // revert the OPS consume()
                self.tx.rate_limiter.manual_replenish(1, TokenType::Ops);
                // stop processing the queue
                break;
            }

            read_count = 0;
            // Copy buffer from across multiple descriptors.
            // TODO(performance - Issue #420): change this to use `writev()` instead of `write()`
            // and get rid of the intermediate buffer.
            for (desc_addr, desc_len) in self.tx.iovec.drain(..) {
                let limit = cmp::min((read_count + desc_len) as usize, self.tx.frame_buf.len());

                let read_result = self.mem.read_slice_at_addr(
                    &mut self.tx.frame_buf[read_count..limit as usize],
                    desc_addr,
                );
                match read_result {
                    Ok(sz) => {
                        read_count += sz;
                    }
                    Err(e) => {
                        error!("Failed to read slice: {:?}", e);
                        METRICS.net.tx_fails.inc();
                        break;
                    }
                }
            }

            let write_result = self.tap.write(&self.tx.frame_buf[..read_count as usize]);
            match write_result {
                Ok(_) => {
                    METRICS.net.tx_bytes_count.add(read_count);
                    METRICS.net.tx_packets_count.inc();
                }
                Err(e) => {
                    error!("Failed to write to tap: {:?}", e);
                    METRICS.net.tx_fails.inc();
                }
            };

            self.tx.used_desc_heads[used_count] = head_index;
            used_count += 1;
        }
        if rate_limited {
            // If rate limiting kicked in, queue had advanced one element that we aborted
            // processing; go back one element so it can be processed next time.
            self.tx.queue.go_to_previous_position();
        }

        if used_count != 0 {
            // TODO(performance - Issue #425): find a way around RUST mutability enforcements to
            // allow calling queue.add_used() inside the loop. This would lead to better distribution
            // of descriptor usage between the firecracker thread and the guest tx thread.
            for &desc_index in &self.tx.used_desc_heads[..used_count] {
                self.tx.queue.add_used(&self.mem, desc_index, 0);
            }
        }
    }

    #[cfg(test)]
    fn rx_single_frame_no_irq_coalescing(&mut self) -> bool {
        let ret = self.rx_single_frame();
        if self.rx.deferred_irqs {
            self.rx.deferred_irqs = false;
            self.signal_used_queue();
        }
        ret
    }

    #[cfg(test)]
    fn get_rx_rate_limiter(&self) -> &RateLimiter {
        &self.rx.rate_limiter
    }

    #[cfg(test)]
    fn get_tx_rate_limiter(&self) -> &RateLimiter {
        &self.tx.rate_limiter
    }

    #[cfg(test)]
    fn set_rx_rate_limiter(&mut self, rx_rate_limiter: RateLimiter) {
        self.rx.rate_limiter = rx_rate_limiter;
    }

    #[cfg(test)]
    fn set_tx_rate_limiter(&mut self, tx_rate_limiter: RateLimiter) {
        self.tx.rate_limiter = tx_rate_limiter;
    }

    #[cfg(not(test))]
    fn read_tap(&mut self) -> io::Result<usize> {
        self.tap.read(&mut self.rx.frame_buf)
    }

    #[cfg(test)]
    fn read_tap(&mut self) -> io::Result<usize> {
        use std::cmp::min;

        let count = min(1234, self.rx.frame_buf.len());

        for i in 0..count {
            self.rx.frame_buf[i] = 5;
        }

        Ok(count)
    }
}

impl EpollHandler for NetEpollHandler {
    fn handle_event(&mut self, device_event: DeviceEventT, _: u32) {
        match device_event {
            RX_TAP_EVENT => {
                METRICS.net.rx_tap_event_count.inc();

                // While limiter is blocked, don't process any more incoming.
                if self.rx.rate_limiter.is_blocked() {
                    return;
                }
                // Process a deferred frame first if available. Don't read from tap again
                // until we manage to receive this deferred frame.
                if self.rx.deferred_frame {
                    if self.rate_limited_rx_single_frame() {
                        self.rx.deferred_frame = false;
                    } else {
                        if self.rx.deferred_irqs {
                            self.rx.deferred_irqs = false;
                            self.signal_used_queue();
                        }
                        return;
                    }
                }
                self.process_rx();
            }
            RX_QUEUE_EVENT => {
                METRICS.net.rx_queue_event_count.inc();
                if let Err(e) = self.rx.queue_evt.read() {
                    error!("Failed to get rx queue event: {:?}", e);
                    METRICS.net.event_fails.inc();
                    // Shouldn't we return here?
                }
                // If the limiter is not blocked, resume the receiving of bytes.
                if !self.rx.rate_limiter.is_blocked() {
                    // There should be a buffer available now to receive the frame into.
                    self.resume_rx();
                }
            }
            TX_QUEUE_EVENT => {
                METRICS.net.tx_queue_event_count.inc();
                if let Err(e) = self.tx.queue_evt.read() {
                    error!("Failed to get tx queue event: {:?}", e);
                    // Shouldn't we return here?
                    METRICS.net.event_fails.inc();
                }
                // If the limiter is not blocked, continue transmitting bytes.
                if !self.tx.rate_limiter.is_blocked() {
                    self.process_tx();
                }
            }
            KILL_EVENT => {
                info!("virtio net device killed")
                // TODO: device should be removed from epoll
            }
            RX_RATE_LIMITER_EVENT => {
                METRICS.net.rx_event_rate_limiter_count.inc();
                // Upon rate limiter event, call the rate limiter handler
                // and restart processing the queue.
                match self.rx.rate_limiter.event_handler() {
                    Ok(_) => {
                        // There might be enough budget now to receive the frame.
                        self.resume_rx();
                    }
                    Err(e) => {
                        METRICS.net.event_fails.inc();
                        error!("Failed to get rx rate-limiter event: {:?}", e)
                    }
                }
            }
            TX_RATE_LIMITER_EVENT => {
                METRICS.net.tx_rate_limiter_event_count.inc();
                // Upon rate limiter event, call the rate limiter handler
                // and restart processing the queue.
                match self.tx.rate_limiter.event_handler() {
                    Ok(_) => {
                        // There might be enough budget now to send the frame.
                        self.process_tx();
                    }
                    Err(e) => {
                        METRICS.net.event_fails.inc();
                        error!("Failed to get tx rate-limiter event: {:?}", e)
                    }
                }
            }
            _ => panic!("Unknown event type was received."),
        }
    }
}

pub struct EpollConfig {
    rx_tap_token: u64,
    rx_queue_token: u64,
    tx_queue_token: u64,
    kill_token: u64,
    rx_rate_limiter_token: u64,
    tx_rate_limiter_token: u64,
    epoll_raw_fd: RawFd,
    sender: mpsc::Sender<Box<EpollHandler>>,
}

impl EpollConfig {
    pub fn new(
        first_token: u64,
        epoll_raw_fd: RawFd,
        sender: mpsc::Sender<Box<EpollHandler>>,
    ) -> Self {
        EpollConfig {
            rx_tap_token: first_token + RX_TAP_EVENT as u64,
            rx_queue_token: first_token + RX_QUEUE_EVENT as u64,
            tx_queue_token: first_token + TX_QUEUE_EVENT as u64,
            kill_token: first_token + KILL_EVENT as u64,
            rx_rate_limiter_token: first_token + RX_RATE_LIMITER_EVENT as u64,
            tx_rate_limiter_token: first_token + TX_RATE_LIMITER_EVENT as u64,
            epoll_raw_fd,
            sender,
        }
    }
}

pub struct Net {
    workers_kill_evt: Option<EventFd>,
    kill_evt: EventFd,
    tap: Option<Tap>,
    avail_features: u64,
    acked_features: u64,
    // The config space will only consist of the MAC address specified by the user,
    // or nothing, if no such address if provided.
    config_space: Vec<u8>,
    epoll_config: EpollConfig,
    rx_rate_limiter: Option<RateLimiter>,
    tx_rate_limiter: Option<RateLimiter>,
}

impl Net {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(
        tap: Tap,
        guest_mac: Option<&MacAddr>,
        epoll_config: EpollConfig,
        rx_rate_limiter: Option<RateLimiter>,
        tx_rate_limiter: Option<RateLimiter>,
    ) -> Result<Self> {
        let kill_evt = EventFd::new().map_err(Error::CreateKillEventFd)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_sys::TUN_F_CSUM | net_sys::TUN_F_UFO | net_sys::TUN_F_TSO4 | net_sys::TUN_F_TSO6,
        ).map_err(Error::TapSetOffload)?;

        let vnet_hdr_size = mem::size_of::<virtio_net_hdr_v1>() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(Error::TapSetVnetHdrSize)?;

        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        let mut config_space;
        if let Some(mac) = guest_mac {
            config_space = Vec::with_capacity(MAC_ADDR_LEN);
            // This is safe, because we know the capacity is large enough.
            unsafe { config_space.set_len(MAC_ADDR_LEN) }
            config_space[..].copy_from_slice(mac.get_bytes());
            // When this feature isn't available, the driver generates a random MAC address.
            // Otherwise, it should attempt to read the device MAC address from the config space.
            avail_features |= 1 << VIRTIO_NET_F_MAC;
        } else {
            config_space = Vec::new();
        }

        Ok(Net {
            workers_kill_evt: Some(kill_evt.try_clone().map_err(Error::CloneKillEventFd)?),
            kill_evt,
            tap: Some(tap),
            avail_features,
            acked_features: 0u64,
            config_space,
            epoll_config,
            rx_rate_limiter,
            tx_rate_limiter,
        })
    }

    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(
        ip_addr: Ipv4Addr,
        netmask: Ipv4Addr,
        guest_mac: Option<&MacAddr>,
        epoll_config: EpollConfig,
        rx_rate_limiter: Option<RateLimiter>,
        tx_rate_limiter: Option<RateLimiter>,
    ) -> Result<Self> {
        let tap = Tap::new().map_err(Error::TapOpen)?;
        tap.set_ip_addr(ip_addr).map_err(Error::TapSetIp)?;
        tap.set_netmask(netmask).map_err(Error::TapSetNetmask)?;
        tap.enable().map_err(Error::TapEnable)?;

        Self::new_with_tap(
            tap,
            guest_mac,
            epoll_config,
            rx_rate_limiter,
            tx_rate_limiter,
        )
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        // Only kill the child if it claimed its eventfd.
        if self.workers_kill_evt.is_none() {
            if let Err(e) = self.kill_evt.write(1) {
                warn!("Failed to trigger kill event: {:?}", e);
                METRICS.net.event_fails.inc();
            }
        }
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            0 => self.avail_features as u32,
            1 => (self.avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page: {}", page);
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => value as u64,
            1 => (value as u64) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page: {}", page);
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {:x}", v);
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    // Taken from block.rs. This will only read data that is actually available in the config space,
    // and leave the rest of the destination buffer as is. When the length of the configuration
    // space is 0, nothing actually happens.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            METRICS.net.cfg_fails.inc();

            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                NUM_QUEUES,
                queues.len()
            );
            METRICS.net.activate_fails.inc();

            return Err(ActivateError::BadActivate);
        }

        if let Some(tap) = self.tap.take() {
            if let Some(kill_evt) = self.workers_kill_evt.take() {
                let kill_raw_fd = kill_evt.as_raw_fd();

                let rx_queue = queues.remove(0);
                let tx_queue = queues.remove(0);
                let rx_queue_evt = queue_evts.remove(0);
                let tx_queue_evt = queue_evts.remove(0);
                let handler = NetEpollHandler {
                    rx: RxVirtio::new(
                        rx_queue,
                        rx_queue_evt,
                        self.rx_rate_limiter.take().unwrap_or_default(),
                    ),
                    tap,
                    mem,
                    tx: TxVirtio::new(
                        tx_queue,
                        tx_queue_evt,
                        self.tx_rate_limiter.take().unwrap_or_default(),
                    ),
                    interrupt_status: status,
                    interrupt_evt,
                    acked_features: self.acked_features,
                };

                let tap_raw_fd = handler.tap.as_raw_fd();
                let rx_queue_raw_fd = handler.rx.queue_evt.as_raw_fd();
                let tx_queue_raw_fd = handler.tx.queue_evt.as_raw_fd();

                let rx_rate_limiter_rawfd = handler.rx.rate_limiter.as_raw_fd();
                let tx_rate_limiter_rawfd = handler.tx.rate_limiter.as_raw_fd();

                //channel should be open and working
                self.epoll_config
                    .sender
                    .send(Box::new(handler))
                    .expect("Failed to send through the channel");

                //TODO: barrier needed here maybe?

                epoll::ctl(
                    self.epoll_config.epoll_raw_fd,
                    epoll::EPOLL_CTL_ADD,
                    tap_raw_fd,
                    epoll::Event::new(epoll::EPOLLIN, self.epoll_config.rx_tap_token),
                ).map_err(|e| {
                    METRICS.net.activate_fails.inc();
                    ActivateError::EpollCtl(e)
                })?;

                epoll::ctl(
                    self.epoll_config.epoll_raw_fd,
                    epoll::EPOLL_CTL_ADD,
                    rx_queue_raw_fd,
                    epoll::Event::new(epoll::EPOLLIN, self.epoll_config.rx_queue_token),
                ).map_err(|e| {
                    METRICS.net.activate_fails.inc();
                    ActivateError::EpollCtl(e)
                })?;

                epoll::ctl(
                    self.epoll_config.epoll_raw_fd,
                    epoll::EPOLL_CTL_ADD,
                    tx_queue_raw_fd,
                    epoll::Event::new(epoll::EPOLLIN, self.epoll_config.tx_queue_token),
                ).map_err(|e| {
                    METRICS.net.activate_fails.inc();
                    ActivateError::EpollCtl(e)
                })?;

                epoll::ctl(
                    self.epoll_config.epoll_raw_fd,
                    epoll::EPOLL_CTL_ADD,
                    kill_raw_fd,
                    epoll::Event::new(epoll::EPOLLIN, self.epoll_config.kill_token),
                ).map_err(|e| {
                    METRICS.net.activate_fails.inc();
                    ActivateError::EpollCtl(e)
                })?;

                if rx_rate_limiter_rawfd != -1 {
                    epoll::ctl(
                        self.epoll_config.epoll_raw_fd,
                        epoll::EPOLL_CTL_ADD,
                        rx_rate_limiter_rawfd,
                        epoll::Event::new(epoll::EPOLLIN, self.epoll_config.rx_rate_limiter_token),
                    ).map_err(ActivateError::EpollCtl)?;
                }

                if tx_rate_limiter_rawfd != -1 {
                    epoll::ctl(
                        self.epoll_config.epoll_raw_fd,
                        epoll::EPOLL_CTL_ADD,
                        tx_rate_limiter_rawfd,
                        epoll::Event::new(epoll::EPOLLIN, self.epoll_config.tx_rate_limiter_token),
                    ).map_err(ActivateError::EpollCtl)?;
                }

                return Ok(());
            }
        }
        METRICS.net.activate_fails.inc();
        Err(ActivateError::BadActivate)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::Receiver;
    use std::thread;
    use std::time::Duration;
    use std::u32;

    use libc;

    use super::*;
    use sys_util::GuestAddress;
    use virtio::queue::tests::*;

    struct DummyNet {
        net: Net,
        epoll_raw_fd: i32,
        _receiver: Receiver<Box<EpollHandler>>,
    }

    impl DummyNet {
        fn new() -> Self {
            let epoll_raw_fd = epoll::create(true).unwrap();
            let (sender, _receiver) = mpsc::channel();
            let epoll_config = EpollConfig::new(0, epoll_raw_fd, sender);

            DummyNet {
                net: Net::new(
                    "192.168.249.1".parse().unwrap(),
                    "255.255.255.0".parse().unwrap(),
                    None,
                    epoll_config,
                    // rate limiters present but with _very high_ allowed rate
                    Some(
                        RateLimiter::new(u64::max_value(), 0, 1000, u64::max_value(), 0, 1000)
                            .unwrap(),
                    ),
                    Some(
                        RateLimiter::new(u64::max_value(), 0, 1000, u64::max_value(), 0, 1000)
                            .unwrap(),
                    ),
                ).unwrap(),
                epoll_raw_fd,
                _receiver,
            }
        }

        fn net(&mut self) -> &mut Net {
            &mut self.net
        }
    }

    impl Drop for DummyNet {
        fn drop(&mut self) {
            unsafe { libc::close(self.epoll_raw_fd) };
        }
    }

    fn activate_some_net(n: &mut Net, bad_qlen: bool, bad_evtlen: bool) -> ActivateResult {
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let interrupt_evt = EventFd::new().unwrap();
        let status = Arc::new(AtomicUsize::new(0));

        let rxq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let txq = VirtQueue::new(GuestAddress(0x1000), &mem, 16);

        assert!(rxq.end().0 < txq.start().0);

        let mut queues = vec![rxq.create_queue(), txq.create_queue()];
        let mut queue_evts = vec![EventFd::new().unwrap(), EventFd::new().unwrap()];

        if bad_qlen {
            queues.pop();
        }

        if bad_evtlen {
            queue_evts.pop();
        }

        n.activate(mem.clone(), interrupt_evt, status, queues, queue_evts)
    }

    #[test]
    fn test_virtio_device() {
        let mut dummy = DummyNet::new();
        let n = dummy.net();

        assert_eq!(n.device_type(), TYPE_NET);
        assert_eq!(n.queue_max_sizes(), QUEUE_SIZES);

        let features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        assert_eq!(n.features(0), features as u32);
        assert_eq!(n.features(1), (features >> 32) as u32);
        for i in 2..10 {
            assert_eq!(n.features(i), 0u32);
        }

        for i in 0..10 {
            n.ack_features(i, u32::MAX);
        }

        assert_eq!(n.acked_features, features);

        // Let's test the activate function.

        // It should fail when not enough queues and/or evts are provided.
        assert!(activate_some_net(n, true, false).is_err());
        assert!(activate_some_net(n, false, true).is_err());
        assert!(activate_some_net(n, true, true).is_err());

        // Otherwise, it should be ok.
        assert!(activate_some_net(n, false, false).is_ok());

        // Second activate shouldn't be ok anymore.
        assert!(activate_some_net(n, false, false).is_err());
    }

    #[test]
    fn test_handler() {
        let mut dummy = DummyNet::new();
        let n = dummy.net();

        let mem = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();

        let rxq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let txq = VirtQueue::new(GuestAddress(0x1000), &mem, 16);

        assert!(rxq.end().0 < txq.start().0);

        let rx_queue = rxq.create_queue();
        let tx_queue = txq.create_queue();
        let interrupt_status = Arc::new(AtomicUsize::new(0));
        let interrupt_evt = EventFd::new().unwrap();
        let rx_queue_evt = EventFd::new().unwrap();
        let tx_queue_evt = EventFd::new().unwrap();

        let mut h = NetEpollHandler {
            rx: RxVirtio::new(rx_queue, rx_queue_evt, RateLimiter::default()),
            tap: n.tap.take().unwrap(),
            mem: mem.clone(),
            tx: TxVirtio::new(tx_queue, tx_queue_evt, RateLimiter::default()),
            interrupt_status,
            interrupt_evt,
            acked_features: n.acked_features,
        };

        let daddr = 0x2000;
        assert!(daddr as usize > txq.end().0);

        // Some corner cases for rx_single_frame().
        {
            assert_eq!(h.rx.bytes_read, 0);

            // Let's imagine we received some data.
            h.rx.bytes_read = MAX_BUFFER_SIZE;

            {
                // a read only descriptor
                rxq.avail.ring[0].set(0);
                rxq.avail.idx.set(1);
                rxq.dtable[0].set(daddr, 0x1000, 0, 0);
                assert!(!h.rx_single_frame_no_irq_coalescing());
                assert_eq!(rxq.used.idx.get(), 1);

                // resetting values
                rxq.used.idx.set(0);
                h.rx.queue = rxq.create_queue();
                h.interrupt_evt.write(1).unwrap();
                // The prev rx_single_frame_no_irq_coalescing() call should have written one more.
                assert_eq!(h.interrupt_evt.read(), Ok(2));
            }

            {
                // We make the prev desc write_only (with no other flag) to get a chain which is
                // writable, but too short.
                rxq.dtable[0].flags.set(VIRTQ_DESC_F_WRITE);
                assert!(!h.rx_single_frame_no_irq_coalescing());
                assert_eq!(rxq.used.idx.get(), 1);

                rxq.used.idx.set(0);
                h.rx.queue = rxq.create_queue();
                h.interrupt_evt.write(1).unwrap();
                assert_eq!(h.interrupt_evt.read(), Ok(2));
            }

            // set rx_count back to 0
            h.rx.bytes_read = 0;
        }

        // Now let's move on to the actual device events.

        {
            // testing TX_QUEUE_EVENT
            txq.avail.idx.set(1);
            txq.avail.ring[0].set(0);
            txq.dtable[0].set(daddr, 0x1000, 0, 0);

            h.tx.queue_evt.write(1).unwrap();
            h.handle_event(TX_QUEUE_EVENT, 0);
            // Make sure the data queue advanced.
            assert_eq!(txq.used.idx.get(), 1);
        }

        {
            // testing RX_TAP_EVENT

            assert!(!h.rx.deferred_frame);

            // this should work just fine
            rxq.avail.idx.set(1);
            rxq.avail.ring[0].set(0);
            rxq.dtable[0].set(daddr, 0x1000, VIRTQ_DESC_F_WRITE, 0);

            h.interrupt_evt.write(1).unwrap();
            h.handle_event(RX_TAP_EVENT, 0);
            assert!(h.rx.deferred_frame);
            assert_eq!(h.interrupt_evt.read(), Ok(2));
            // The #cfg(test) enabled version of read_tap always returns 1234 bytes (or the len of
            // the buffer, whichever is smaller).
            assert_eq!(rxq.used.ring[0].get().len, 1234);

            // Since deferred_frame is now true, activating the same event again will trigger
            // a different execution path.

            // reset some parts of the queue first
            h.rx.queue = rxq.create_queue();
            rxq.used.idx.set(0);

            // this should also be successful
            h.interrupt_evt.write(1).unwrap();
            h.handle_event(RX_TAP_EVENT, 0);
            assert!(h.rx.deferred_frame);
            assert_eq!(h.interrupt_evt.read(), Ok(2));

            // ... but the following shouldn't, because we emulate receiving much more data than
            // we can fit inside a single descriptor

            h.rx.bytes_read = MAX_BUFFER_SIZE;
            h.rx.queue = rxq.create_queue();
            rxq.used.idx.set(0);

            h.interrupt_evt.write(1).unwrap();
            h.handle_event(RX_TAP_EVENT, 0);
            assert!(h.rx.deferred_frame);
            assert_eq!(h.interrupt_evt.read(), Ok(2));

            // A mismatch shows the reception was unsuccessful.
            assert_ne!(rxq.used.ring[0].get().len as usize, h.rx.bytes_read);

            // We set this back to a manageable size, for the following test.
            h.rx.bytes_read = 1234;
        }

        {
            // now also try an RX_QUEUE_EVENT
            rxq.avail.idx.set(2);
            rxq.avail.ring[1].set(1);
            rxq.dtable[1].set(daddr + 0x1000, 0x1000, VIRTQ_DESC_F_WRITE, 0);

            h.rx.queue_evt.write(1).unwrap();
            h.interrupt_evt.write(1).unwrap();
            h.handle_event(RX_QUEUE_EVENT, 0);
            assert_eq!(h.interrupt_evt.read(), Ok(2));
        }

        {
            // does nothing currently
            h.handle_event(KILL_EVENT, 0);
        }
    }

    #[test]
    fn test_bandwidth_rate_limiter() {
        let mut dummy = DummyNet::new();
        let n = dummy.net();

        let mem = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();

        let rxq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let txq = VirtQueue::new(GuestAddress(0x1000), &mem, 16);

        assert!(rxq.end().0 < txq.start().0);

        let rx_queue = rxq.create_queue();
        let tx_queue = txq.create_queue();
        let interrupt_status = Arc::new(AtomicUsize::new(0));
        let interrupt_evt = EventFd::new().unwrap();
        let rx_queue_evt = EventFd::new().unwrap();
        let tx_queue_evt = EventFd::new().unwrap();

        let mut h = NetEpollHandler {
            rx: RxVirtio::new(rx_queue, rx_queue_evt, RateLimiter::default()),
            tap: n.tap.take().unwrap(),
            mem: mem.clone(),
            tx: TxVirtio::new(tx_queue, tx_queue_evt, RateLimiter::default()),
            interrupt_status,
            interrupt_evt,
            acked_features: n.acked_features,
        };

        let daddr = 0x2000;
        assert!(daddr as usize > txq.end().0);

        // Test TX bandwidth rate limiting
        {
            // create bandwidth rate limiter that allows 40960 bytes/s with bucket size 4096 bytes
            let mut rl = RateLimiter::new(0x1000, 0, 100, 0, 0, 0).unwrap();
            // use up the budget
            assert!(rl.consume(0x1000, TokenType::Bytes));

            // set this tx rate limiter to be used
            h.set_tx_rate_limiter(rl);

            // try doing TX
            txq.avail.idx.set(1);
            txq.avail.ring[0].set(0);
            txq.dtable[0].set(daddr, 0x1000, 0, 0);

            // following TX procedure should fail because of bandwidth rate limiting
            {
                // trigger the TX handler
                h.tx.queue_evt.write(1).unwrap();
                h.handle_event(TX_QUEUE_EVENT, 0);

                // assert that limiter is blocked
                assert!(h.get_tx_rate_limiter().is_blocked());
                // make sure the data is still queued for processing
                assert_eq!(txq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 50ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(150));

            // following TX procedure should succeed because bandwidth should now be available
            {
                h.handle_event(TX_RATE_LIMITER_EVENT, 0);
                // validate the rate_limiter is no longer blocked
                assert!(!h.get_tx_rate_limiter().is_blocked());
                // make sure the data queue advanced
                assert_eq!(txq.used.idx.get(), 1);
            }
        }

        // Test RX bandwidth rate limiting
        {
            // create bandwidth rate limiter that allows 40960 bytes/s with bucket size 4096 bytes
            let mut rl = RateLimiter::new(0x1000, 0, 100, 0, 0, 0).unwrap();
            // use up the budget
            assert!(rl.consume(0x1000, TokenType::Bytes));

            // set this rx rate limiter to be used
            h.set_rx_rate_limiter(rl);

            // set up RX
            assert!(!h.rx.deferred_frame);
            rxq.avail.idx.set(1);
            rxq.avail.ring[0].set(0);
            rxq.dtable[0].set(daddr, 0x1000, VIRTQ_DESC_F_WRITE, 0);

            // following RX procedure should fail because of bandwidth rate limiting
            {
                // leave at least one event here so that reading it later won't block
                h.interrupt_evt.write(1).unwrap();
                // trigger the RX handler
                h.handle_event(RX_TAP_EVENT, 0);

                // assert that limiter is blocked
                assert!(h.get_rx_rate_limiter().is_blocked());
                assert!(h.rx.deferred_frame);
                // assert that no operation actually completed (limiter blocked it)
                assert_eq!(h.interrupt_evt.read(), Ok(1));
                // make sure the data is still queued for processing
                assert_eq!(rxq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 50ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(150));

            // following RX procedure should succeed because bandwidth should now be available
            {
                // leave at least one event here so that reading it later won't block
                h.interrupt_evt.write(1).unwrap();
                h.handle_event(RX_RATE_LIMITER_EVENT, 0);
                // validate the rate_limiter is no longer blocked
                assert!(!h.get_rx_rate_limiter().is_blocked());
                // make sure the virtio queue operation completed this time
                assert_eq!(h.interrupt_evt.read(), Ok(2));
                // make sure the data queue advanced
                assert_eq!(rxq.used.idx.get(), 1);
                // The #cfg(test) enabled version of read_tap always returns 1234 bytes
                // (or the len of the buffer, whichever is smaller).
                assert_eq!(rxq.used.ring[0].get().len, 1234);
            }
        }
    }

    #[test]
    fn test_ops_rate_limiter() {
        let mut dummy = DummyNet::new();
        let n = dummy.net();

        let mem = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();

        let rxq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let txq = VirtQueue::new(GuestAddress(0x1000), &mem, 16);

        assert!(rxq.end().0 < txq.start().0);

        let rx_queue = rxq.create_queue();
        let tx_queue = txq.create_queue();
        let interrupt_status = Arc::new(AtomicUsize::new(0));
        let interrupt_evt = EventFd::new().unwrap();
        let rx_queue_evt = EventFd::new().unwrap();
        let tx_queue_evt = EventFd::new().unwrap();

        let mut h = NetEpollHandler {
            rx: RxVirtio::new(rx_queue, rx_queue_evt, RateLimiter::default()),
            tap: n.tap.take().unwrap(),
            mem: mem.clone(),
            tx: TxVirtio::new(tx_queue, tx_queue_evt, RateLimiter::default()),
            interrupt_status,
            interrupt_evt,
            acked_features: n.acked_features,
        };

        let daddr = 0x2000;
        assert!(daddr as usize > txq.end().0);

        // Test TX ops rate limiting
        {
            // create ops rate limiter that allows 10 ops/s with bucket size 1 ops
            let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 100).unwrap();
            // use up the budget
            assert!(rl.consume(1, TokenType::Ops));

            // set this tx rate limiter to be used
            h.set_tx_rate_limiter(rl);

            // try doing TX
            txq.avail.idx.set(1);
            txq.avail.ring[0].set(0);
            txq.dtable[0].set(daddr, 0x1000, 0, 0);

            // following TX procedure should fail because of ops rate limiting
            {
                // trigger the TX handler
                h.tx.queue_evt.write(1).unwrap();
                h.handle_event(TX_QUEUE_EVENT, 0);

                // assert that limiter is blocked
                assert!(h.get_tx_rate_limiter().is_blocked());
                // make sure the data is still queued for processing
                assert_eq!(txq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 50ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(150));

            // following TX procedure should succeed because ops should now be available
            {
                h.handle_event(TX_RATE_LIMITER_EVENT, 0);
                // validate the rate_limiter is no longer blocked
                assert!(!h.get_tx_rate_limiter().is_blocked());
                // make sure the data queue advanced
                assert_eq!(txq.used.idx.get(), 1);
            }
        }

        // Test RX ops rate limiting
        {
            // create ops rate limiter that allows 10 ops/s with bucket size 1 ops
            let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 100).unwrap();
            // use up the budget
            assert!(rl.consume(0x800, TokenType::Ops));

            // set this rx rate limiter to be used
            h.set_rx_rate_limiter(rl);

            // set up RX
            assert!(!h.rx.deferred_frame);
            rxq.avail.idx.set(1);
            rxq.avail.ring[0].set(0);
            rxq.dtable[0].set(daddr, 0x1000, VIRTQ_DESC_F_WRITE, 0);

            // following RX procedure should fail because of ops rate limiting
            {
                // leave at least one event here so that reading it later won't block
                h.interrupt_evt.write(1).unwrap();
                // trigger the RX handler
                h.handle_event(RX_TAP_EVENT, 0);

                // assert that limiter is blocked
                assert!(h.get_rx_rate_limiter().is_blocked());
                assert!(h.rx.deferred_frame);
                // assert that no operation actually completed (limiter blocked it)
                assert_eq!(h.interrupt_evt.read(), Ok(1));
                // make sure the data is still queued for processing
                assert_eq!(rxq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 50ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(150));

            // following RX procedure should succeed because ops should now be available
            {
                // leave at least one event here so that reading it later won't block
                h.interrupt_evt.write(1).unwrap();
                h.handle_event(RX_RATE_LIMITER_EVENT, 0);
                // make sure the virtio queue operation completed this time
                assert_eq!(h.interrupt_evt.read(), Ok(2));
                // make sure the data queue advanced
                assert_eq!(rxq.used.idx.get(), 1);
                // The #cfg(test) enabled version of read_tap always returns 1234 bytes
                // (or the len of the buffer, whichever is smaller).
                assert_eq!(rxq.used.ring[0].get().len, 1234);
            }
        }
    }
}
