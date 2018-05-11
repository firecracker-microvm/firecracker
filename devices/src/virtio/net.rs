// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
#[cfg(not(test))]
use std::io::Read;
use std::io::{self, Write};
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

use libc::EAGAIN;

use super::{ActivateError, ActivateResult};
use super::{Queue, VirtioDevice, TYPE_NET, VIRTIO_MMIO_INT_VRING};
use epoll;
use net_sys;
use net_util::{MacAddr, Tap, TapError, MAC_ADDR_LEN};
use sys_util::{Error as SysError, EventFd, GuestMemory};
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
pub const RX_TAP_EVENT: DeviceEventT = 0;
// The guest has made a buffer available to receive a frame into.
pub const RX_QUEUE_EVENT: DeviceEventT = 1;
// The transmit queue has a frame that is ready to send from the guest.
pub const TX_QUEUE_EVENT: DeviceEventT = 2;
// Device shutdown has been requested.
pub const KILL_EVENT: DeviceEventT = 3;

#[derive(Debug)]
pub enum NetError {
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
    /// Error while polling for events.
    PollError(SysError),
}

struct NetEpollHandler {
    mem: GuestMemory,
    rx_queue: Queue,
    tx_queue: Queue,
    tap: Tap,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    rx_buf: [u8; MAX_BUFFER_SIZE],
    rx_count: usize,
    deferred_rx: bool,
    // TODO(smbarber): http://crbug.com/753630
    // Remove once MRG_RXBUF is supported and this variable is actually used.
    #[allow(dead_code)]
    acked_features: u64,
    rx_queue_evt: EventFd,
    tx_queue_evt: EventFd,
}

impl NetEpollHandler {
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    // Copies a single frame from `self.rx_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self) -> bool {
        let mut next_desc = self.rx_queue.iter(&self.mem).next();

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
                    let limit = cmp::min(write_count + desc.len as usize, self.rx_count);
                    let source_slice = &self.rx_buf[write_count..limit];
                    let write_result = self.mem.write_slice_at_addr(source_slice, desc.addr);

                    match write_result {
                        Ok(sz) => {
                            write_count += sz;
                        }
                        Err(e) => {
                            warn!("net: rx: failed to write slice: {:?}", e);
                            break;
                        }
                    };

                    if write_count >= self.rx_count {
                        break;
                    }
                    next_desc = desc.next_descriptor();
                }
                None => {
                    warn!(
                        "net: rx: buffer is too small to hold frame of size {}",
                        self.rx_count
                    );
                    break;
                }
            }
        }

        self.rx_queue
            .add_used(&self.mem, head_index, write_count as u32);

        // Interrupt the guest immediately for received frames to
        // reduce latency.
        self.signal_used_queue();

        write_count >= self.rx_count
    }

    #[cfg(not(test))]
    fn read_tap(&mut self) -> io::Result<usize> {
        self.tap.read(&mut self.rx_buf)
    }

    #[cfg(test)]
    fn read_tap(&mut self) -> io::Result<usize> {
        use std::cmp::min;

        let count = min(1234, self.rx_buf.len());

        for i in 0..count {
            self.rx_buf[i] = 5;
        }

        Ok(count)
    }

    fn process_rx(&mut self) {
        // Read as many frames as possible.
        loop {
            let res = self.read_tap();
            match res {
                Ok(count) => {
                    self.rx_count = count;
                    if !self.rx_single_frame() {
                        self.deferred_rx = true;
                        break;
                    }
                }
                Err(e) => {
                    // The tap device is nonblocking, so any error aside from EAGAIN is
                    // unexpected.
                    if e.raw_os_error().unwrap() != EAGAIN {
                        warn!("net: rx: failed to read tap: {:?}", e);
                    }
                    break;
                }
            }
        }
    }

    fn process_tx(&mut self) {
        let mut frame = [0u8; MAX_BUFFER_SIZE];
        let mut used_desc_heads = [0u16; QUEUE_SIZE as usize];
        let mut used_count = 0;

        for avail_desc in self.tx_queue.iter(&self.mem) {
            let head_index = avail_desc.index;
            let mut next_desc = Some(avail_desc);
            let mut read_count = 0;

            // Copy buffer from across multiple descriptors.
            loop {
                match next_desc {
                    Some(desc) => {
                        if desc.is_write_only() {
                            break;
                        }
                        let limit = cmp::min(read_count + desc.len as usize, frame.len());
                        let read_result = self.mem
                            .read_slice_at_addr(&mut frame[read_count..limit as usize], desc.addr);
                        match read_result {
                            Ok(sz) => {
                                read_count += sz;
                            }
                            Err(e) => {
                                warn!("net: tx: failed to read slice: {:?}", e);
                                break;
                            }
                        }
                        next_desc = desc.next_descriptor();
                    }
                    None => {
                        break;
                    }
                }
            }

            let write_result = self.tap.write(&frame[..read_count as usize]);
            match write_result {
                Ok(_) => {}
                Err(e) => {
                    warn!("net: tx: error failed to write to tap: {:?}", e);
                }
            };

            used_desc_heads[used_count] = head_index;
            used_count += 1;
        }

        for &desc_index in &used_desc_heads[..used_count] {
            self.tx_queue.add_used(&self.mem, desc_index, 0);
        }

        self.signal_used_queue();
    }
}

impl EpollHandler for NetEpollHandler {
    fn handle_event(&mut self, device_event: DeviceEventT, _: u32) {
        match device_event {
            RX_TAP_EVENT => {
                // Process a deferred frame first if available. Don't read from tap again
                // until we manage to receive this deferred frame.
                if self.deferred_rx {
                    if self.rx_single_frame() {
                        self.deferred_rx = false;
                    } else {
                        return;
                    }
                }
                self.process_rx();
            }
            RX_QUEUE_EVENT => {
                if let Err(e) = self.rx_queue_evt.read() {
                    error!("net: error reading rx queue EventFd: {:?}", e);
                    //TODO: device should be removed from epoll
                }
                // There should be a buffer available now to receive the frame into.
                if self.deferred_rx && self.rx_single_frame() {
                    self.deferred_rx = false;
                }
            }
            TX_QUEUE_EVENT => {
                if let Err(e) = self.tx_queue_evt.read() {
                    error!("net: error reading tx queue EventFd: {:?}", e);
                    //TODO: device should be removed from epoll
                }
                self.process_tx();
            }
            KILL_EVENT => {
                info!("virtio net device killed")
                //TODO: device should be removed from epoll
            }
            _ => panic!("unknown token for virtio net device"),
        }
    }
}

pub struct EpollConfig {
    rx_tap_token: u64,
    rx_queue_token: u64,
    tx_queue_token: u64,
    kill_token: u64,
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
            rx_tap_token: first_token,
            rx_queue_token: first_token + 1,
            tx_queue_token: first_token + 2,
            kill_token: first_token + 3,
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
}

impl Net {
    pub fn new_with_tap(
        tap: Tap,
        guest_mac: Option<&MacAddr>,
        epoll_config: EpollConfig,
    ) -> Result<Self, NetError> {
        let kill_evt = EventFd::new().map_err(NetError::CreateKillEventFd)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_sys::TUN_F_CSUM | net_sys::TUN_F_UFO | net_sys::TUN_F_TSO4 | net_sys::TUN_F_TSO6,
        ).map_err(NetError::TapSetOffload)?;

        let vnet_hdr_size = mem::size_of::<virtio_net_hdr_v1>() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(NetError::TapSetVnetHdrSize)?;

        let mut avail_features =
            1 << VIRTIO_NET_F_GUEST_CSUM | 1 << VIRTIO_NET_F_CSUM | 1 << VIRTIO_NET_F_GUEST_TSO4
                | 1 << VIRTIO_NET_F_GUEST_UFO | 1 << VIRTIO_NET_F_HOST_TSO4
                | 1 << VIRTIO_NET_F_HOST_UFO | 1 << VIRTIO_F_VERSION_1;

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
            workers_kill_evt: Some(kill_evt.try_clone().map_err(NetError::CloneKillEventFd)?),
            kill_evt,
            tap: Some(tap),
            avail_features,
            acked_features: 0u64,
            config_space,
            epoll_config,
        })
    }

    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(
        ip_addr: Ipv4Addr,
        netmask: Ipv4Addr,
        guest_mac: Option<&MacAddr>,
        epoll_config: EpollConfig,
    ) -> Result<Self, NetError> {
        let tap = Tap::new().map_err(NetError::TapOpen)?;
        tap.set_ip_addr(ip_addr).map_err(NetError::TapSetIp)?;
        tap.set_netmask(netmask).map_err(NetError::TapSetNetmask)?;
        tap.enable().map_err(NetError::TapEnable)?;

        Self::new_with_tap(tap, guest_mac, epoll_config)
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        // Only kill the child if it claimed its eventfd.
        if self.workers_kill_evt.is_none() {
            // Ignore the result because there is nothing we can do about it.
            let _ = self.kill_evt.write(1);
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
                warn!("net: virtio net got request for features page: {}", page);
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => value as u64,
            1 => (value as u64) << 32,
            _ => {
                warn!(
                    "net: virtio net device cannot ack unknown feature page: {}",
                    page
                );
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("net: virtio net got unknown feature ack: {:x}", v);

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
                "virtio-net expected {} queues, got {}",
                NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if let Some(tap) = self.tap.take() {
            if let Some(kill_evt) = self.workers_kill_evt.take() {
                let kill_raw_fd = kill_evt.as_raw_fd();

                let handler = NetEpollHandler {
                    mem,
                    rx_queue: queues.remove(0),
                    tx_queue: queues.remove(0),
                    tap,
                    interrupt_status: status,
                    interrupt_evt,
                    rx_buf: [0u8; MAX_BUFFER_SIZE],
                    rx_count: 0,
                    deferred_rx: false,
                    acked_features: self.acked_features,
                    rx_queue_evt: queue_evts.remove(0),
                    tx_queue_evt: queue_evts.remove(0),
                };

                let tap_raw_fd = handler.tap.as_raw_fd();
                let rx_queue_raw_fd = handler.rx_queue_evt.as_raw_fd();
                let tx_queue_raw_fd = handler.tx_queue_evt.as_raw_fd();

                //channel should be open and working
                self.epoll_config.sender.send(Box::new(handler)).unwrap();

                //TODO: barrier needed here maybe?

                epoll::ctl(
                    self.epoll_config.epoll_raw_fd,
                    epoll::EPOLL_CTL_ADD,
                    tap_raw_fd,
                    epoll::Event::new(epoll::EPOLLIN, self.epoll_config.rx_tap_token),
                ).map_err(ActivateError::EpollCtl)?;

                epoll::ctl(
                    self.epoll_config.epoll_raw_fd,
                    epoll::EPOLL_CTL_ADD,
                    rx_queue_raw_fd,
                    epoll::Event::new(epoll::EPOLLIN, self.epoll_config.rx_queue_token),
                ).map_err(ActivateError::EpollCtl)?;

                epoll::ctl(
                    self.epoll_config.epoll_raw_fd,
                    epoll::EPOLL_CTL_ADD,
                    tx_queue_raw_fd,
                    epoll::Event::new(epoll::EPOLLIN, self.epoll_config.tx_queue_token),
                ).map_err(ActivateError::EpollCtl)?;

                epoll::ctl(
                    self.epoll_config.epoll_raw_fd,
                    epoll::EPOLL_CTL_ADD,
                    kill_raw_fd,
                    epoll::Event::new(epoll::EPOLLIN, self.epoll_config.kill_token),
                ).map_err(ActivateError::EpollCtl)?;

                return Ok(());
            }
        }

        Err(ActivateError::BadActivate)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::Receiver;
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

        let features = 1 << VIRTIO_NET_F_GUEST_CSUM | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4 | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4 | 1 << VIRTIO_NET_F_HOST_UFO
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
            mem: mem.clone(),
            rx_queue,
            tx_queue,
            tap: n.tap.take().unwrap(),
            interrupt_status,
            interrupt_evt,
            rx_buf: [0u8; MAX_BUFFER_SIZE],
            rx_count: 0,
            deferred_rx: false,
            acked_features: n.acked_features,
            rx_queue_evt,
            tx_queue_evt,
        };

        let daddr = 0x2000;
        assert!(daddr as usize > txq.end().0);

        // Some corner cases for rx_single_frame().
        {
            assert_eq!(h.rx_count, 0);

            // Let's imagine we received some data.
            h.rx_count = MAX_BUFFER_SIZE;

            {
                // a read only descriptor
                rxq.avail.ring[0].set(0);
                rxq.avail.idx.set(1);
                rxq.dtable[0].set(daddr, 0x1000, 0, 0);
                assert!(!h.rx_single_frame());
                assert_eq!(rxq.used.idx.get(), 1);

                // resetting values
                rxq.used.idx.set(0);
                h.rx_queue = rxq.create_queue();
                h.interrupt_evt.write(1).unwrap();
                // The prev rx_single_frame() call should have written one more.
                assert_eq!(h.interrupt_evt.read(), Ok(2));
            }

            {
                // We make the prev desc write_only (with no other flag) to get a chain which is
                // writable, but too short.
                rxq.dtable[0].flags.set(VIRTQ_DESC_F_WRITE);
                assert!(!h.rx_single_frame());
                assert_eq!(rxq.used.idx.get(), 1);

                rxq.used.idx.set(0);
                h.rx_queue = rxq.create_queue();
                h.interrupt_evt.write(1).unwrap();
                assert_eq!(h.interrupt_evt.read(), Ok(2));
            }

            // set rx_count back to 0
            h.rx_count = 0;
        }

        // Now let's move on to the actual device events.

        {
            // testing TX_QUEUE_EVENT
            txq.avail.idx.set(1);
            txq.avail.ring[0].set(0);
            txq.dtable[0].set(daddr, 0x1000, 0, 0);

            h.tx_queue_evt.write(1).unwrap();
            h.interrupt_evt.write(1).unwrap();
            h.handle_event(TX_QUEUE_EVENT, 0);
            assert_eq!(h.interrupt_evt.read(), Ok(2));
        }

        {
            // testing RX_TAP_EVENT

            assert!(!h.deferred_rx);

            // this should work just fine
            rxq.avail.idx.set(1);
            rxq.avail.ring[0].set(0);
            rxq.dtable[0].set(daddr, 0x1000, VIRTQ_DESC_F_WRITE, 0);

            h.interrupt_evt.write(1).unwrap();
            h.handle_event(RX_TAP_EVENT, 0);
            assert!(h.deferred_rx);
            assert_eq!(h.interrupt_evt.read(), Ok(2));
            // The #cfg(test) enabled version of read_tap always returns 1234 bytes (or the len of
            // the buffer, whichever is smaller).
            assert_eq!(rxq.used.ring[0].get().len, 1234);

            // Since deferred_rx is now true, activating the same event again will trigger
            // a different execution path.

            // reset some parts of the queue first
            h.rx_queue = rxq.create_queue();
            rxq.used.idx.set(0);

            // this should also be successful
            h.interrupt_evt.write(1).unwrap();
            h.handle_event(RX_TAP_EVENT, 0);
            assert!(h.deferred_rx);
            assert_eq!(h.interrupt_evt.read(), Ok(2));

            // ... but the following shouldn't, because we emulate receiving much more data than
            // we can fit inside a single descriptor

            h.rx_count = MAX_BUFFER_SIZE;
            h.rx_queue = rxq.create_queue();
            rxq.used.idx.set(0);

            h.interrupt_evt.write(1).unwrap();
            h.handle_event(RX_TAP_EVENT, 0);
            assert!(h.deferred_rx);
            assert_eq!(h.interrupt_evt.read(), Ok(2));

            // A mismatch shows the reception was unsuccessful.
            assert_ne!(rxq.used.ring[0].get().len as usize, h.rx_count);

            // We set this back to a manageable size, for the following test.
            h.rx_count = 1234;
        }

        {
            // now also try an RX_QUEUE_EVENT
            rxq.avail.idx.set(2);
            rxq.avail.ring[1].set(1);
            rxq.dtable[1].set(daddr + 0x1000, 0x1000, VIRTQ_DESC_F_WRITE, 0);

            h.rx_queue_evt.write(1).unwrap();
            h.interrupt_evt.write(1).unwrap();
            h.handle_event(RX_QUEUE_EVENT, 0);
            assert!(!h.deferred_rx);
            assert_eq!(h.interrupt_evt.read(), Ok(2));
        }

        {
            // does nothing currently
            h.handle_event(KILL_EVENT, 0);
        }
    }
}
