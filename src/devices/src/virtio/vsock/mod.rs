// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod csm;
mod device;
mod epoll_handler;
mod packet;
mod unix;

pub use self::defs::uapi::VIRTIO_ID_VSOCK as TYPE_VSOCK;
pub use self::defs::EVENT_COUNT as VSOCK_EVENTS_COUNT;
pub use self::device::Vsock;
pub use self::unix::{Error as VsockUnixBackendError, VsockUnixBackend};

use std::os::unix::io::RawFd;
use std::sync::mpsc;

use vm_memory::GuestMemoryError;

use super::super::EpollHandler;
use super::EpollConfigConstructor;
use packet::VsockPacket;

mod defs {
    use crate::DeviceEventT;

    /// RX queue event: the driver added available buffers to the RX queue.
    pub const RXQ_EVENT: DeviceEventT = 0;
    /// TX queue event: the driver added available buffers to the RX queue.
    pub const TXQ_EVENT: DeviceEventT = 1;
    /// Event queue event: the driver added available buffers to the event queue.
    pub const EVQ_EVENT: DeviceEventT = 2;
    /// Backend event: the backend needs a kick.
    pub const BACKEND_EVENT: DeviceEventT = 3;
    /// Total number of events known to the vsock epoll handler.
    pub const EVENT_COUNT: usize = 4;

    /// Number of virtio queues.
    pub const NUM_QUEUES: usize = 3;
    /// Virtio queue sizes, in number of descriptor chain heads.
    /// There are 3 queues for a virtio device (in this order): RX, TX, Event
    pub const QUEUE_SIZES: &[u16] = &[256; NUM_QUEUES];

    /// Max vsock packet data/buffer size.
    pub const MAX_PKT_BUF_SIZE: usize = 64 * 1024;

    pub mod uapi {

        /// Virtio feature flags.
        /// Defined in `/include/uapi/linux/virtio_config.h`.
        ///
        /// The device processes available buffers in the same order in which the device
        /// offers them.
        pub const VIRTIO_F_IN_ORDER: usize = 35;
        /// The device conforms to the virtio spec version 1.0.
        pub const VIRTIO_F_VERSION_1: u32 = 32;

        /// Virtio vsock device ID.
        /// Defined in `include/uapi/linux/virtio_ids.h`.
        pub const VIRTIO_ID_VSOCK: u32 = 19;

        /// Vsock packet operation IDs.
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Connection request.
        pub const VSOCK_OP_REQUEST: u16 = 1;
        /// Connection response.
        pub const VSOCK_OP_RESPONSE: u16 = 2;
        /// Connection reset.
        pub const VSOCK_OP_RST: u16 = 3;
        /// Connection clean shutdown.
        pub const VSOCK_OP_SHUTDOWN: u16 = 4;
        /// Connection data (read/write).
        pub const VSOCK_OP_RW: u16 = 5;
        /// Flow control credit update.
        pub const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
        /// Flow control credit update request.
        pub const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

        /// Vsock packet flags.
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Valid with a VSOCK_OP_SHUTDOWN packet: the packet sender will receive no more data.
        pub const VSOCK_FLAGS_SHUTDOWN_RCV: u32 = 1;
        /// Valid with a VSOCK_OP_SHUTDOWN packet: the packet sender will send no more data.
        pub const VSOCK_FLAGS_SHUTDOWN_SEND: u32 = 2;

        /// Vsock packet type.
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Stream / connection-oriented packet (the only currently valid type).
        pub const VSOCK_TYPE_STREAM: u16 = 1;

        pub const VSOCK_HOST_CID: u64 = 2;
    }
}

#[derive(Debug)]
pub enum VsockError {
    /// The vsock data/buffer virtio descriptor length is smaller than expected.
    BufDescTooSmall,
    /// The vsock data/buffer virtio descriptor is expected, but missing.
    BufDescMissing,
    /// Chained GuestMemoryMmap error.
    GuestMemoryMmap(GuestMemoryError),
    /// Bounds check failed on guest memory pointer.
    GuestMemoryBounds,
    /// The vsock header descriptor length is too small.
    HdrDescTooSmall(u32),
    /// The vsock header `len` field holds an invalid value.
    InvalidPktLen(u32),
    /// A data fetch was attempted when no data was available.
    NoData,
    /// A data buffer was expected for the provided packet, but it is missing.
    PktBufMissing,
    /// Encountered an unexpected write-only virtio descriptor.
    UnreadableDescriptor,
    /// Encountered an unexpected read-only virtio descriptor.
    UnwritableDescriptor,
}
type Result<T> = std::result::Result<T, VsockError>;

pub struct EpollConfig {
    rxq_token: u64,
    txq_token: u64,
    evq_token: u64,
    backend_token: u64,
    epoll_raw_fd: RawFd,
    sender: mpsc::Sender<Box<dyn EpollHandler>>,
}

impl EpollConfigConstructor for EpollConfig {
    fn new(
        first_token: u64,
        epoll_raw_fd: RawFd,
        sender: mpsc::Sender<Box<dyn EpollHandler>>,
    ) -> Self {
        EpollConfig {
            rxq_token: first_token + u64::from(defs::RXQ_EVENT),
            txq_token: first_token + u64::from(defs::TXQ_EVENT),
            evq_token: first_token + u64::from(defs::EVQ_EVENT),
            backend_token: first_token + u64::from(defs::BACKEND_EVENT),
            epoll_raw_fd,
            sender,
        }
    }
}

/// A passive, event-driven object, that needs to be notified whenever an epoll-able event occurs.
/// An event-polling control loop will use `get_polled_fd()` and `get_polled_evset()` to query
/// the listener for the file descriptor and the set of events it's interested in. When such an
/// event occurs, the control loop will route the event to the listener via `notify()`.
pub trait VsockEpollListener {
    /// Get the file descriptor the listener needs polled.
    fn get_polled_fd(&self) -> RawFd;

    /// Get the set of events for which the listener wants to be notified.
    fn get_polled_evset(&self) -> epoll::Events;

    /// Notify the listener that one ore more events have occurred.
    fn notify(&mut self, evset: epoll::Events);
}

/// Any channel that handles vsock packet traffic: sending and receiving packets. Since we're
/// implementing the device model here, our responsibility is to always process the sending of
/// packets (i.e. the TX queue). So, any locally generated data, addressed to the driver (e.g.
/// a connection response or RST), will have to be queued, until we get to processing the RX queue.
///
/// Note: `recv_pkt()` and `send_pkt()` are named analogous to `Read::read()` and `Write::write()`,
///       respectively. I.e.
///       - `recv_pkt(&mut pkt)` will read data from the channel, and place it into `pkt`; and
///       - `send_pkt(&pkt)` will fetch data from `pkt`, and place it into the channel.
pub trait VsockChannel {
    /// Read/receive an incoming packet from the channel.
    fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> Result<()>;

    /// Write/send a packet through the channel.
    fn send_pkt(&mut self, pkt: &VsockPacket) -> Result<()>;

    /// Checks whether there is pending incoming data inside the channel, meaning that a subsequent
    /// call to `recv_pkt()` won't fail.
    fn has_pending_rx(&self) -> bool;
}

/// The vsock backend, which is basically an epoll-event-driven vsock channel, that needs to be
/// sendable through a mpsc channel (the latter due to how `vmm::EpollContext` works).
/// Currently, the only implementation we have is `crate::virtio::unix::muxer::VsockMuxer`, which
/// translates guest-side vsock connections to host-side Unix domain socket connections.
pub trait VsockBackend: VsockChannel + VsockEpollListener + Send {}

#[cfg(test)]
mod tests {
    use super::epoll_handler::VsockEpollHandler;
    use super::packet::VSOCK_PKT_HDR_SIZE;
    use super::*;

    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use utils::eventfd::EventFd;

    use crate::virtio::queue::tests::VirtQueue as GuestQ;
    use crate::virtio::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    pub struct TestBackend {
        pub evfd: EventFd,
        pub rx_err: Option<VsockError>,
        pub tx_err: Option<VsockError>,
        pub pending_rx: bool,
        pub rx_ok_cnt: usize,
        pub tx_ok_cnt: usize,
        pub evset: Option<epoll::Events>,
    }
    impl TestBackend {
        pub fn new() -> Self {
            Self {
                evfd: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                rx_err: None,
                tx_err: None,
                pending_rx: false,
                rx_ok_cnt: 0,
                tx_ok_cnt: 0,
                evset: None,
            }
        }
        pub fn set_rx_err(&mut self, err: Option<VsockError>) {
            self.rx_err = err;
        }
        pub fn set_tx_err(&mut self, err: Option<VsockError>) {
            self.tx_err = err;
        }
        pub fn set_pending_rx(&mut self, prx: bool) {
            self.pending_rx = prx;
        }
    }
    impl VsockChannel for TestBackend {
        fn recv_pkt(&mut self, _pkt: &mut VsockPacket) -> Result<()> {
            let cool_buf = [0xDu8, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF];
            match self.rx_err.take() {
                None => {
                    if let Some(buf) = _pkt.buf_mut() {
                        for i in 0..buf.len() {
                            buf[i] = cool_buf[i % cool_buf.len()];
                        }
                    }
                    self.rx_ok_cnt += 1;
                    Ok(())
                }
                Some(e) => Err(e),
            }
        }

        fn send_pkt(&mut self, _pkt: &VsockPacket) -> Result<()> {
            match self.tx_err.take() {
                None => {
                    self.tx_ok_cnt += 1;
                    Ok(())
                }
                Some(e) => Err(e),
            }
        }

        fn has_pending_rx(&self) -> bool {
            self.pending_rx
        }
    }
    impl VsockEpollListener for TestBackend {
        fn get_polled_fd(&self) -> RawFd {
            self.evfd.as_raw_fd()
        }
        fn get_polled_evset(&self) -> epoll::Events {
            epoll::Events::EPOLLIN
        }
        fn notify(&mut self, evset: epoll::Events) {
            self.evset = Some(evset);
        }
    }
    impl VsockBackend for TestBackend {}

    pub struct TestContext {
        pub cid: u64,
        pub mem: GuestMemoryMmap,
        pub mem_size: usize,
        pub device: Vsock<TestBackend>,

        // This needs to live here, so that sending the handler, at device activation, works.
        _handler_receiver: mpsc::Receiver<Box<dyn EpollHandler>>,
    }

    impl TestContext {
        pub fn new() -> Self {
            const CID: u64 = 52;
            const MEM_SIZE: usize = 1024 * 1024 * 128;
            let (sender, _handler_receiver) = mpsc::channel();
            Self {
                cid: CID,
                mem: GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap(),
                mem_size: MEM_SIZE,
                device: Vsock::new(
                    CID,
                    EpollConfig::new(0, epoll::create(true).unwrap(), sender),
                    TestBackend::new(),
                )
                .unwrap(),
                _handler_receiver,
            }
        }

        pub fn create_epoll_handler_context(&self) -> EpollHandlerContext {
            const QSIZE: u16 = 2;

            let guest_rxvq = GuestQ::new(GuestAddress(0x0010_0000), &self.mem, QSIZE as u16);
            let guest_txvq = GuestQ::new(GuestAddress(0x0020_0000), &self.mem, QSIZE as u16);
            let guest_evvq = GuestQ::new(GuestAddress(0x0030_0000), &self.mem, QSIZE as u16);
            let rxvq = guest_rxvq.create_queue();
            let txvq = guest_txvq.create_queue();
            let evvq = guest_evvq.create_queue();

            // Set up one available descriptor in the RX queue.
            guest_rxvq.dtable[0].set(
                0x0040_0000,
                VSOCK_PKT_HDR_SIZE as u32,
                VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
                1,
            );
            guest_rxvq.dtable[1].set(0x0040_1000, 4096, VIRTQ_DESC_F_WRITE, 0);

            guest_rxvq.avail.ring[0].set(0);
            guest_rxvq.avail.idx.set(1);

            // Set up one available descriptor in the TX queue.
            guest_txvq.dtable[0].set(0x0050_0000, VSOCK_PKT_HDR_SIZE as u32, VIRTQ_DESC_F_NEXT, 1);
            guest_txvq.dtable[1].set(0x0050_1000, 4096, 0, 0);
            guest_txvq.avail.ring[0].set(0);
            guest_txvq.avail.idx.set(1);

            EpollHandlerContext {
                guest_rxvq,
                guest_txvq,
                guest_evvq,
                handler: VsockEpollHandler {
                    rxvq,
                    rxvq_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                    txvq,
                    txvq_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                    evvq,
                    evvq_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                    cid: self.cid,
                    mem: self.mem.clone(),
                    interrupt_status: Arc::new(AtomicUsize::new(0)),
                    interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                    backend: TestBackend::new(),
                },
            }
        }
    }

    pub struct EpollHandlerContext<'a> {
        pub handler: VsockEpollHandler<TestBackend>,
        pub guest_rxvq: GuestQ<'a>,
        pub guest_txvq: GuestQ<'a>,
        pub guest_evvq: GuestQ<'a>,
    }

    impl<'a> EpollHandlerContext<'a> {
        pub fn signal_txq_event(&mut self) {
            self.handler.txvq_evt.write(1).unwrap();
            self.handler
                .handle_event(defs::TXQ_EVENT, epoll::Events::EPOLLIN)
                .unwrap();
        }
        pub fn signal_rxq_event(&mut self) {
            self.handler.rxvq_evt.write(1).unwrap();
            self.handler
                .handle_event(defs::RXQ_EVENT, epoll::Events::EPOLLIN)
                .unwrap();
        }
    }
}
