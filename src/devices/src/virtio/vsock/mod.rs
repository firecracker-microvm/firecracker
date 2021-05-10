// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod csm;
mod device;
mod event_handler;
mod packet;
pub mod persist;
pub mod test_utils;
mod unix;

use std::os::unix::io::AsRawFd;

use crate::virtio::persist::Error as VirtioStateError;

pub use self::defs::uapi::VIRTIO_ID_VSOCK as TYPE_VSOCK;
pub use self::device::Vsock;
pub use self::unix::{Error as VsockUnixBackendError, VsockUnixBackend};

use utils::epoll::EventSet;
use vm_memory::GuestMemoryError;

use packet::VsockPacket;

mod defs {
    /// Device ID used in MMIO device identification.
    /// Because Vsock is unique per-vm, this ID can be hardcoded.
    pub const VSOCK_DEV_ID: &str = "vsock";

    /// Number of virtio queues.
    pub const NUM_QUEUES: usize = 3;
    /// Max size of virtio queues.
    pub const QUEUE_SIZE: u16 = 256;
    /// Virtio queue sizes, in number of descriptor chain heads.
    /// There are 3 queues for a virtio device (in this order): RX, TX, Event
    pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

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
    /// EventFd error
    EventFd(std::io::Error),
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
    /// Invalid virtio configuration.
    VirtioState(VirtioStateError),
    VsockUdsBackend(VsockUnixBackendError),
}

type Result<T> = std::result::Result<T, VsockError>;

/// A passive, event-driven object, that needs to be notified whenever an epoll-able event occurs.
/// An event-polling control loop will use `as_raw_fd()` and `get_polled_evset()` to query
/// the listener for the file descriptor and the set of events it's interested in. When such an
/// event occurs, the control loop will route the event to the listener via `notify()`.
pub trait VsockEpollListener: AsRawFd {
    /// Get the set of events for which the listener wants to be notified.
    fn get_polled_evset(&self) -> EventSet;

    /// Notify the listener that one ore more events have occurred.
    fn notify(&mut self, evset: EventSet);
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

/// The vsock backend, which is basically an epoll-event-driven vsock channel.
/// Currently, the only implementation we have is `crate::virtio::unix::muxer::VsockMuxer`, which
/// translates guest-side vsock connections to host-side Unix domain socket connections.
pub trait VsockBackend: VsockChannel + VsockEpollListener + Send {}
