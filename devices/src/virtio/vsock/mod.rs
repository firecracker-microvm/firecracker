// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod device;
mod epoll_handler;

pub use self::defs::uapi::VIRTIO_ID_VSOCK as TYPE_VSOCK;
pub use self::defs::EVENT_COUNT as VSOCK_EVENTS_COUNT;
pub use self::device::Vsock;
pub use DummyBackend as VsockUnixBackend;

use std::os::unix::io::RawFd;
use std::sync::mpsc;

use memory_model::GuestMemoryError;

use super::super::EpollHandler;
use super::EpollConfigConstructor;

#[allow(dead_code)]
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
    /// Chained GuestMemory error.
    GuestMemory(GuestMemoryError),
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
    sender: mpsc::Sender<Box<EpollHandler>>,
}

impl EpollConfigConstructor for EpollConfig {
    fn new(first_token: u64, epoll_raw_fd: RawFd, sender: mpsc::Sender<Box<EpollHandler>>) -> Self {
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

/// Placeholder for a to-be-defined vsock backend trait.
pub trait VsockBackend: Send {}

/// Placeholder implementor for a future vsock backend.
pub struct DummyBackend {}
impl DummyBackend {
    pub fn new(_cid: u64, _path: String) -> Result<Self> {
        Ok(Self {})
    }
}
impl VsockBackend for DummyBackend {}
