// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
/// This module implements our vsock connection state machine. The heavy lifting is done by
/// `connection::VsockConnection`, while this file only defines some constants and helper structs.
///
mod connection;
mod txbuf;

pub use connection::VsockConnection;

pub mod defs {
    /// Vsock connection TX buffer capacity.
    pub const CONN_TX_BUF_SIZE: usize = 64 * 1024;

    /// After the guest thinks it has filled our TX buffer up to this limit (in bytes), we'll send
    /// them a credit update packet, to let them know we can handle more.
    pub const CONN_CREDIT_UPDATE_THRESHOLD: usize = CONN_TX_BUF_SIZE - 4 * 4 * 1024;

    /// Connection request timeout, in millis.
    pub const CONN_REQUEST_TIMEOUT_MS: u64 = 2000;

    /// Connection graceful shutdown timeout, in millis.
    pub const CONN_SHUTDOWN_TIMEOUT_MS: u64 = 2000;
}

#[derive(Debug)]
pub enum Error {
    /// Attempted to push data to a full TX buffer.
    TxBufFull,
    /// An I/O error occurred, when attempting to flush the connection TX buffer.
    TxBufFlush(std::io::Error),
    /// An I/O error occurred, when attempting to write data to the host-side stream.
    StreamWrite(std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// A vsock connection state.
///
#[derive(Debug, PartialEq)]
pub enum ConnState {
    /// The connection has been initiated by the host end, but is yet to be confirmed by the guest.
    LocalInit,
    /// The connection has been initiated by the guest, but we are yet to confirm it, by sending
    /// a response packet (VSOCK_OP_RESPONSE).
    PeerInit,
    /// The connection handshake has been performed successfully, and data can now be exchanged.
    Established,
    /// The host (AF_UNIX) socket was closed.
    LocalClosed,
    /// A VSOCK_OP_SHUTDOWN packet was received from the guest. The tuple represents the guest R/W
    /// indication: (will_not_recv_anymore_data, will_not_send_anymore_data).
    PeerClosed(bool, bool),
    /// The connection is scheduled to be forcefully terminated as soon as possible.
    Killed,
}

/// An RX indication, used by `VsockConnection` to schedule future `recv_pkt()` responses.
/// For instance, after being notified that there is available data to be read from the host stream
/// (via `notify()`), the connection will store a `PendingRx::Rw` to be later inspected by
/// `recv_pkt()`.
///
#[derive(Clone, Copy, PartialEq)]
enum PendingRx {
    /// We need to yield a connection request packet (VSOCK_OP_REQUEST).
    Request = 0,
    /// We need to yield a connection response packet (VSOCK_OP_RESPONSE).
    Response = 1,
    /// We need to yield a forceful connection termination packet (VSOCK_OP_RST).
    Rst = 2,
    /// We need to yield a data packet (VSOCK_OP_RW), by reading from the AF_UNIX socket.
    Rw = 3,
    /// We need to yield a credit update packet (VSOCK_OP_CREDIT_UPDATE).
    CreditUpdate = 4,
}
impl PendingRx {
    /// Transform the enum value into a bitmask, that can be used for set operations.
    ///
    fn into_mask(self) -> u16 {
        1u16 << (self as u16)
    }
}

/// A set of RX indications (`PendingRx` items).
///
struct PendingRxSet {
    data: u16,
}

impl PendingRxSet {
    /// Insert an item into the set.
    ///
    fn insert(&mut self, it: PendingRx) {
        self.data |= it.into_mask();
    }

    /// Remove an item from the set and return:
    /// - true, if the item was in the set; or
    /// - false, if the item wasn't in the set.
    ///
    fn remove(&mut self, it: PendingRx) -> bool {
        let ret = self.contains(it);
        self.data &= !it.into_mask();
        ret
    }

    /// Check if an item is present in this set.
    ///
    fn contains(&self, it: PendingRx) -> bool {
        self.data & it.into_mask() != 0
    }

    /// Check if the set is empty.
    ///
    fn is_empty(&self) -> bool {
        self.data == 0
    }
}

/// Create a set containing only one item.
///
impl From<PendingRx> for PendingRxSet {
    fn from(it: PendingRx) -> Self {
        Self {
            data: it.into_mask(),
        }
    }
}
