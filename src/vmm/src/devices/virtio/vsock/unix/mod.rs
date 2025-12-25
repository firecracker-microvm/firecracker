// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

/// This module implements the Unix Domain Sockets backend for vsock - a mediator between
/// guest-side AF_VSOCK sockets and host-side AF_UNIX sockets. The heavy lifting is performed by
/// `muxer::VsockMuxer`, a connection multiplexer that uses `super::csm::VsockConnection` for
/// handling vsock connection states.
/// Check out `muxer.rs` for a more detailed explanation of the inner workings of this backend.
mod muxer;
mod muxer_killq;
mod muxer_rxq;
mod seqpacket;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::time::Instant;

pub use muxer::VsockMuxer as VsockUnixBackend;
use vm_memory::io::{ReadVolatile, WriteVolatile};
use vmm_sys_util::epoll::EventSet;

use crate::devices::VsockError;
use crate::devices::virtio::vsock::csm::{ConnState, VsockConnectionBackend, VsockCsmError};
use crate::devices::virtio::vsock::packet::{VsockPacketRx, VsockPacketTx};
use crate::devices::virtio::vsock::unix::seqpacket::SeqpacketConn;
use crate::devices::virtio::vsock::{VsockChannel as _, VsockEpollListener};

mod defs {
    /// Maximum number of established connections that we can handle.
    pub const MAX_CONNECTIONS: usize = 1023;

    /// Size of the muxer RX packet queue.
    pub const MUXER_RXQ_SIZE: u32 = 256;

    /// Size of the muxer connection kill queue.
    pub const MUXER_KILLQ_SIZE: u32 = 128;
}

/// Vsock backend related errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VsockUnixBackendError {
    /// Error registering a new epoll-listening FD: {0}
    EpollAdd(std::io::Error),
    /// Error creating an epoll FD: {0}
    EpollFdCreate(std::io::Error),
    /// The host made an invalid vsock port connection request.
    InvalidPortRequest,
    /// Error accepting a new connection from the host-side Unix socket: {0}
    UnixAccept(std::io::Error),
    /// Error binding to the host-side Unix socket: {0}
    UnixBind(std::io::Error),
    /// Error connecting to a host-side Unix socket: {0}
    UnixConnect(std::io::Error),
    /// Error reading from host-side Unix socket: {0}
    UnixRead(std::io::Error),
    /// Muxer connection limit reached.
    TooManyConnections,
}

type MuxerStreamConnection = super::csm::VsockConnection<UnixStream>;
type MuxerSeqpacketConnetion = super::csm::VsockConnection<SeqpacketConn>;

#[derive(Debug)]
enum MuxerConn {
    Stream(MuxerStreamConnection),
    Seqpacket(MuxerSeqpacketConnetion),
}

macro_rules! forward_to_inner {
    ($self:ident, $method:ident $(, $args:expr )* ) => {
        match $self {
            MuxerConn::Stream(inner) => inner.$method($($args),*),
            MuxerConn::Seqpacket(inner) => inner.$method($($args),*),
        }
    };
}

impl MuxerConn {
    fn has_pending_rx(&self) -> bool {
        forward_to_inner!(self, has_pending_rx)
    }

    fn as_raw_fd(&self) -> i32 {
        forward_to_inner!(self, as_raw_fd)
    }

    fn kill(&mut self) {
        forward_to_inner!(self, kill)
    }

    fn get_polled_evset(&self) -> EventSet {
        forward_to_inner!(self, get_polled_evset)
    }

    fn will_expire(&self) -> bool {
        forward_to_inner!(self, will_expire)
    }

    fn has_expired(&self) -> bool {
        forward_to_inner!(self, has_expired)
    }

    fn send_bytes_raw(&mut self, buf: &[u8]) -> Result<usize, VsockCsmError> {
        forward_to_inner!(self, send_bytes_raw, buf)
    }

    fn state(&self) -> ConnState {
        forward_to_inner!(self, state)
    }

    fn expiry(&self) -> Option<Instant> {
        forward_to_inner!(self, expiry)
    }

    fn recv_pkt(&mut self, pkt: &mut VsockPacketRx) -> Result<(), VsockError> {
        forward_to_inner!(self, recv_pkt, pkt)
    }

    fn send_pkt(&mut self, pkt: &VsockPacketTx) -> Result<(), VsockError> {
        forward_to_inner!(self, send_pkt, pkt)
    }

    fn notify(&mut self, evset: EventSet) {
        forward_to_inner!(self, notify, evset)
    }
}

#[cfg(test)]
impl MuxerConn {
    pub(crate) fn fwd_cnt(&self) -> std::num::Wrapping<u32> {
        forward_to_inner!(self, fwd_cnt)
    }

    pub(crate) fn insert_credit_update(&mut self) {
        forward_to_inner!(self, insert_credit_update)
    }
}

impl VsockConnectionBackend for UnixStream {}

impl VsockConnectionBackend for SeqpacketConn {}
