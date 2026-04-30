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
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

pub use muxer::VsockMuxer as VsockUnixBackend;
use vm_memory::io::{ReadVolatile, WriteVolatile};

use crate::devices::virtio::vsock::csm::VsockConnectionBackend;
use crate::devices::virtio::vsock::unix::seqpacket::SeqpacketConn;

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

#[derive(Debug)]
pub enum ConnBackend {
    Stream(UnixStream),
    Seqpacket(SeqpacketConn),
}

macro_rules! forward_to_inner {
    ($self:ident, $method:ident $(, $args:expr )* ) => {
        match $self {
            ConnBackend::Stream(inner) => inner.$method($($args),*),
            ConnBackend::Seqpacket(inner) => inner.$method($($args),*),
        }
    };
}

impl Read for ConnBackend {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        forward_to_inner!(self, read, buf)
    }
}

impl AsRawFd for ConnBackend {
    fn as_raw_fd(&self) -> i32 {
        forward_to_inner!(self, as_raw_fd)
    }
}

impl ReadVolatile for ConnBackend {
    fn read_volatile<B: vm_memory::bitmap::BitmapSlice>(
        &mut self,
        buf: &mut vm_memory::VolatileSlice<B>,
    ) -> Result<usize, vm_memory::VolatileMemoryError> {
        forward_to_inner!(self, read_volatile, buf)
    }
}

impl WriteVolatile for ConnBackend {
    fn write_volatile<B: vm_memory::bitmap::BitmapSlice>(
        &mut self,
        buf: &vm_memory::VolatileSlice<B>,
    ) -> Result<usize, vm_memory::VolatileMemoryError> {
        forward_to_inner!(self, write_volatile, buf)
    }
}

impl Write for ConnBackend {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        forward_to_inner!(self, write, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub trait IncomingLength {
    fn incoming_len(&mut self) -> Result<usize, io::Error>;
}

impl<B: VsockConnectionBackend> IncomingLength for B {
    fn incoming_len(&mut self) -> Result<usize, io::Error> {
        let fd = self.as_raw_fd();
        // the maximum message size 256 bytes anyways
        let mut peek_buf = [0u8; 1];
        // SAFETY: `fd` is a valid file descriptor for the duration of this call, and `peek_buf`
        // is a valid single-byte buffer. MSG_PEEK | MSG_TRUNC returns the message size without
        // consuming it.
        let msg_size = unsafe {
            libc::recv(
                fd,
                peek_buf.as_mut_ptr().cast(),
                1,
                libc::MSG_PEEK | libc::MSG_TRUNC,
            )
        };
        if msg_size < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(msg_size.cast_unsigned())
        }
    }
}

#[derive(Default, Debug)]
pub struct ReadResult {
    pub bytes_read: u32,
    pub should_retrigger: bool,
}

impl ReadResult {
    pub fn new(bytes_read: u32, should_retrigger: bool) -> Self {
        ReadResult {
            bytes_read,
            should_retrigger,
        }
    }
}

impl VsockConnectionBackend for ConnBackend {}
