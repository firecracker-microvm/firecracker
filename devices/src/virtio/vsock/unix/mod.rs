// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

/// This module implements the Unix Domain Sockets backend for vsock - a mediator between
/// guest-side AF_VSOCK sockets and host-side AF_UNIX sockets. The heavy lifting is performed by
/// `muxer::VsockMuxer`, a connection multiplexer that uses `super::csm::VsockConnection` for
/// handling vsock connection states.
/// Check out `muxer.rs` for a more detailed explanation of the inner workings of this backend.
///
mod muxer;
mod muxer_killq;
mod muxer_rxq;

pub use muxer::VsockMuxer as VsockUnixBackend;
use std::fmt;

mod defs {
    /// Maximum number of established connections that we can handle.
    pub const MAX_CONNECTIONS: usize = 1023;

    /// Size of the muxer RX packet queue.
    pub const MUXER_RXQ_SIZE: usize = 256;

    /// Size of the muxer connection kill queue.
    pub const MUXER_KILLQ_SIZE: usize = 128;
}
#[derive(Debug)]
pub enum Error {
    /// Error registering a new epoll-listening FD.
    EpollAdd(std::io::Error),
    /// Error creating an epoll FD.
    EpollFdCreate(std::io::Error),
    /// The host made an invalid vsock port connection request.
    InvalidPortRequest,
    /// Error accepting a new connection from the host-side Unix socket.
    UnixAccept(std::io::Error),
    /// Error binding to the host-side Unix socket.
    UnixBind(std::io::Error),
    /// Error connecting to a host-side Unix socket.
    UnixConnect(std::io::Error),
    /// Error reading from host-side Unix socket.
    UnixRead(std::io::Error),
    /// Muxer connection limit reached.
    TooManyConnections,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::EpollAdd(err) => {
                write!(f, "Error registering a new epoll-listening FD: {}", err)
            }
            Error::EpollFdCreate(err) => write!(f, "Error creating an epoll FD: {}", err),
            Error::InvalidPortRequest => {
                write!(f, "The host made an invalid vsock port connection request.")
            }
            Error::UnixAccept(err) => write!(
                f,
                "Error accepting a new connection from the host-side Unix socket: {}",
                err
            ),
            Error::UnixBind(err) => {
                write!(f, "Error binding to the host-side Unix socket: {}", err)
            }
            Error::UnixConnect(err) => {
                write!(f, "Error connecting to a host-side Unix socket: {}", err)
            }
            Error::UnixRead(err) => write!(f, "Error reading from host-side Unix socket: {}", err),
            Error::TooManyConnections => write!(f, "Muxer connection limit reached."),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;
type MuxerConnection = super::csm::VsockConnection<std::os::unix::net::UnixStream>;

#[cfg(test)]
mod tests {
    use crate::virtio::vsock::unix::Error;

    #[test]
    fn test_error_messages() {
        assert_eq!(
            format!("{}", Error::EpollAdd(std::io::Error::from_raw_os_error(0))),
            format!(
                "Error registering a new epoll-listening FD: {}",
                std::io::Error::from_raw_os_error(0)
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::EpollFdCreate(std::io::Error::from_raw_os_error(0))
            ),
            format!(
                "Error creating an epoll FD: {}",
                std::io::Error::from_raw_os_error(0)
            )
        );
        assert_eq!(
            format!("{}", Error::InvalidPortRequest),
            "The host made an invalid vsock port connection request."
        );
        assert_eq!(
            format!(
                "{}",
                Error::UnixAccept(std::io::Error::from_raw_os_error(0))
            ),
            format!(
                "Error accepting a new connection from the host-side Unix socket: {}",
                std::io::Error::from_raw_os_error(0)
            )
        );
        assert_eq!(
            format!("{}", Error::UnixBind(std::io::Error::from_raw_os_error(0))),
            format!(
                "Error binding to the host-side Unix socket: {}",
                std::io::Error::from_raw_os_error(0)
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::UnixConnect(std::io::Error::from_raw_os_error(0))
            ),
            format!(
                "Error connecting to a host-side Unix socket: {}",
                std::io::Error::from_raw_os_error(0)
            )
        );
        assert_eq!(
            format!("{}", Error::UnixRead(std::io::Error::from_raw_os_error(0))),
            format!(
                "Error reading from host-side Unix socket: {}",
                std::io::Error::from_raw_os_error(0)
            )
        );
        assert_eq!(
            format!("{}", Error::TooManyConnections),
            "Muxer connection limit reached."
        );
    }
}
