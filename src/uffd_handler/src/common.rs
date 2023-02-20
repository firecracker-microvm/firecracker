// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::unix::net::UnixStream;

use utils::sock_ctrl_msg::ScmSocket;

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("Invalid data received over uffd socket: {0}")]
    InvalidData(std::string::FromUtf8Error),
    #[error("No userfaultfd was received through the uffd socket.")]
    NoFd,
    #[error("Receiving data and file descriptor from uffd socket failed: {0}")]
    RecvWithFd(utils::errno::Error),
}

/// Parse the unix stream received from the Firecracker process to obtain
/// the userfaultfd used to poll for events and the message containing memory mappings.
pub fn parse_unix_stream(stream: &UnixStream) -> Result<(File, String), StreamError> {
    let mut message_buf = vec![0u8; 1024];
    let (bytes_read, file) = stream
        .recv_with_fd(&mut message_buf[..])
        .map_err(StreamError::RecvWithFd)?;
    message_buf.resize(bytes_read, 0);

    let body = String::from_utf8(message_buf).map_err(StreamError::InvalidData)?;
    let file = file.ok_or(StreamError::NoFd)?;

    Ok((file, body))
}
