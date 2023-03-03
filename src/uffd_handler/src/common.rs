// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::unix::net::UnixStream;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
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

/// If the userfaultfd handler process dies, Firecracker will freeze because it will wait
/// forever for its page faults to be handled. The handler sends a SIGBUS signal to the Firecracker
/// process to inform it of crashes/exits.
pub fn send_sigbus(pid: Pid) {
    match kill(pid, Signal::SIGBUS) {
        Ok(()) => println!(
            "Successfully sent SIGBUS signal to process with PID: {:?}",
            pid
        ),
        Err(e) => eprintln!(
            "Encountered error: {:?} while sending SIGBUS signal to process with PID: {:?}",
            e, pid
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::io::AsRawFd;

    use super::*;

    #[test]
    fn test_parse_unix_stream_successful() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let expected_body = "test body".to_string();
        let fd = sender.socket_fd();

        let sent = sender.send_with_fd(expected_body.as_bytes(), fd).unwrap();
        assert_eq!(sent, expected_body.len());

        // Successfully receive and parse a message body and file descriptor from sender.
        let (actual_fd, actual_body) = parse_unix_stream(&receiver).unwrap();
        assert_eq!(actual_body, expected_body);
        assert!(actual_fd.as_raw_fd() >= 0);
        assert_ne!(actual_fd.as_raw_fd(), receiver.as_raw_fd());
        // `send_with_fd()` only sends the reference to the file description, not the actual
        // descriptor number. We expect the fd number to change between processes, but the
        // kernel structure it represents will not.
        assert_ne!(actual_fd.as_raw_fd(), sender.as_raw_fd());
    }

    #[test]
    fn test_parse_unix_stream_no_msg() {
        let (_sender, receiver) = UnixStream::pair().unwrap();
        // Force receiver to not wait for message.
        receiver.set_nonblocking(true).unwrap();

        // Fail stream parsing when no message was received.
        let res = parse_unix_stream(&receiver);
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), StreamError::RecvWithFd(_)));
    }

    #[test]
    fn test_parse_unix_stream_no_fd() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let expected_body = "test body".to_string();

        // Fail stream parsing when the file descriptor is missing.
        sender.write_all(expected_body.as_bytes()).unwrap();
        let res = parse_unix_stream(&receiver);
        assert!(res.is_err());
        assert_eq!(
            StreamError::NoFd.to_string(),
            res.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_parse_unix_stream_not_utf8() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let fd = sender.socket_fd();
        let invalid_utf8 = [0xfe, 0xfe, 0xff, 0xff];

        // Fail stream parsing when the message is not UTF-8.
        sender.send_with_fd(invalid_utf8.as_slice(), fd).unwrap();
        let res = parse_unix_stream(&receiver);
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), StreamError::InvalidData(_)));
    }
}
