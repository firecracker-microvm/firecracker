// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Length-prefixed bitcode message broker over a [`UnixStream`].
//!
//! Provides framed, typed messaging between Firecracker and the UFFD handler
//! using bitcode encoding with a 4-byte little-endian length prefix.

use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

use vmm_sys_util::epoll::EventSet;

use crate::persist::{FaultReply, FaultRequest};

/// Framed message broker for UFFD fault request/reply communication.
///
/// Messages are length-prefixed: a 4-byte little-endian size header followed
/// by the bitcode-encoded payload. The broker buffers partial reads and
/// delivers complete [`FaultReply`] messages via its [`Iterator`] impl.
pub struct UffdMessageBroker {
    stream: UnixStream,
    read_buffer: [u8; 4096],
    write_buffer: [u8; 4096],
    current_pos: usize,
    encode_buffer: bitcode::Buffer,
}

impl std::fmt::Debug for UffdMessageBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UffdMessageBroker")
            .field("stream", &self.stream)
            .field("current_pos", &self.current_pos)
            .finish_non_exhaustive()
    }
}

impl UffdMessageBroker {
    /// Create a new broker wrapping the given stream.
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            read_buffer: [0; 4096],
            write_buffer: [0; 4096],
            current_pos: 0,
            encode_buffer: bitcode::Buffer::new(),
        }
    }

    /// Returns a reference to the underlying [`UnixStream`].
    pub fn stream(&self) -> &UnixStream {
        &self.stream
    }

    /// Encode and send a fault request over the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the write to the underlying stream fails.
    pub fn send_fault_request(&mut self, fault_request: FaultRequest) -> io::Result<()> {
        let encoded = self.encode_buffer.encode(&fault_request);
        let len = encoded.len();
        let size = u32::try_from(len).expect("encoded message exceeds u32::MAX");
        self.write_buffer[..4].copy_from_slice(&size.to_le_bytes());
        self.write_buffer[4..4 + len].copy_from_slice(encoded);

        self.stream.write_all(&self.write_buffer[..4 + len])
    }

    /// Check if the given event source and set match this broker's stream.
    pub fn active_event(&self, source: i32, event_set: EventSet) -> bool {
        self.stream.as_raw_fd() == source && event_set == EventSet::IN
    }

    /// Parse the expected payload size from the 4-byte length prefix.
    ///
    /// Returns `None` if fewer than 4 bytes have been buffered.
    // The `try_into().unwrap()` is safe: the `current_pos < 4` guard above
    // ensures the slice is exactly 4 bytes, so conversion to `[u8; 4]` cannot fail.
    fn expected_size(&self) -> Option<u32> {
        if self.current_pos < 4 {
            return None;
        }

        Some(u32::from_le_bytes(
            self.read_buffer[..4].try_into().unwrap(),
        ))
    }

    fn can_decode(&self) -> bool {
        let Some(expected_size) = self.expected_size() else {
            return false;
        };

        self.current_pos - 4 >= expected_size as usize
    }
}

impl Iterator for UffdMessageBroker {
    type Item = FaultReply;

    fn next(&mut self) -> Option<Self::Item> {
        match self.stream.read(&mut self.read_buffer[self.current_pos..]) {
            Ok(bytes_read) => self.current_pos += bytes_read,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Continue with existing buffer data
            }
            Err(e) => {
                log::error!("Failed to read from UFFD broker stream: {e}");
                return None;
            }
        }

        if !self.can_decode() {
            return None;
        }

        // Safe: `can_decode()` returned true, so `expected_size()` is `Some`.
        let size = self.expected_size().unwrap() as usize;
        let decoded = match bitcode::decode(&self.read_buffer[4..4 + size]) {
            Ok(msg) => msg,
            Err(e) => {
                log::error!("Failed to decode UFFD broker message: {e}");
                return None;
            }
        };

        self.read_buffer.copy_within(4 + size..self.current_pos, 0);
        self.current_pos -= 4 + size;

        Some(decoded)
    }
}
