// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]
//! Provides helper logic for parsing and writing protocol data units, and minimalist
//! implementations of a TCP listener, a TCP connection, and an HTTP/1.1 server.

#[macro_use]
extern crate bitflags;

extern crate logger;
extern crate micro_http;
extern crate serde;
extern crate utils;

mod mac;
pub mod pdu;
pub mod tcp;

pub use mac::{MacAddr, MAC_ADDR_LEN};
use std::ops::Index;

/// Represents a generalization of a borrowed `[u8]` slice.
#[allow(clippy::len_without_is_empty)]
pub trait ByteBuffer: Index<usize, Output = u8> {
    /// Returns the length of the buffer.
    fn len(&self) -> usize;

    /// Reads `buf.len()` bytes from `buf` into the inner buffer, starting at `offset`.
    ///
    /// # Panics
    ///
    /// Panics if `offset + buf.len()` < `self.len()`.
    fn read_to_slice(&self, offset: usize, buf: &mut [u8]);
}

impl ByteBuffer for [u8] {
    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn read_to_slice(&self, offset: usize, buf: &mut [u8]) {
        let buf_len = buf.len();
        buf.copy_from_slice(&self[offset..offset + buf_len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bb_len<T: ByteBuffer + ?Sized>(buf: &T) -> usize {
        buf.len()
    }

    fn bb_is_empty<T: ByteBuffer + ?Sized>(buf: &T) -> bool {
        buf.len() == 0
    }

    fn bb_read_from_1<T: ByteBuffer + ?Sized>(src: &T, dst: &mut [u8]) {
        src.read_to_slice(1, dst);
    }

    #[test]
    fn test_u8_byte_buffer() {
        let a = [1u8, 2, 3];
        let mut b = [0u8; 2];
        assert_eq!(bb_len(a.as_ref()), a.len());
        assert_eq!(bb_is_empty(a.as_ref()), false);
        bb_read_from_1(a.as_ref(), b.as_mut());
        assert_eq!(b, [2, 3]);
    }
}
