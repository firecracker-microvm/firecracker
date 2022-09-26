// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A module for interpreting byte slices as protocol data units (PDUs).
//!
//! A PDU represents data transmitted as a single unit during communication using a specific
//! protocol. Ethernet frames, IP packets, and TCP segments are all examples of protocol data
//! units.

use std::net::Ipv4Addr;

use crate::pdu::bytes::NetworkBytes;
use crate::pdu::ipv4::{PROTOCOL_TCP, PROTOCOL_UDP};

pub mod arp;
pub mod bytes;
pub mod ethernet;
pub mod ipv4;
pub mod tcp;
pub mod udp;

/// This is the baseline definition of the `Incomplete` struct, which wraps a PDU that does is
/// still missing some values or content.
///
/// It's mostly important when writing PDUs, because fields like checksum
/// can only be computed after the payload becomes known. Also, the length of the underlying slice
/// should be equal to the actual size for a complete PDU. To that end, whenever a variable-length
/// payload is involved, the slice is shrunk to an exact fit. The particular ways of completing an
/// `Incomplete<T>` are implemented for each specific PDU.
pub struct Incomplete<T> {
    inner: T,
}

impl<T> Incomplete<T> {
    #[inline]
    fn new(inner: T) -> Self {
        Incomplete { inner }
    }

    /// Returns a reference to the wrapped object.
    #[inline]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped object.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq)]
enum ChecksumProto {
    Tcp = PROTOCOL_TCP,
    Udp = PROTOCOL_UDP,
}

/// Computes the checksum of a TCP/UDP packet. Since both protocols use
/// the same algorithm to compute the checksum.
///
/// # Arguments
/// * `bytes` - Raw bytes of a TCP packet or a UDP datagram
/// * `src_addr` - IPv4 source address
/// * `dst_addr` - IPv4 destination address
/// * `protocol` - **must** be either `PROTOCOL_TCP` or `PROTOCOL_UDP` defined in
/// `ipv4` module
///
/// More details about TCP checksum computation can be found [here].
///
/// [here]: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
#[inline]
fn compute_checksum<T: NetworkBytes>(
    bytes: &T,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    protocol: ChecksumProto,
) -> u16 {
    // TODO: Is u32 enough to prevent overflow for the code in this function? I think so, but it
    // would be nice to double-check.
    let mut sum = 0u32;

    let a = u32::from(src_addr);
    sum += a & 0xffff;
    sum += a >> 16;

    let b = u32::from(dst_addr);
    sum += b & 0xffff;
    sum += b >> 16;

    let len = bytes.len();
    sum += protocol as u32;
    sum += len as u32;

    for i in 0..len / 2 {
        sum += u32::from(bytes.ntohs_unchecked(i * 2));
    }

    if len % 2 != 0 {
        sum += u32::from(bytes[len - 1]) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let mut csum = !(sum as u16);
    // If a UDP packet checksum is 0, an all ones value is transmitted
    if protocol == ChecksumProto::Udp && csum == 0x0 {
        csum = !csum;
    }

    csum
}
