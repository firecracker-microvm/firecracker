// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A module for interpreting byte slices as protocol data units (PDUs).
//!
//! A PDU represents data transmitted as a single unit during communication using a specific
//! protocol. Ethernet frames, IP packets, and TCP segments are all examples of protocol data
//! units.

use std::fmt::Debug;
use std::net::Ipv4Addr;

use crate::dumbo::pdu::bytes::NetworkBytes;
use crate::dumbo::pdu::ipv4::{PROTOCOL_TCP, PROTOCOL_UDP};

pub mod arp;
pub mod bytes;
pub mod ethernet;
pub mod ipv4;
pub mod tcp;

/// This is the baseline definition of the `Incomplete` struct, which wraps a PDU that does is
/// still missing some values or content.
///
/// It's mostly important when writing PDUs, because fields like checksum
/// can only be computed after the payload becomes known. Also, the length of the underlying slice
/// should be equal to the actual size for a complete PDU. To that end, whenever a variable-length
/// payload is involved, the slice is shrunk to an exact fit. The particular ways of completing an
/// `Incomplete<T>` are implemented for each specific PDU.
#[derive(Debug)]
pub struct Incomplete<T> {
    inner: T,
}

impl<T: Debug> Incomplete<T> {
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
#[derive(Debug, Copy, Clone, PartialEq)]
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
/// * `protocol` - **must** be either `PROTOCOL_TCP` or `PROTOCOL_UDP` defined in `ipv4` module
///
/// More details about TCP checksum computation can be found [here].
///
/// [here]: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
#[inline]
fn compute_checksum<T: NetworkBytes + Debug>(
    bytes: &T,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    protocol: ChecksumProto,
) -> u16 {
    let mut sum = 0usize;

    let a = u32::from(src_addr) as usize;
    sum += a & 0xffff;
    sum += a >> 16;

    let b = u32::from(dst_addr) as usize;
    sum += b & 0xffff;
    sum += b >> 16;

    let len = bytes.len();
    sum += protocol as usize;
    sum += len;

    let (words, rest) = bytes.as_chunks::<2>();
    for word in words {
        sum += usize::from(u16::from_be_bytes(*word));
    }
    if let [last] = rest {
        sum += usize::from(*last) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Safe to unwrap due to the while loop above
    let mut csum = !u16::try_from(sum).unwrap();
    // If a UDP packet checksum is 0, an all ones value is transmitted
    if protocol == ChecksumProto::Udp && csum == 0x0 {
        csum = !csum;
    }

    csum
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // Long enough for a TCP header of any size (20 to 60 bytes) followed by some payload, and for
    // segments of even and of odd length. The time the solver needs grows steeply with this bound.
    const MAX_LEN: usize = 64;

    /// Adds to `sum` the 16-bit words RFC 1071 divides `bytes` into: adjacent bytes pair up with
    /// the most significant one first, and an odd last byte is paired with a zero.
    fn add_words(mut sum: u64, bytes: &[u8]) -> u64 {
        let mut i = 0;
        while i < bytes.len() {
            let high = u64::from(bytes[i]);
            let low = if i + 1 < bytes.len() {
                u64::from(bytes[i + 1])
            } else {
                0
            };
            sum += high << 8 | low;
            i += 2;
        }
        sum
    }

    /// The checksum as RFC 9293, Sec. 3.1, and RFC 768 define it: the ones' complement of the
    /// ones' complement sum of the 16-bit words in the pseudo-header and in the segment.
    fn checksum_spec(
        bytes: &[u8],
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
        protocol: ChecksumProto,
    ) -> u16 {
        let [s0, s1, s2, s3] = src_addr.octets();
        let [d0, d1, d2, d3] = dst_addr.octets();
        let [l0, l1] = u16::try_from(bytes.len()).unwrap().to_be_bytes();
        let pseudo_header = [s0, s1, s2, s3, d0, d1, d2, d3, 0, protocol as u8, l0, l1];

        let mut sum = add_words(add_words(0, &pseudo_header), bytes);
        // A ones' complement addition brings the carry out of the top bit back in at the bottom.
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let checksum = !u16::try_from(sum).unwrap();

        // In UDP a checksum field of zero means that there is no checksum, so a computed zero is
        // sent as all ones, which is the same number in ones' complement arithmetic.
        if protocol == ChecksumProto::Udp && checksum == 0 {
            0xffff
        } else {
            checksum
        }
    }

    /// For any addresses, either protocol and any segment of up to `MAX_LEN` bytes,
    /// `compute_checksum` does not panic or overflow, and returns the checksum the RFCs define.
    #[kani::proof]
    // Enough to run the loops over the 32 words of the longest segment to their end.
    #[kani::unwind(34)]
    fn verify_compute_checksum() {
        let buffer: [u8; MAX_LEN] = kani::Arbitrary::any_array::<MAX_LEN>();
        let len: usize = kani::any();
        kani::assume(len <= MAX_LEN);
        let bytes = &buffer[..len];
        let src_addr = Ipv4Addr::from(kani::any::<u32>());
        let dst_addr = Ipv4Addr::from(kani::any::<u32>());
        let protocol = if kani::any() {
            ChecksumProto::Tcp
        } else {
            ChecksumProto::Udp
        };

        let checksum = compute_checksum(&bytes, src_addr, dst_addr, protocol);

        assert_eq!(checksum, checksum_spec(bytes, src_addr, dst_addr, protocol));
    }
}
