// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod connection;
mod endpoint;
pub mod handler;

use pdu::bytes::NetworkBytes;
use pdu::tcp::{Flags as TcpFlags, TcpSegment};

use std::num::Wrapping;

/// The largest possible window size ever (requires the window scaling option).
pub const MAX_WINDOW_SIZE: u32 = 1_073_725_440;

/// The default MSS value, used when no MSS information is carried over the initial handshake.
pub const MSS_DEFAULT: u16 = 536;

// Describes whether a particular entity (a Connection for example) has segments to send.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum NextSegmentStatus {
    // Segments are available immediately.
    Available,
    // There's nothing to send.
    Nothing,
    // A RTO will fire at the specified point in time.
    Timeout(u64),
}

// Represents the configuration of the sequence number and ACK fields for outgoing RST segments.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum RstConfig {
    // The RST segment will carry the specified sequence number, and will not have the ACK flag set.
    Seq(u32),
    // The RST segment will carry 0 as the sequence number, will have the ACK flag set, and the ACK
    // number will be set to the specified value.
    Ack(u32),
}

impl RstConfig {
    // Creates a RstConfig in response to the specified incoming segment.
    pub fn new<T: NetworkBytes>(s: &TcpSegment<T>) -> Self {
        if s.flags_after_ns().intersects(TcpFlags::ACK) {
            // If s contains an ACK number, we use that as the sequence number of the RST.
            RstConfig::Seq(s.ack_number())
        } else {
            // Otherwise we try to guess a valid ACK number for the RST like this.
            RstConfig::Ack(s.sequence_number().wrapping_add(s.payload_len() as u32))
        }
    }

    // Returns the sequence number, ACK number, and TCP flags (not counting NS) that must be set
    // on the outgoing RST segment.
    pub fn seq_ack_tcp_flags(&self) -> (u32, u32, TcpFlags) {
        match *self {
            RstConfig::Seq(seq) => (seq, 0, TcpFlags::RST),
            RstConfig::Ack(ack) => (0, ack, TcpFlags::RST | TcpFlags::ACK),
        }
    }
}

// Please note this is not a connex binary relation; in other words, given two sequence numbers a
// and b, it's sometimes possible that seq_at_or_after(a, b) || seq_at_or_after(b, a) == false. This
// is why we can't define seq_after(a, b) as simply !seq_at_or_after(b, a).
#[inline]
pub fn seq_at_or_after(a: Wrapping<u32>, b: Wrapping<u32>) -> bool {
    (a - b).0 < MAX_WINDOW_SIZE
}

#[inline]
pub fn seq_after(a: Wrapping<u32>, b: Wrapping<u32>) -> bool {
    a != b && (a - b).0 < MAX_WINDOW_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rst_config() {
        let mut buf = [0u8; 100];

        let seq = 1234;
        let ack = 5678;

        let mut s = TcpSegment::write_segment::<[u8]>(
            buf.as_mut(),
            0,
            0,
            seq,
            ack,
            TcpFlags::empty(),
            0,
            None,
            100,
            None,
            None,
        ).unwrap();

        // The ACK flag isn't set, and the payload length is 0.
        let cfg = RstConfig::new(&s);
        assert_eq!(cfg, RstConfig::Ack(seq));
        assert_eq!(
            cfg.seq_ack_tcp_flags(),
            (0, seq, TcpFlags::RST | TcpFlags::ACK)
        );

        // Let's set the ACK flag.
        s.set_flags_after_ns(TcpFlags::ACK);
        let cfg = RstConfig::new(&s);
        assert_eq!(cfg, RstConfig::Seq(ack));
        assert_eq!(cfg.seq_ack_tcp_flags(), (ack, 0, TcpFlags::RST));
    }

    #[test]
    fn test_seq_at_or_after() {
        let a = Wrapping(123);
        let b = a + Wrapping(100);
        let c = a + Wrapping(MAX_WINDOW_SIZE);

        assert!(seq_at_or_after(a, a));
        assert!(!seq_after(a, a));
        assert!(seq_at_or_after(b, a));
        assert!(seq_after(b, a));
        assert!(!seq_at_or_after(a, b));
        assert!(!seq_after(a, b));
        assert!(!seq_at_or_after(c, a));
        assert!(!seq_after(c, a));
        assert!(seq_at_or_after(c, b));
        assert!(seq_after(c, b));
    }
}
