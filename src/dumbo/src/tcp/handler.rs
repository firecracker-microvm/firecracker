// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exposes simple TCP over IPv4 listener functionality via the [`TcpIPv4Handler`] structure.
//!
//! [`TcpIPv4Handler`]: struct.TcpIPv4Handler.html

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;

use pdu::bytes::NetworkBytes;
use pdu::ipv4::{Error as IPv4PacketError, IPv4Packet, PROTOCOL_TCP};
use pdu::tcp::{Error as TcpSegmentError, Flags as TcpFlags, TcpSegment};
use tcp::endpoint::Endpoint;
use tcp::{NextSegmentStatus, RstConfig};

// TODO: This is currently IPv4 specific. Maybe change it to a more generic implementation.

/// Describes events which may occur when the handler receives packets.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum RecvEvent {
    /// The local endpoint is done communicating, and has been removed.
    EndpointDone,
    /// An error occurred while trying to create a new `Endpoint` object, based on an incoming
    /// `SYN` segment.
    FailedNewConnection,
    /// A new local `Endpoint` has been successfully created.
    NewConnectionSuccessful,
    /// Failed to add a local `Endpoint` because the handler is already at the maximum number of
    /// concurrent connections, and there are no evictable Endpoints.
    NewConnectionDropped,
    /// A new local `Endpoint` has been successfully created, but the handler had to make room by
    /// evicting an older `Endpoint`.
    NewConnectionReplacing,
    /// Nothing interesting happened regarding the state of the handler.
    Nothing,
    /// The handler received a non-`SYN` segment which does not belong to any existing
    /// connection.
    UnexpectedSegment,
}

/// Describes events which may occur when the handler writes packets.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum WriteEvent {
    /// The local `Endpoint` transitioned to being done after this segment was written.
    EndpointDone,
    /// Nothing interesting happened.
    Nothing,
}

/// Describes errors which may be encountered by the [`receive_packet`] method from
/// [`TcpIPv4Handler`].
///
/// [`receive_packet`]: struct.TcpIPv4Handler.html#method.receive_packet
/// [`TcpIPv4Handler`]: struct.TcpIPv4Handler.html
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum RecvError {
    /// The inner segment has an invalid destination port.
    InvalidPort,
    /// The handler encountered an error while parsing the inner TCP segment.
    TcpSegment(TcpSegmentError),
}

/// Describes errors which may be encountered by the [`write_next_packet`] method from
/// [`TcpIPv4Handler`].
///
/// [`write_next_packet`]: struct.TcpIPv4Handler.html#method.write_next_packet
/// [`TcpIPv4Handler`]: struct.TcpIPv4Handler.html
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum WriteNextError {
    /// There was an error while writing the contents of the IPv4 packet.
    IPv4Packet(IPv4PacketError),
    /// There was an error while writing the contents of the inner TCP segment.
    TcpSegment(TcpSegmentError),
}

// Generally speaking, a TCP/IPv4 connection is identified using the four-tuple (src_addr, src_port,
// dst_addr, dst_port). However, the IPv4 address and TCP port of the MMDS endpoint are fixed, so
// we can get away with uniquely identifying connections using just the remote address and port.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[cfg_attr(test, derive(Debug))]
struct ConnectionTuple {
    remote_addr: Ipv4Addr,
    remote_port: u16,
}

impl ConnectionTuple {
    fn new(remote_addr: Ipv4Addr, remote_port: u16) -> Self {
        ConnectionTuple {
            remote_addr,
            remote_port,
        }
    }
}

/// Implements a minimalist TCP over IPv4 listener.
///
/// Forwards incoming TCP segments to the appropriate connection object, based on the associated
/// tuple, or attempts to establish new connections (when receiving `SYN` segments). Aside from
/// constructors, the handler operation is based on three methods:
///
/// * [`receive_packet`] examines an incoming IPv4 packet. It checks whether the destination
///   address is correct, the attempts examine the inner TCP segment, making sure the destination
///   port number is also correct. Then, it steers valid segments towards exiting connections,
///   creates new connections for incoming `SYN` segments, and enqueues `RST` replies in response
///   to any segments which cannot be associated with a connection (except other `RST` segments).
///   On success, also describes any internal status changes triggered by the reception of the
///   packet.
/// * [`write_next_packet`] writes the next IPv4 packet (if available) that would be sent by the
///   handler itself (right now it can only mean an enqueued `RST`), or one of the existing
///   connections. On success, also describes any internal status changes triggered as the packet
///   gets transmitted.
/// * [`next_segment_status`] describes whether the handler can send a packet immediately, or
///   after some retransmission timeout associated with a connection fires, or if there's nothing
///   to send for the moment. This is used to determine whether it's appropriate to call
///   [`write_next_packet`].
///
/// [`receive_packet`]: ../handler/struct.TcpIPv4Handler.html#method.receive_packet
/// [`write_next_packet`]: ../handler/struct.TcpIPv4Handler.html#method.write_next_packet
/// [`next_segment_status`]: ../handler/struct.TcpIPv4Handler.html#method.next_segment_status
pub struct TcpIPv4Handler {
    // Handler IPv4 address used for every connection.
    local_ipv4_addr: Ipv4Addr,
    // Handler TCP port used for every connection.
    pub(crate) local_port: u16,
    // This map holds the currently active endpoints, identified by their connection tuple.
    connections: HashMap<ConnectionTuple, Endpoint>,
    // Maximum number of concurrent connections we are willing to handle.
    pub(crate) max_connections: usize,
    // Holds connections which are able to send segments immediately.
    active_connections: HashSet<ConnectionTuple>,
    // Remembers the closest timestamp into the future when one of the connections has to deal
    // with an RTO trigger.
    next_timeout: Option<(u64, ConnectionTuple)>,
    // RST segments awaiting to be sent.
    rst_queue: Vec<(ConnectionTuple, RstConfig)>,
    // Maximum size of the RST queue.
    pub(crate) max_pending_resets: usize,
}

// Only used locally, in the receive_packet method, to differentiate between different outcomes
// associated with processing incoming packets.
enum RecvSegmentOutcome {
    EndpointDone,
    EndpointRunning(NextSegmentStatus),
    NewConnection,
    UnexpectedSegment(bool),
}

impl TcpIPv4Handler {
    /// Creates a new `TcpIPv4Handler`.
    ///
    /// The handler acts as if bound to `local_addr`:`local_port`, and will accept at most
    /// `max_connections` concurrent connections. `RST` segments generated by unexpected incoming
    /// segments are placed in a queue which is at most `max_pending_resets` long.
    #[inline]
    pub fn new(
        local_ipv4_addr: Ipv4Addr,
        local_port: u16,
        max_connections: NonZeroUsize,
        max_pending_resets: NonZeroUsize,
    ) -> Self {
        let max_connections = max_connections.get();
        let max_pending_resets = max_pending_resets.get();
        TcpIPv4Handler {
            local_ipv4_addr,
            local_port,
            connections: HashMap::with_capacity(max_connections),
            max_connections,
            active_connections: HashSet::with_capacity(max_connections),
            next_timeout: None,
            rst_queue: Vec::with_capacity(max_pending_resets),
            max_pending_resets,
        }
    }

    /// Setter for the local IPv4 address of this TCP handler.
    pub fn set_local_ipv4_addr(&mut self, ipv4_addr: Ipv4Addr) {
        self.local_ipv4_addr = ipv4_addr;
    }

    /// Contains logic for handling incoming segments.
    ///
    /// Any changes to the state if the handler are communicated through an `Ok(RecvEvent)`.
    pub fn receive_packet<T: NetworkBytes>(
        &mut self,
        packet: &IPv4Packet<T>,
    ) -> Result<RecvEvent, RecvError> {
        // TODO: We skip verifying the checksum, just in case the device model relies on offloading
        // checksum computation from the guest to some other entity. Clear this up at some point!
        // (Issue #520)
        let segment =
            TcpSegment::from_bytes(packet.payload(), None).map_err(RecvError::TcpSegment)?;

        if segment.destination_port() != self.local_port {
            return Err(RecvError::InvalidPort);
        }

        let tuple = ConnectionTuple::new(packet.source_address(), segment.source_port());

        let outcome = if let Some(endpoint) = self.connections.get_mut(&tuple) {
            endpoint.receive_segment(&segment);
            if endpoint.is_done() {
                RecvSegmentOutcome::EndpointDone
            } else {
                RecvSegmentOutcome::EndpointRunning(endpoint.next_segment_status())
            }
        } else if segment.flags_after_ns() == TcpFlags::SYN {
            RecvSegmentOutcome::NewConnection
        } else {
            // We should send a RST for every non-RST unexpected segment we receive.
            RecvSegmentOutcome::UnexpectedSegment(
                !segment.flags_after_ns().intersects(TcpFlags::RST),
            )
        };

        match outcome {
            RecvSegmentOutcome::EndpointDone => {
                self.remove_connection(tuple);
                Ok(RecvEvent::EndpointDone)
            }
            RecvSegmentOutcome::EndpointRunning(status) => {
                if !self.check_next_segment_status(tuple, status) {
                    // The connection may not have been a member of active_connection, but it's
                    // more straightforward to cover both cases this way.
                    self.active_connections.remove(&tuple);
                }
                Ok(RecvEvent::Nothing)
            }
            RecvSegmentOutcome::NewConnection => {
                let endpoint = match Endpoint::new_with_defaults(&segment) {
                    Ok(endpoint) => endpoint,
                    Err(_) => return Ok(RecvEvent::FailedNewConnection),
                };

                if self.connections.len() >= self.max_connections {
                    if let Some(evict_tuple) = self.find_evictable_connection() {
                        let rst_config = self.connections[&evict_tuple]
                            .connection()
                            .make_rst_config();
                        self.enqueue_rst_config(evict_tuple, rst_config);
                        self.remove_connection(evict_tuple);
                        self.add_connection(tuple, endpoint);
                        Ok(RecvEvent::NewConnectionReplacing)
                    } else {
                        // No room to accept the new connection. Try to enqueue a RST, and forget
                        // about it.
                        self.enqueue_rst(tuple, &segment);
                        Ok(RecvEvent::NewConnectionDropped)
                    }
                } else {
                    self.add_connection(tuple, endpoint);
                    Ok(RecvEvent::NewConnectionSuccessful)
                }
            }
            RecvSegmentOutcome::UnexpectedSegment(enqueue_rst) => {
                if enqueue_rst {
                    self.enqueue_rst(tuple, &segment);
                }
                Ok(RecvEvent::UnexpectedSegment)
            }
        }
    }

    fn check_timeout(&mut self, value: u64, tuple: ConnectionTuple) {
        match self.next_timeout {
            Some((t, _)) if t > value => self.next_timeout = Some((value, tuple)),
            None => self.next_timeout = Some((value, tuple)),
            _ => (),
        };
    }

    fn find_next_timeout(&mut self) {
        let mut next_timeout = None;
        for (tuple, endpoint) in self.connections.iter() {
            if let NextSegmentStatus::Timeout(value) = endpoint.next_segment_status() {
                if let Some((t, _)) = next_timeout {
                    if t > value {
                        next_timeout = Some((value, *tuple));
                    }
                } else {
                    next_timeout = Some((value, *tuple));
                }
            }
        }
        self.next_timeout = next_timeout;
    }

    // Returns true if the endpoint has been added to the set of active connections (it may have
    // been there already).
    fn check_next_segment_status(
        &mut self,
        tuple: ConnectionTuple,
        status: NextSegmentStatus,
    ) -> bool {
        if let Some((_, timeout_tuple)) = self.next_timeout {
            if tuple == timeout_tuple {
                self.find_next_timeout();
            }
        }
        match status {
            NextSegmentStatus::Available => {
                self.active_connections.insert(tuple);
                return true;
            }
            NextSegmentStatus::Timeout(value) => self.check_timeout(value, tuple),
            NextSegmentStatus::Nothing => (),
        };

        false
    }

    fn add_connection(&mut self, tuple: ConnectionTuple, endpoint: Endpoint) {
        self.check_next_segment_status(tuple, endpoint.next_segment_status());
        self.connections.insert(tuple, endpoint);
    }

    fn remove_connection(&mut self, tuple: ConnectionTuple) {
        // Just in case it's in there somewhere.
        self.active_connections.remove(&tuple);
        self.connections.remove(&tuple);

        if let Some((_, timeout_tuple)) = self.next_timeout {
            if timeout_tuple == tuple {
                self.find_next_timeout();
            }
        }
    }

    // TODO: I guess this should be refactored at some point to also remove the endpoint if found.
    fn find_evictable_connection(&self) -> Option<ConnectionTuple> {
        for (tuple, endpoint) in self.connections.iter() {
            if endpoint.is_evictable() {
                return Some(*tuple);
            }
        }
        None
    }

    fn enqueue_rst_config(&mut self, tuple: ConnectionTuple, cfg: RstConfig) {
        // We simply forgo sending any RSTs if the queue is already full.
        if self.rst_queue.len() < self.max_pending_resets {
            self.rst_queue.push((tuple, cfg));
        }
    }

    fn enqueue_rst<T: NetworkBytes>(&mut self, tuple: ConnectionTuple, s: &TcpSegment<T>) {
        self.enqueue_rst_config(tuple, RstConfig::new(&s));
    }

    /// Attempts to write one packet, from either the `RST` queue or one of the existing endpoints,
    /// to `buf`.
    ///
    /// On success, the function returns a pair containing an `Option<NonZeroUsize>` and a
    /// `WriteEvent`. The options represents how many bytes have been written to `buf`, or
    /// that no packet can be send presently (when equal to `None`). The `WriteEvent` describes
    /// whether any noteworthy state changes are associated with the write.
    pub fn write_next_packet(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(Option<NonZeroUsize>, WriteEvent), WriteNextError> {
        let mut len = None;
        let mut writer_status = None;
        let mut event = WriteEvent::Nothing;

        // Write an incomplete Ipv4 packet and complete it afterwards with missing information.
        let mut packet =
            IPv4Packet::write_header(buf, PROTOCOL_TCP, Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
                .map_err(WriteNextError::IPv4Packet)?;

        // We set mss_used to 0, because we don't add any IP options.
        // TODO: Maybe get this nicely from packet at some point.
        let mss_reserved = 0;

        // We prioritize sending RSTs for now. The 10000 value for window size is just an arbitrary
        // number, and using mss_remaining = 0 is perfectly fine in this case, because we don't add
        // any TCP options, or a payload.
        if let Some((tuple, rst_cfg)) = self.rst_queue.pop() {
            let (seq, ack, flags_after_ns) = rst_cfg.seq_ack_tcp_flags();
            let segment_len = TcpSegment::write_incomplete_segment::<[u8]>(
                packet.inner_mut().payload_mut(),
                seq,
                ack,
                flags_after_ns,
                10000,
                None,
                0,
                None,
            )
            .map_err(WriteNextError::TcpSegment)?
            .finalize(
                self.local_port,
                tuple.remote_port,
                Some((self.local_ipv4_addr, tuple.remote_addr)),
            )
            .len();

            packet
                .inner_mut()
                .set_source_address(self.local_ipv4_addr)
                .set_destination_address(tuple.remote_addr);

            let packet_len = packet.with_payload_len_unchecked(segment_len, true).len();
            // The unwrap() is safe because packet_len > 0.
            return Ok((
                Some(NonZeroUsize::new(packet_len).unwrap()),
                WriteEvent::Nothing,
            ));
        }

        for tuple in self
            .active_connections
            .iter()
            .chain(self.next_timeout.as_ref().map(|(_, x)| x))
        {
            // Tuples in self.active_connection or self.next_timeout should also appear as keys
            // in self.connections.
            let endpoint = self.connections.get_mut(tuple).unwrap();
            // We need this block to clearly delimit the lifetime of the mutable borrow started by
            // the following packet.inner_mut().
            let segment_len = {
                let maybe_segment =
                    endpoint.write_next_segment(packet.inner_mut().payload_mut(), mss_reserved);

                match maybe_segment {
                    Some(segment) => segment
                        .finalize(
                            self.local_port,
                            tuple.remote_port,
                            Some((self.local_ipv4_addr, tuple.remote_addr)),
                        )
                        .len(),
                    None => continue,
                }
            };

            packet
                .inner_mut()
                .set_source_address(self.local_ipv4_addr)
                .set_destination_address(tuple.remote_addr);

            let ip_len = packet.with_payload_len_unchecked(segment_len, true).len();

            // The unwrap is safe because ip_len > 0.
            len = Some(NonZeroUsize::new(ip_len).unwrap());
            writer_status = Some((*tuple, endpoint.is_done()));

            break;
        }

        if let Some((tuple, is_done)) = writer_status {
            if is_done {
                self.remove_connection(tuple);
                event = WriteEvent::EndpointDone;
            } else {
                // The unwrap is safe because tuple is present as a key in self.connections if we
                // got here.
                let status = self.connections[&tuple].next_segment_status();
                if !self.check_next_segment_status(tuple, status) {
                    self.active_connections.remove(&tuple);
                }
            }
        }

        Ok((len, event))
    }

    /// Describes the status of the next segment to be sent by the handler.
    #[inline]
    pub fn next_segment_status(&self) -> NextSegmentStatus {
        if !self.active_connections.is_empty() || !self.rst_queue.is_empty() {
            return NextSegmentStatus::Available;
        }

        if let Some((value, _)) = self.next_timeout {
            return NextSegmentStatus::Timeout(value);
        }

        NextSegmentStatus::Nothing
    }
}

#[cfg(test)]
mod tests {
    use pdu::bytes::NetworkBytesMut;

    use super::*;

    impl TcpIPv4Handler {
        pub fn local_ipv4_addr(&self) -> Ipv4Addr {
            self.local_ipv4_addr
        }
    }

    fn inner_tcp_mut<'a, 'b, T: NetworkBytesMut>(
        p: &'a mut IPv4Packet<'b, T>,
    ) -> TcpSegment<'a, &'a mut [u8]> {
        TcpSegment::from_bytes(p.payload_mut(), None).unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn write_next<'a>(
        h: &mut TcpIPv4Handler,
        buf: &'a mut [u8],
    ) -> Result<(Option<IPv4Packet<'a, &'a mut [u8]>>, WriteEvent), WriteNextError> {
        h.write_next_packet(buf).map(|(o, e)| {
            (
                o.map(move |len| {
                    let len = len.get();
                    IPv4Packet::from_bytes(buf.split_at_mut(len).0, true).unwrap()
                }),
                e,
            )
        })
    }

    fn next_written_segment<'a>(
        h: &mut TcpIPv4Handler,
        buf: &'a mut [u8],
        expected_event: WriteEvent,
    ) -> TcpSegment<'a, &'a mut [u8]> {
        let (segment_start, segment_end) = {
            let (o, e) = write_next(h, buf).unwrap();
            assert_eq!(e, expected_event);
            let p = o.unwrap();
            (p.header_len(), p.len())
        };

        TcpSegment::from_bytes(&mut buf[segment_start..segment_end], None).unwrap()
    }

    // Calls write_next_packet until either an error occurs, or there's nothing left to send.
    // When successful, returns how many packets were written. The remote_addr argument is used
    // to check the packets are sent to the appropriate destination.
    fn drain_packets(
        h: &mut TcpIPv4Handler,
        src_addr: Ipv4Addr,
        remote_addr: Ipv4Addr,
    ) -> Result<usize, WriteNextError> {
        let mut buf = [0u8; 2000];
        let mut count: usize = 0;
        loop {
            let (o, _) = write_next(h, buf.as_mut())?;
            if let Some(packet) = o {
                count += 1;
                assert_eq!(packet.source_address(), src_addr);
                assert_eq!(packet.destination_address(), remote_addr);
            } else {
                break;
            }
        }
        Ok(count)
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_handler() {
        let mut buf = [0u8; 100];
        let mut buf2 = [0u8; 2000];

        let wrong_local_addr = Ipv4Addr::new(123, 123, 123, 123);
        let local_addr = Ipv4Addr::new(169, 254, 169, 254);
        let local_port = 80;
        let remote_addr = Ipv4Addr::new(10, 0, 0, 1);
        let remote_port = 1012;
        let max_connections = 2;
        let max_pending_resets = 2;

        let mut h = TcpIPv4Handler::new(
            local_addr,
            local_port,
            NonZeroUsize::new(max_connections).unwrap(),
            NonZeroUsize::new(max_pending_resets).unwrap(),
        );

        // We start with a wrong destination address and destination port to check those error
        // conditions first.
        let mut p =
            IPv4Packet::write_header(buf.as_mut(), PROTOCOL_TCP, remote_addr, wrong_local_addr)
                .unwrap();

        let seq_number = 123;

        let s_len = {
            // We're going to use this simple segment to test stuff.
            let s = TcpSegment::write_segment::<[u8]>(
                p.inner_mut().payload_mut(),
                remote_port,
                // We use the wrong port here initially, to trigger an error.
                local_port + 1,
                seq_number,
                456,
                TcpFlags::empty(),
                10000,
                None,
                100,
                None,
                None,
            )
            .unwrap();
            s.len()
        };

        // The handler should have nothing to send at this point.
        assert_eq!(h.next_segment_status(), NextSegmentStatus::Nothing);
        assert_eq!(drain_packets(&mut h, local_addr, remote_addr), Ok(0));

        let mut p = p.with_payload_len_unchecked(s_len, false);

        p.set_destination_address(local_addr);
        assert_eq!(h.receive_packet(&p).unwrap_err(), RecvError::InvalidPort);

        // Let's fix the port. However, the segment is not a valid SYN, so we should get an
        // UnexpectedSegment status, and the handler should write a RST.
        assert_eq!(h.rst_queue.len(), 0);
        inner_tcp_mut(&mut p).set_destination_port(local_port);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::UnexpectedSegment));
        assert_eq!(h.rst_queue.len(), 1);
        assert_eq!(h.next_segment_status(), NextSegmentStatus::Available);
        {
            let s = next_written_segment(&mut h, buf2.as_mut(), WriteEvent::Nothing);
            assert!(s.flags_after_ns().intersects(TcpFlags::RST));
            assert_eq!(s.source_port(), local_port);
            assert_eq!(s.destination_port(), remote_port);
        }

        assert_eq!(h.rst_queue.len(), 0);
        assert_eq!(h.next_segment_status(), NextSegmentStatus::Nothing);

        // Let's check we can only enqueue max_pending_resets resets.
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::UnexpectedSegment));
        assert_eq!(h.rst_queue.len(), 1);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::UnexpectedSegment));
        assert_eq!(h.rst_queue.len(), 2);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::UnexpectedSegment));
        assert_eq!(h.rst_queue.len(), 2);

        // Drain the resets.
        assert_eq!(h.next_segment_status(), NextSegmentStatus::Available);
        assert_eq!(drain_packets(&mut h, local_addr, remote_addr), Ok(2));
        assert_eq!(h.next_segment_status(), NextSegmentStatus::Nothing);

        // Ok now let's send a valid SYN.
        assert_eq!(h.connections.len(), 0);
        inner_tcp_mut(&mut p).set_flags_after_ns(TcpFlags::SYN);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::NewConnectionSuccessful));
        assert_eq!(h.connections.len(), 1);
        assert_eq!(h.active_connections.len(), 1);

        // Let's immediately send a RST to the newly initiated connection. This should
        // terminate it.
        inner_tcp_mut(&mut p)
            .set_flags_after_ns(TcpFlags::RST)
            .set_sequence_number(seq_number.wrapping_add(1));
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::EndpointDone));
        assert_eq!(h.connections.len(), 0);
        assert_eq!(h.active_connections.len(), 0);

        // Now, let's restore the previous SYN, and resend it to initiate a connection.
        inner_tcp_mut(&mut p)
            .set_flags_after_ns(TcpFlags::SYN)
            .set_sequence_number(seq_number);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::NewConnectionSuccessful));
        assert_eq!(h.connections.len(), 1);
        assert_eq!(h.active_connections.len(), 1);

        // There will be a SYNACK in response.
        assert_eq!(h.next_segment_status(), NextSegmentStatus::Available);
        assert_eq!(drain_packets(&mut h, local_addr, remote_addr), Ok(1));

        let remote_tuple = ConnectionTuple::new(remote_addr, remote_port);
        let remote_tuple2 = ConnectionTuple::new(remote_addr, remote_port + 1);

        // Also, there should be a retransmission timer associated with the previous SYNACK now.
        assert_eq!(h.active_connections.len(), 0);
        let old_timeout_value = if let Some((t, tuple)) = h.next_timeout {
            assert_eq!(tuple, remote_tuple);
            t
        } else {
            panic!("missing first expected timeout");
        };

        // Using the same SYN again will route the packet to the previous connection, and not
        // create a new one.
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::Nothing));
        assert_eq!(h.connections.len(), 1);
        // SYNACK retransmission.
        assert_eq!(drain_packets(&mut h, local_addr, remote_addr), Ok(1));

        // The timeout value should've gotten updated.
        assert_eq!(h.active_connections.len(), 0);
        if let Some((t, tuple)) = h.next_timeout {
            assert_eq!(tuple, remote_tuple);
            // The current Endpoint implementation gets timestamps using timestamp_cycles(), which
            // increases VERY fast so the following inequality is guaranteed to be true. If the
            // timestamp source gets coarser at some point, we might need an explicit wait before
            // the previous h.receive_packet() :-s
            assert!(t > old_timeout_value);
        } else {
            panic!("missing second expected timeout");
        };

        // Let's ACK the SYNACK.
        {
            let seq = h.connections[&remote_tuple].connection().first_not_sent().0;
            inner_tcp_mut(&mut p)
                .set_flags_after_ns(TcpFlags::ACK)
                .set_ack_number(seq);
            assert_eq!(h.receive_packet(&p), Ok(RecvEvent::Nothing));
        }

        // There should be no more active connections now, and also no pending timeout.
        assert_eq!(h.active_connections.len(), 0);
        assert_eq!(h.next_timeout, None);

        // Make p a SYN packet again.
        inner_tcp_mut(&mut p).set_flags_after_ns(TcpFlags::SYN);

        // Create a new connection, from a different remote_port.
        inner_tcp_mut(&mut p).set_source_port(remote_port + 1);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::NewConnectionSuccessful));
        assert_eq!(h.connections.len(), 2);
        assert_eq!(h.active_connections.len(), 1);
        // SYNACK
        assert_eq!(drain_packets(&mut h, local_addr, remote_addr), Ok(1));

        // The timeout associated with the SYNACK of the second connection should be next.
        assert_eq!(h.active_connections.len(), 0);
        if let Some((_, tuple)) = h.next_timeout {
            assert_ne!(tuple, ConnectionTuple::new(remote_addr, remote_port));
        } else {
            panic!("missing third expected timeout");
        }

        // No more room for another one.
        {
            let port = remote_port + 2;
            inner_tcp_mut(&mut p).set_source_port(port);
            assert_eq!(h.receive_packet(&p), Ok(RecvEvent::NewConnectionDropped));
            assert_eq!(h.connections.len(), 2);

            // We should get a RST.
            assert_eq!(h.rst_queue.len(), 1);
            let s = next_written_segment(&mut h, buf2.as_mut(), WriteEvent::Nothing);
            assert!(s.flags_after_ns().intersects(TcpFlags::RST));
            assert_eq!(s.destination_port(), port);
        }

        // Let's make the second endpoint evictable.
        h.connections
            .get_mut(&remote_tuple2)
            .unwrap()
            .set_eviction_threshold(0);

        // The new connection will replace the old one.
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::NewConnectionReplacing));
        assert_eq!(h.connections.len(), 2);
        assert_eq!(h.active_connections.len(), 1);

        // One SYNACK for the new connection, and one RST for the old one.
        assert_eq!(h.rst_queue.len(), 1);
        assert_eq!(drain_packets(&mut h, local_addr, remote_addr), Ok(2));
        assert_eq!(h.rst_queue.len(), 0);
        assert_eq!(h.active_connections.len(), 0);

        // Let's send another SYN to the first connection. This should make it reappear among the
        // active connections (because it will have a RST to send), and then cause it to be removed
        // altogether after sending the RST (because is_done() will be true).
        inner_tcp_mut(&mut p).set_source_port(remote_port);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::Nothing));
        assert_eq!(h.active_connections.len(), 1);
        assert_eq!(drain_packets(&mut h, local_addr, remote_addr), Ok(1));
        assert_eq!(h.connections.len(), 1);
        assert_eq!(h.active_connections.len(), 0);
    }
}
