use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;

use pdu::bytes::NetworkBytes;
use pdu::ipv4::{Error as IPv4PacketError, IPv4Packet, PROTOCOL_TCP};
use pdu::tcp::{Error as TcpSegmentError, Flags as TcpFlags, TcpSegment};
use tcp::endpoint::Endpoint;
use tcp::RstConfig;

// TODO: This is currently IPv4 specific. Maybe change it to a more generic implementation.

// When sending or receiving segments, we may encounter events such as connections being added or
// removed, and others. The following two enums represent any such occurrences when receiving
// or writing segments.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum RecvEvent {
    EndpointDone,
    FailedNewConnection,
    NewConnectionSuccessful,
    NewConnectionDropped,
    NewConnectionReplacing,
    Nothing,
    UnexpectedSegment,
}

#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum WriteEvent {
    EndpointDone,
    Nothing,
}

#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum RecvError {
    InvalidPort,
    TcpSegment(TcpSegmentError),
}

#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum WriteNextError {
    IPv4Packet(IPv4PacketError),
    TcpSegment(TcpSegmentError),
}

// Generally speaking, a TCP/IPv4 connection is identified using the four-tuple (src_addr, src_port,
// dst_addr, dst_port). However, the IPv4 address and TCP port of the MMDS endpoint are fixed, so
// we can get away with uniquely identifying connections using just the remote address and port.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
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

pub struct TcpIPv4Handler {
    local_addr: Ipv4Addr,
    local_port: u16,
    // This map holds the currently active endpoints, identified by their connection tuple.
    connections: HashMap<ConnectionTuple, Endpoint>,
    // Maximum number of concurrent connections we are willing to handle.
    max_connections: usize,
    // RST segments awaiting to be sent.
    rst_queue: Vec<(ConnectionTuple, RstConfig)>,
    // Maximum size of the RST queue.
    max_pending_resets: usize,
}

impl TcpIPv4Handler {
    // Max_connections represents the maximum number of concurrent connections we are willing
    // to accept/handle.
    #[inline]
    pub fn new(
        local_addr: Ipv4Addr,
        local_port: u16,
        max_connections: NonZeroUsize,
        max_pending_resets: NonZeroUsize,
    ) -> Self {
        let max_connections = max_connections.get();
        let max_pending_resets = max_pending_resets.get();
        TcpIPv4Handler {
            local_addr,
            local_port,
            connections: HashMap::with_capacity(max_connections),
            max_connections,
            rst_queue: Vec::with_capacity(max_pending_resets),
            max_pending_resets,
        }
    }

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
        let mut new_connection = false;
        let mut endpoint_is_done = false;
        // This is an Option<bool>; when Some(true) we also attempt to enqueue a RST.
        let mut unexpected_segment = None;

        if let Some(endpoint) = self.connections.get_mut(&tuple) {
            endpoint.receive_segment(&segment);
            if endpoint.is_done() {
                // We only set this boolean variable here, instead of actually having the logic
                // which depends on it, because the borrow checker starts complaining.
                endpoint_is_done = true;
            }
        } else if segment.flags_after_ns() == TcpFlags::SYN {
            // Same as above.
            new_connection = true;
        } else {
            // We should send a RST for every non-RST unexpected segment we receive.
            unexpected_segment = Some(!segment.flags_after_ns().intersects(TcpFlags::RST));
        }

        if let Some(enqueue_rst) = unexpected_segment {
            if enqueue_rst {
                self.enqueue_rst(&tuple, &segment);
            }
            return Ok(RecvEvent::UnexpectedSegment);
        }

        if endpoint_is_done {
            self.remove_connection(&tuple);
            return Ok(RecvEvent::EndpointDone);
        } else if new_connection {
            let endpoint = match Endpoint::new_with_defaults(&segment) {
                Ok(endpoint) => endpoint,
                Err(_) => return Ok(RecvEvent::FailedNewConnection),
            };

            if self.connections.len() >= self.max_connections {
                if let Some(evict_tuple) = self.find_evictable_connection() {
                    // The unwrap() is safe because evict_tuple must be present as a key.
                    let rst_config = self
                        .connections
                        .get(&evict_tuple)
                        .unwrap()
                        .connection()
                        .make_rst_config();
                    self.enqueue_rst_config(&evict_tuple, rst_config);
                    self.remove_connection(&evict_tuple);
                    self.connections.insert(tuple, endpoint);
                    return Ok(RecvEvent::NewConnectionReplacing);
                } else {
                    // No room to accept the new connection. Try to enqueue a RST, and forget
                    // about it.
                    self.enqueue_rst(&tuple, &segment);
                    return Ok(RecvEvent::NewConnectionDropped);
                }
            } else {
                self.connections.insert(tuple, endpoint);
                return Ok(RecvEvent::NewConnectionSuccessful);
            }
        } else {
            return Ok(RecvEvent::Nothing);
        }
    }

    fn remove_connection(&mut self, tuple: &ConnectionTuple) {
        self.connections.remove(tuple);
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

    fn enqueue_rst_config(&mut self, tuple: &ConnectionTuple, cfg: RstConfig) {
        // We simply forgo sending any RSTs if the queue is already full.
        if self.rst_queue.len() < self.max_pending_resets {
            self.rst_queue.push((*tuple, cfg));
        }
    }

    fn enqueue_rst<T: NetworkBytes>(&mut self, tuple: &ConnectionTuple, s: &TcpSegment<T>) {
        self.enqueue_rst_config(tuple, RstConfig::new(&s));
    }

    pub fn write_next_packet(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(Option<NonZeroUsize>, WriteEvent), WriteNextError> {
        let mut len = None;
        let mut endpoint_is_done = None;
        let mut event = WriteEvent::Nothing;

        // We use self.local_addr for the dst_addr parameter also just as a placeholder value. The
        // actual destination address is written below, after deciding which endpoint is allowed
        // to send the next packet.
        let mut packet =
            IPv4Packet::write_header(buf, PROTOCOL_TCP, self.local_addr, self.local_addr)
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
            ).map_err(WriteNextError::TcpSegment)?
            .finalize(
                self.local_port,
                tuple.remote_port,
                Some((self.local_addr, tuple.remote_addr)),
            ).len();

            let packet_len = packet.with_payload_len_unchecked(segment_len, true).len();
            // The unwrap() is safe because packet_len > 0.
            return Ok((
                Some(NonZeroUsize::new(packet_len).unwrap()),
                WriteEvent::Nothing,
            ));
        }

        for (tuple, endpoint) in self.connections.iter_mut() {
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
                            Some((self.local_addr, tuple.remote_addr)),
                        ).len(),
                    None => continue,
                }
            };

            packet
                .inner_mut()
                .set_destination_address(tuple.remote_addr);

            let ip_len = packet.with_payload_len_unchecked(segment_len, true).len();

            // The unwrap is safe because ip_len > 0.
            len = Some(NonZeroUsize::new(ip_len).unwrap());

            if endpoint.is_done() {
                endpoint_is_done = Some(*tuple)
            }

            break;
        }

        if let Some(tuple) = endpoint_is_done {
            self.remove_connection(&tuple);
            event = WriteEvent::EndpointDone;
        }

        Ok((len, event))
    }

    #[inline]
    pub fn has_active_connections(&self) -> bool {
        !self.connections.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use pdu::bytes::NetworkBytesMut;

    use super::*;

    fn inner_tcp_mut<'a, 'b, T: NetworkBytesMut>(
        p: &'a mut IPv4Packet<'b, T>,
    ) -> TcpSegment<'a, &'a mut [u8]> {
        TcpSegment::from_bytes(p.payload_mut(), None).unwrap()
    }

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
    // When successful, returns how many packets were written.
    fn drain_packets(h: &mut TcpIPv4Handler) -> Result<usize, WriteNextError> {
        let mut buf = [0u8; 2000];
        let mut count: usize = 0;
        loop {
            let (o, _) = write_next(h, buf.as_mut())?;
            if o.is_some() {
                count += 1;
            } else {
                break;
            }
        }
        Ok(count)
    }

    #[test]
    fn test_handler() {
        let mut buf = [0u8; 100];
        let mut buf2 = [0u8; 2000];

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

        // We set the proper value of dst_addr from the start, because the TcpHandler expects this
        // check to be made before receiving the packet.
        let mut p =
            IPv4Packet::write_header(buf.as_mut(), PROTOCOL_TCP, remote_addr, local_addr).unwrap();

        let s_len = {
            // We're going to use this simple segment to test stuff.
            let s = TcpSegment::write_segment::<[u8]>(
                p.inner_mut().payload_mut(),
                remote_port,
                // We use the wrong port here initially, to trigger an error.
                local_port + 1,
                123,
                456,
                TcpFlags::empty(),
                10000,
                None,
                100,
                None,
                None,
            ).unwrap();
            s.len()
        };

        // The handler should have nothing to send at this point.
        assert_eq!(drain_packets(&mut h), Ok(0));

        let mut p = p.with_payload_len_unchecked(s_len, false);
        assert_eq!(h.receive_packet(&p).unwrap_err(), RecvError::InvalidPort);

        // Let's fix the port. However, the segment is not a valid SYN, so we should get an
        // UnexpectedSegment status, and the handler should write a RST.
        assert_eq!(h.rst_queue.len(), 0);
        inner_tcp_mut(&mut p).set_destination_port(local_port);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::UnexpectedSegment));
        assert_eq!(h.rst_queue.len(), 1);
        {
            let s = next_written_segment(&mut h, buf2.as_mut(), WriteEvent::Nothing);
            assert!(s.flags_after_ns().intersects(TcpFlags::RST));
            assert_eq!(s.destination_port(), remote_port);
        }

        assert_eq!(h.rst_queue.len(), 0);

        // Let's check we can only enqueue max_pending_resets resets.
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::UnexpectedSegment));
        assert_eq!(h.rst_queue.len(), 1);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::UnexpectedSegment));
        assert_eq!(h.rst_queue.len(), 2);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::UnexpectedSegment));
        assert_eq!(h.rst_queue.len(), 2);

        // "Send" the resets.
        assert_eq!(drain_packets(&mut h), Ok(2));

        // Ok now let's send a valid SYN.
        assert_eq!(h.connections.len(), 0);
        inner_tcp_mut(&mut p).set_flags_after_ns(TcpFlags::SYN);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::NewConnectionSuccessful));
        assert_eq!(h.connections.len(), 1);
        // There will be a SYNACK in response.
        assert_eq!(drain_packets(&mut h), Ok(1));

        // Using the same SYN again will route the packet to the previous connection, and not
        // create a new one.
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::Nothing));
        assert_eq!(h.connections.len(), 1);
        // SYNACK retransmission.
        assert_eq!(drain_packets(&mut h), Ok(1));

        // Create a new connection, from a different remote_port.
        inner_tcp_mut(&mut p).set_source_port(remote_port + 1);
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::NewConnectionSuccessful));
        assert_eq!(h.connections.len(), 2);
        // SYNACK
        assert_eq!(drain_packets(&mut h), Ok(1));

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

        // Let's make one of the endpoints evictable.
        for e in h.connections.values_mut() {
            e.set_eviction_threshold(0);
            break;
        }

        // The new connection will replace the old one.
        assert_eq!(h.receive_packet(&p), Ok(RecvEvent::NewConnectionReplacing));
        assert_eq!(h.connections.len(), 2);

        // One SYNACK for the new connection, and one RST for the old one.
        assert_eq!(h.rst_queue.len(), 1);
        assert_eq!(drain_packets(&mut h), Ok(2));
        assert_eq!(h.rst_queue.len(), 0);
    }
}
