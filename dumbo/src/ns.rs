// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TODO: get rid of this when splitting dumbo into public and internal parts.
#![allow(missing_docs)]

use std::convert::From;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::result::Result;

use crate::MacAddr;
use logger::{Metric, METRICS};
use pdu::arp::{test_speculative_tpa, Error as ArpFrameError, EthIPv4ArpFrame, ETH_IPV4_FRAME_LEN};
use pdu::ethernet::{Error as EthernetFrameError, EthernetFrame, ETHERTYPE_ARP, ETHERTYPE_IPV4};
use pdu::ipv4::{test_speculative_dst_addr, Error as IPv4PacketError, IPv4Packet, PROTOCOL_TCP};
use pdu::tcp::Error as TcpSegmentError;
use pdu::Incomplete;
use tcp::handler::{self, RecvEvent, TcpIPv4Handler, WriteEvent};
use tcp::NextSegmentStatus;
use utils::time::timestamp_cycles;

const DEFAULT_MAC_ADDR: &str = "06:01:23:45:67:01";
const DEFAULT_IPV4_ADDR: [u8; 4] = [169, 254, 169, 254];
const DEFAULT_TCP_PORT: u16 = 80;
const DEFAULT_MAX_CONNECTIONS: usize = 30;
const DEFAULT_MAX_PENDING_RESETS: usize = 100;

#[cfg_attr(test, derive(Debug, PartialEq))]
enum WriteArpFrameError {
    Arp(ArpFrameError),
    Ethernet(EthernetFrameError),
}

#[cfg_attr(test, derive(Debug, PartialEq))]
enum WritePacketError {
    IPv4Packet(IPv4PacketError),
    Ethernet(EthernetFrameError),
    TcpSegment(TcpSegmentError),
}

impl From<handler::WriteNextError> for WritePacketError {
    fn from(error: handler::WriteNextError) -> Self {
        match error {
            handler::WriteNextError::IPv4Packet(inner) => WritePacketError::IPv4Packet(inner),
            handler::WriteNextError::TcpSegment(inner) => WritePacketError::TcpSegment(inner),
        }
    }
}

pub struct MmdsNetworkStack {
    // The Ethernet MAC address of the MMDS server.
    mac_addr: MacAddr,
    // Whenever we detour a frame, we update the value of the remote MAC address. We need this
    // because we don't send ARP request ourselves.
    remote_mac_addr: MacAddr,
    // The IPv4 address of the MMDS server.
    ipv4_addr: Ipv4Addr,
    // We only remember the most recently received ARP request, and store the remote IPv4 address
    // here (we keep the remote MAC address in self.remote_mac_addr), to be used when the next
    // opportunity to send a frame presents itself.
    pending_arp_reply: Option<Ipv4Addr>,
    // This handles MMDS<->guest interaction at the TCP level.
    tcp_handler: TcpIPv4Handler,
}

impl MmdsNetworkStack {
    pub fn new(
        mac_addr: MacAddr,
        ipv4_addr: Ipv4Addr,
        tcp_port: u16,
        max_connections: NonZeroUsize,
        max_pending_resets: NonZeroUsize,
    ) -> Self {
        MmdsNetworkStack {
            mac_addr,
            remote_mac_addr: mac_addr,
            ipv4_addr,
            pending_arp_reply: None,
            tcp_handler: TcpIPv4Handler::new(
                ipv4_addr,
                tcp_port,
                max_connections,
                max_pending_resets,
            ),
        }
    }

    pub fn new_with_defaults() -> Self {
        // The unwrap is safe if parse_str() is implemented properly.
        let mac_addr = MacAddr::parse_str(DEFAULT_MAC_ADDR).unwrap();
        let ipv4_addr = Ipv4Addr::from(DEFAULT_IPV4_ADDR);

        // The unwrap()s are safe because the given literals are greater than 0.
        Self::new(
            mac_addr,
            ipv4_addr,
            DEFAULT_TCP_PORT,
            NonZeroUsize::new(DEFAULT_MAX_CONNECTIONS).unwrap(),
            NonZeroUsize::new(DEFAULT_MAX_PENDING_RESETS).unwrap(),
        )
    }

    // This is the entry point into the MMDS network stack. The src slice should hold the contents
    // of an Ethernet frame (of that exact size, without the CRC).
    pub fn detour_frame(&mut self, src: &[u8]) -> bool {
        // The frame cannot possibly contain an ARP request or IPv4 packet for the MMDS.
        if !test_speculative_tpa(src, self.ipv4_addr)
            && !test_speculative_dst_addr(src, self.ipv4_addr)
        {
            return false;
        }

        if let Ok(eth) = EthernetFrame::from_bytes(src) {
            match eth.ethertype() {
                ETHERTYPE_ARP => return self.detour_arp(eth),
                ETHERTYPE_IPV4 => return self.detour_ipv4(eth),
                _ => (),
            };
        } else {
            METRICS.mmds.rx_bad_eth.inc();
        }
        false
    }

    fn detour_arp(&mut self, eth: EthernetFrame<&[u8]>) -> bool {
        if let Ok(arp) = EthIPv4ArpFrame::request_from_bytes(eth.payload()) {
            if arp.tpa() == self.ipv4_addr {
                self.remote_mac_addr = arp.sha();
                self.pending_arp_reply = Some(arp.spa());
                return true;
            }
        }
        false
    }

    fn detour_ipv4(&mut self, eth: EthernetFrame<&[u8]>) -> bool {
        // TODO: We skip verifying the checksum, just in case the device model relies on offloading
        // checksum computation from the guest driver to some other entity. Clear up this entire
        // context at some point!
        if let Ok(ip) = IPv4Packet::from_bytes(eth.payload(), false) {
            if ip.destination_address() == self.ipv4_addr {
                if ip.protocol() == PROTOCOL_TCP {
                    self.remote_mac_addr = eth.src_mac();
                    match self.tcp_handler.receive_packet(&ip) {
                        Ok(event) => {
                            METRICS.mmds.rx_count.inc();
                            match event {
                                RecvEvent::NewConnectionSuccessful => {
                                    METRICS.mmds.connections_created.inc()
                                }
                                RecvEvent::NewConnectionReplacing => {
                                    METRICS.mmds.connections_created.inc();
                                    METRICS.mmds.connections_destroyed.inc();
                                }
                                RecvEvent::EndpointDone => {
                                    METRICS.mmds.connections_destroyed.inc();
                                }
                                _ => (),
                            }
                        }
                        Err(_) => METRICS.mmds.rx_accepted_err.inc(),
                    }
                } else {
                    // A non-TCP IPv4 packet heading towards the MMDS; we consider it unusual.
                    METRICS.mmds.rx_accepted_unusual.inc();
                }
                return true;
            }
        }
        false
    }

    // Allows the MMDS network stack to write a frame to the specified buffer. Will return:
    // - None, if the MMDS network stack has no frame to send at this point. The buffer can be
    // used for something else by the device model.
    // - Some(len), if a frame of the given length has been written to the specified buffer.
    pub fn write_next_frame(&mut self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        // We try to send ARP replies first.
        if let Some(spa) = self.pending_arp_reply {
            return match self.write_arp_reply(buf, spa) {
                Ok(something) => {
                    METRICS.mmds.tx_count.inc();
                    self.pending_arp_reply = None;
                    something
                }
                Err(_) => {
                    METRICS.mmds.tx_errors.inc();
                    None
                }
            };
        } else {
            let call_write = match self.tcp_handler.next_segment_status() {
                NextSegmentStatus::Available => true,
                NextSegmentStatus::Timeout(value) => timestamp_cycles() >= value,
                NextSegmentStatus::Nothing => false,
            };

            if call_write {
                return match self.write_packet(buf) {
                    Ok(something) => {
                        METRICS.mmds.tx_count.inc();
                        something
                    }
                    Err(_) => {
                        METRICS.mmds.tx_errors.inc();
                        None
                    }
                };
            }
        }
        None
    }

    fn prepare_eth_unsized<'a>(
        &self,
        buf: &'a mut [u8],
        ethertype: u16,
    ) -> Result<Incomplete<EthernetFrame<'a, &'a mut [u8]>>, EthernetFrameError> {
        EthernetFrame::write_incomplete(buf, self.remote_mac_addr, self.mac_addr, ethertype)
    }

    fn write_arp_reply(
        &self,
        buf: &mut [u8],
        dst_ipv4: Ipv4Addr,
    ) -> Result<Option<NonZeroUsize>, WriteArpFrameError> {
        let mut eth_unsized = self
            .prepare_eth_unsized(buf, ETHERTYPE_ARP)
            .map_err(WriteArpFrameError::Ethernet)?;

        let arp_len = EthIPv4ArpFrame::write_reply(
            eth_unsized
                .inner_mut()
                .payload_mut()
                .split_at_mut(ETH_IPV4_FRAME_LEN)
                .0,
            self.mac_addr,
            self.ipv4_addr,
            self.remote_mac_addr,
            dst_ipv4,
        )
        .map_err(WriteArpFrameError::Arp)?
        .len();

        Ok(Some(
            // The unwrap() is safe because arp_len > 0.
            NonZeroUsize::new(eth_unsized.with_payload_len_unchecked(arp_len).len()).unwrap(),
        ))
    }

    fn write_packet(&mut self, buf: &mut [u8]) -> Result<Option<NonZeroUsize>, WritePacketError> {
        let mut eth_unsized = self
            .prepare_eth_unsized(buf, ETHERTYPE_IPV4)
            .map_err(WritePacketError::Ethernet)?;

        let (maybe_len, event) = self
            .tcp_handler
            .write_next_packet(eth_unsized.inner_mut().payload_mut())?;

        if let WriteEvent::EndpointDone = event {
            METRICS.mmds.connections_destroyed.inc()
        }

        if let Some(packet_len) = maybe_len {
            return Ok(Some(
                // The unwrap() is safe because packet_len > 0.
                NonZeroUsize::new(
                    eth_unsized
                        .with_payload_len_unchecked(packet_len.get())
                        .len(),
                )
                .unwrap(),
            ));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pdu::tcp::{Flags as TcpFlags, TcpSegment};
    use std::str::FromStr;

    // We use LOCALHOST here because const new() is not stable yet, so just reuse this const, since
    // all we're interested in is having some address different from the MMDS one.
    const REMOTE_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;
    const REMOTE_MAC_STR: &str = "11:11:11:22:22:22";
    const MMDS_PORT: u16 = 80;
    const REMOTE_PORT: u16 = 1235;
    const SEQ_NUMBER: u32 = 123;

    // Helper methods which only make sense for testing.
    impl MmdsNetworkStack {
        fn write_arp_request(&self, buf: &mut [u8], for_mmds: bool) -> usize {
            // We write a reply, and then modify it into a request.
            let len = self
                .write_arp_reply(buf, REMOTE_ADDR)
                .unwrap()
                .unwrap()
                .get();

            let mut eth = EthernetFrame::from_bytes_unchecked(&mut buf[..len]);
            let mut arp = EthIPv4ArpFrame::from_bytes_unchecked(eth.payload_mut());

            // Set the operation to REQUEST.
            arp.set_operation(1);
            arp.set_sha(MacAddr::parse_str(REMOTE_MAC_STR).unwrap());
            arp.set_spa(REMOTE_ADDR);

            // The tpa remains REMOTE_ADDR otherwise, and is thus invalid for the MMDS.
            if for_mmds {
                arp.set_tpa(self.ipv4_addr);
            }
            len
        }

        fn write_incoming_tcp_segment(
            &self,
            buf: &mut [u8],
            addr: Ipv4Addr,
            flags: TcpFlags,
        ) -> usize {
            let mut eth_unsized = self.prepare_eth_unsized(buf, ETHERTYPE_IPV4).unwrap();
            let packet_len = {
                let mut packet = IPv4Packet::write_header(
                    eth_unsized.inner_mut().payload_mut(),
                    PROTOCOL_TCP,
                    REMOTE_ADDR,
                    addr,
                )
                .unwrap();

                let segment_len = TcpSegment::write_incomplete_segment::<[u8]>(
                    packet.inner_mut().payload_mut(),
                    SEQ_NUMBER,
                    1234,
                    flags,
                    10000,
                    None,
                    0,
                    None,
                )
                .unwrap()
                .finalize(REMOTE_PORT, MMDS_PORT, Some((REMOTE_ADDR, addr)))
                .len();

                packet.with_payload_len_unchecked(segment_len, true).len()
            };

            eth_unsized.with_payload_len_unchecked(packet_len).len()
        }

        fn next_frame_as_ipv4_packet<'a>(&mut self, buf: &'a mut [u8]) -> IPv4Packet<&'a [u8]> {
            let len = self.write_next_frame(buf).unwrap().get();
            let eth = EthernetFrame::from_bytes(&buf[..len]).unwrap();
            IPv4Packet::from_bytes(&buf[eth.payload_offset()..len], true).unwrap()
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_ns() {
        let mut ns = MmdsNetworkStack::new_with_defaults();
        assert_eq!(ns.mac_addr, MacAddr::parse_str(DEFAULT_MAC_ADDR).unwrap());
        assert_eq!(ns.ipv4_addr, Ipv4Addr::from(DEFAULT_IPV4_ADDR));

        let mut buf = [0u8; 2000];
        let mut bad_buf = [0u8; 1];

        let remote_mac = MacAddr::parse_str(REMOTE_MAC_STR).unwrap();
        let mmds_addr = ns.ipv4_addr;
        let bad_mmds_addr = Ipv4Addr::from_str("1.2.3.4").unwrap();

        // Buffer is too small.
        assert!(!ns.detour_frame(bad_buf.as_ref()));

        // There's nothing to send right now.
        assert!(ns.write_next_frame(buf.as_mut()).is_none());

        {
            let len = ns.write_arp_request(buf.as_mut(), false);
            // Not asking for MMDS MAC address.
            assert!(!ns.detour_frame(&buf[..len]));
            // There's still nothing to send.
            assert!(ns.write_next_frame(buf.as_mut()).is_none());
        }

        {
            let len = ns.write_arp_request(buf.as_mut(), true);

            // Asking for MMDS MAC address.
            assert!(ns.detour_frame(&buf[..len]));

            assert_eq!(ns.remote_mac_addr, remote_mac);
        }

        // There should be an ARP reply to send.
        {
            // Buffer is too small.
            assert!(ns.write_next_frame(bad_buf.as_mut()).is_none());

            let curr_tx_count = METRICS.mmds.tx_count.count();
            let len = ns.write_next_frame(buf.as_mut()).unwrap().get();
            assert_eq!(curr_tx_count + 1, METRICS.mmds.tx_count.count());
            let eth = EthernetFrame::from_bytes(&buf[..len]).unwrap();
            let arp_reply = EthIPv4ArpFrame::from_bytes_unchecked(eth.payload());

            // REPLY = 2
            assert_eq!(arp_reply.operation(), 2);
            assert_eq!(arp_reply.sha(), ns.mac_addr);
            assert_eq!(arp_reply.spa(), ns.ipv4_addr);
            assert_eq!(arp_reply.tha(), ns.remote_mac_addr);
            assert_eq!(arp_reply.tpa(), REMOTE_ADDR);
        }

        // Nothing to send anymore.
        assert!(ns.write_next_frame(buf.as_mut()).is_none());

        // Let's send a TCP segment which will be rejected, because it's heading to the wrong
        // address.
        {
            let len = ns.write_incoming_tcp_segment(buf.as_mut(), bad_mmds_addr, TcpFlags::ACK);
            assert!(!ns.detour_frame(&buf[..len]));

            // Nothing to send in response.
            assert!(ns.write_next_frame(buf.as_mut()).is_none());
        }

        // Let's send a TCP segment which will cause a RST to come out of the inner TCP handler.
        {
            let len = ns.write_incoming_tcp_segment(buf.as_mut(), mmds_addr, TcpFlags::ACK);
            let curr_rx_count = METRICS.mmds.rx_count.count();
            assert!(ns.detour_frame(&buf[..len]));
            assert_eq!(curr_rx_count + 1, METRICS.mmds.rx_count.count());
        }

        // Let's check we actually get a RST when writing the next frame.
        {
            assert!(ns.write_next_frame(bad_buf.as_mut()).is_none());

            let ip = ns.next_frame_as_ipv4_packet(buf.as_mut());
            assert_eq!(ip.source_address(), mmds_addr);
            assert_eq!(ip.destination_address(), REMOTE_ADDR);

            let s = TcpSegment::from_bytes(
                ip.payload(),
                Some((ip.source_address(), ip.destination_address())),
            )
            .unwrap();
            assert_eq!(s.flags_after_ns(), TcpFlags::RST);
            assert_eq!(s.source_port(), MMDS_PORT);
            assert_eq!(s.destination_port(), REMOTE_PORT);
        }

        // Nothing else to send.
        assert!(ns.write_next_frame(buf.as_mut()).is_none());

        // Let's send a TCP SYN into the ns.
        {
            let len = ns.write_incoming_tcp_segment(buf.as_mut(), mmds_addr, TcpFlags::SYN);
            assert_eq!(ns.detour_frame(&buf[..len]), true);
        }

        // We should be getting a SYNACK out of the ns in response.
        {
            let ip = ns.next_frame_as_ipv4_packet(buf.as_mut());
            assert_eq!(ip.source_address(), mmds_addr);
            assert_eq!(ip.destination_address(), REMOTE_ADDR);

            let s = TcpSegment::from_bytes(
                ip.payload(),
                Some((ip.source_address(), ip.destination_address())),
            )
            .unwrap();
            assert_eq!(s.flags_after_ns(), TcpFlags::SYN | TcpFlags::ACK);
            assert_eq!(s.source_port(), MMDS_PORT);
            assert_eq!(s.destination_port(), REMOTE_PORT);
            assert_eq!(s.ack_number(), SEQ_NUMBER.wrapping_add(1));
        }

        // Nothing else to send.
        assert!(ns.write_next_frame(buf.as_mut()).is_none());
    }
}
