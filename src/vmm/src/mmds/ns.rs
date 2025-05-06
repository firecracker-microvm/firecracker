// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TODO: get rid of this when splitting dumbo into public and internal parts.
#![allow(missing_docs)]

use std::convert::From;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::result::Result;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use utils::time::timestamp_cycles;

use crate::dumbo::pdu::Incomplete;
use crate::dumbo::pdu::arp::{
    ArpError as ArpFrameError, ETH_IPV4_FRAME_LEN, EthIPv4ArpFrame, test_speculative_tpa,
};
use crate::dumbo::pdu::ethernet::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetError as EthernetFrameError, EthernetFrame,
};
use crate::dumbo::pdu::ipv4::{
    IPv4Packet, Ipv4Error as IPv4PacketError, PROTOCOL_TCP, test_speculative_dst_addr,
};
use crate::dumbo::pdu::tcp::TcpError as TcpSegmentError;
use crate::dumbo::tcp::NextSegmentStatus;
use crate::dumbo::tcp::handler::{RecvEvent, TcpIPv4Handler, WriteEvent, WriteNextError};
use crate::logger::{IncMetric, METRICS};
use crate::mmds::data_store::Mmds;
use crate::utils::net::mac::MacAddr;

const DEFAULT_MAC_ADDR: &str = "06:01:23:45:67:01";
const DEFAULT_IPV4_ADDR: [u8; 4] = [169, 254, 169, 254];
const DEFAULT_TCP_PORT: u16 = 80;
const DEFAULT_MAX_CONNECTIONS: usize = 30;
const DEFAULT_MAX_PENDING_RESETS: usize = 100;

#[derive(Debug, PartialEq, thiserror::Error, displaydoc::Display)]
enum WriteArpFrameError {
    /// NoPendingArpReply
    NoPendingArpReply,
    /// ARP error: {0}
    Arp(#[from] ArpFrameError),
    /// Ethernet error: {0}
    Ethernet(#[from] EthernetFrameError),
}

#[derive(Debug, PartialEq, thiserror::Error, displaydoc::Display)]
enum WritePacketError {
    /// IPv4Packet error: {0}
    IPv4Packet(#[from] IPv4PacketError),
    /// Ethernet error: {0}
    Ethernet(#[from] EthernetFrameError),
    /// TcpSegment error: {0}
    TcpSegment(#[from] TcpSegmentError),
    /// WriteNext error: {0}
    WriteNext(#[from] WriteNextError),
}

#[derive(Debug)]
pub struct MmdsNetworkStack {
    // Network interface MAC address used by frames/packets heading to MMDS server.
    remote_mac_addr: MacAddr,
    // The Ethernet MAC address of the MMDS server.
    pub(crate) mac_addr: MacAddr,
    // MMDS server IPv4 address.
    pub ipv4_addr: Ipv4Addr,
    // ARP reply destination IPv4 address (requester of address resolution reply).
    // It is the Ipv4Addr of the network interface for which the MmdsNetworkStack
    // routes the packets.
    pending_arp_reply_dest: Option<Ipv4Addr>,
    // This handles MMDS<->guest interaction at the TCP level.
    pub(crate) tcp_handler: TcpIPv4Handler,
    // Data store reference shared across all MmdsNetworkStack instances.
    pub mmds: Arc<Mutex<Mmds>>,
}

impl MmdsNetworkStack {
    pub fn new(
        mac_addr: MacAddr,
        ipv4_addr: Ipv4Addr,
        tcp_port: u16,
        mmds: Arc<Mutex<Mmds>>,
    ) -> Self {
        MmdsNetworkStack {
            remote_mac_addr: mac_addr,
            mac_addr,
            ipv4_addr,
            pending_arp_reply_dest: None,
            tcp_handler: TcpIPv4Handler::new(
                ipv4_addr,
                tcp_port,
                NonZeroUsize::new(DEFAULT_MAX_CONNECTIONS).unwrap(),
                NonZeroUsize::new(DEFAULT_MAX_PENDING_RESETS).unwrap(),
            ),
            mmds,
        }
    }

    pub fn new_with_defaults(mmds_ipv4_addr: Option<Ipv4Addr>, mmds: Arc<Mutex<Mmds>>) -> Self {
        let mac_addr = MacAddr::from_str(DEFAULT_MAC_ADDR).unwrap();
        let ipv4_addr = mmds_ipv4_addr.unwrap_or_else(|| Ipv4Addr::from(DEFAULT_IPV4_ADDR));

        // The unwrap()s are safe because the given literals are greater than 0.
        Self::new(mac_addr, ipv4_addr, DEFAULT_TCP_PORT, mmds)
    }

    pub fn set_ipv4_addr(&mut self, ipv4_addr: Ipv4Addr) {
        self.ipv4_addr = ipv4_addr;
        self.tcp_handler.set_local_ipv4_addr(ipv4_addr);
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.ipv4_addr
    }

    pub fn default_ipv4_addr() -> Ipv4Addr {
        Ipv4Addr::from(DEFAULT_IPV4_ADDR)
    }

    /// Check if a frame is destined for `mmds`
    ///
    /// This returns `true` if the frame is an ARP or IPv4 frame destined for
    /// the `mmds` service, or `false` otherwise. It does not consume the frame.
    pub fn is_mmds_frame(&self, src: &[u8]) -> bool {
        if let Ok(eth) = EthernetFrame::from_bytes(src) {
            match eth.ethertype() {
                ETHERTYPE_ARP => test_speculative_tpa(src, self.ipv4_addr),
                ETHERTYPE_IPV4 => test_speculative_dst_addr(src, self.ipv4_addr),
                _ => false,
            }
        } else {
            false
        }
    }

    /// Handles a frame destined for `mmds`
    ///
    /// It assumes that the frame is indeed destined for `mmds`, so the caller
    /// must make a call to `is_mmds_frame` to ensure that.
    ///
    /// # Returns
    ///
    /// `true` if the frame was consumed by `mmds` or `false` if an error occured
    pub fn detour_frame(&mut self, src: &[u8]) -> bool {
        if let Ok(eth) = EthernetFrame::from_bytes(src) {
            match eth.ethertype() {
                ETHERTYPE_ARP => return self.detour_arp(eth),
                ETHERTYPE_IPV4 => return self.detour_ipv4(eth),
                _ => (),
            }
        } else {
            METRICS.mmds.rx_bad_eth.inc();
        }

        false
    }

    fn detour_arp(&mut self, eth: EthernetFrame<&[u8]>) -> bool {
        if let Ok(arp) = EthIPv4ArpFrame::request_from_bytes(eth.payload()) {
            self.remote_mac_addr = arp.sha();
            self.pending_arp_reply_dest = Some(arp.spa());
            return true;
        }

        false
    }

    fn detour_ipv4(&mut self, eth: EthernetFrame<&[u8]>) -> bool {
        // TODO: We skip verifying the checksum, just in case the device model relies on offloading
        // checksum computation from the guest driver to some other entity. Clear up this entire
        // context at some point!
        if let Ok(ip) = IPv4Packet::from_bytes(eth.payload(), false) {
            if ip.protocol() == PROTOCOL_TCP {
                // Note-1: `remote_mac_address` is actually the network device mac address, where
                // this TCP segment came from.
                // Note-2: For every routed packet we will have a single source MAC address, because
                // each MmdsNetworkStack routes packets for only one network device.
                self.remote_mac_addr = eth.src_mac();
                let mmds_instance = self.mmds.clone();
                match &mut self.tcp_handler.receive_packet(&ip, move |request| {
                    super::convert_to_response(mmds_instance, request)
                }) {
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

        false
    }

    // Allows the MMDS network stack to write a frame to the specified buffer. Will return:
    // - None, if the MMDS network stack has no frame to send at this point. The buffer can be
    // used for something else by the device model.
    // - Some(len), if a frame of the given length has been written to the specified buffer.
    pub fn write_next_frame(&mut self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        // We try to send ARP replies first.
        if self.pending_arp_reply_dest.is_some() {
            return match self.write_arp_reply(buf) {
                Ok(something) => {
                    METRICS.mmds.tx_count.inc();
                    self.pending_arp_reply_dest = None;
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

    fn write_arp_reply(&self, buf: &mut [u8]) -> Result<Option<NonZeroUsize>, WriteArpFrameError> {
        let arp_reply_dest = self
            .pending_arp_reply_dest
            .ok_or(WriteArpFrameError::NoPendingArpReply)?;

        let mut eth_unsized = self.prepare_eth_unsized(buf, ETHERTYPE_ARP)?;

        let arp_len = EthIPv4ArpFrame::write_reply(
            eth_unsized
                .inner_mut()
                .payload_mut()
                .split_at_mut(ETH_IPV4_FRAME_LEN)
                .0,
            self.mac_addr,
            self.ipv4_addr,
            self.remote_mac_addr,
            arp_reply_dest,
        )?
        .len();

        Ok(Some(
            // The unwrap() is safe because arp_len > 0.
            NonZeroUsize::new(eth_unsized.with_payload_len_unchecked(arp_len).len()).unwrap(),
        ))
    }

    fn write_packet(&mut self, buf: &mut [u8]) -> Result<Option<NonZeroUsize>, WritePacketError> {
        let mut eth_unsized = self.prepare_eth_unsized(buf, ETHERTYPE_IPV4)?;

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
    use std::str::FromStr;

    use super::*;
    use crate::dumbo::pdu::tcp::{Flags as TcpFlags, TcpSegment};

    // We use LOCALHOST here because const new() is not stable yet, so just reuse this const, since
    // all we're interested in is having some address different from the MMDS one.
    const REMOTE_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;
    const REMOTE_MAC_STR: &str = "11:11:11:22:22:22";
    const MMDS_PORT: u16 = 80;
    const REMOTE_PORT: u16 = 1235;
    const SEQ_NUMBER: u32 = 123;

    // Helper methods which only make sense for testing.
    impl MmdsNetworkStack {
        fn write_arp_request(&mut self, buf: &mut [u8], for_mmds: bool) -> usize {
            // Write a reply and then modify it into a request.
            self.pending_arp_reply_dest = Some(REMOTE_ADDR);
            let len = self.write_arp_reply(buf).unwrap().unwrap().get();
            self.pending_arp_reply_dest = None;

            let mut eth = EthernetFrame::from_bytes_unchecked(&mut buf[..len]);
            let mut arp = EthIPv4ArpFrame::from_bytes_unchecked(eth.payload_mut());

            // Set the operation to REQUEST.
            arp.set_operation(1);
            arp.set_sha(MacAddr::from_str(REMOTE_MAC_STR).unwrap());
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
    fn test_ns_new_with_defaults() {
        let ns = MmdsNetworkStack::new_with_defaults(None, Arc::new(Mutex::new(Mmds::default())));
        assert_eq!(ns.mac_addr, MacAddr::from_str(DEFAULT_MAC_ADDR).unwrap());
        assert_eq!(ns.ipv4_addr, Ipv4Addr::from(DEFAULT_IPV4_ADDR));

        let ns = MmdsNetworkStack::new_with_defaults(
            Some(Ipv4Addr::LOCALHOST),
            Arc::new(Mutex::new(Mmds::default())),
        );
        assert_eq!(ns.mac_addr, MacAddr::from_str(DEFAULT_MAC_ADDR).unwrap());
        assert_eq!(ns.ipv4_addr, Ipv4Addr::LOCALHOST);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_ns() {
        let mut ns =
            MmdsNetworkStack::new_with_defaults(None, Arc::new(Mutex::new(Mmds::default())));
        let mut buf = [0u8; 2000];
        let mut bad_buf = [0u8; 1];

        let remote_mac = MacAddr::from_str(REMOTE_MAC_STR).unwrap();
        let mmds_addr = ns.ipv4_addr;
        let bad_mmds_addr = Ipv4Addr::from_str("1.2.3.4").unwrap();

        // Buffer is too small.
        assert!(!ns.is_mmds_frame(&bad_buf));
        assert!(!ns.detour_frame(bad_buf.as_ref()));

        // There's nothing to send right now.
        assert!(ns.write_next_frame(buf.as_mut()).is_none());

        {
            let len = ns.write_arp_request(buf.as_mut(), false);
            // Not asking for MMDS MAC address.
            assert!(!ns.is_mmds_frame(&buf[..len]));
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
            assert!(!ns.is_mmds_frame(&buf[..len]));

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
            assert!(ns.detour_frame(&buf[..len]));
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

    #[test]
    fn test_set_ipv4_addr() {
        let mut ns =
            MmdsNetworkStack::new_with_defaults(None, Arc::new(Mutex::new(Mmds::default())));
        assert_ne!(ns.ipv4_addr, Ipv4Addr::LOCALHOST);
        assert_ne!(ns.tcp_handler.local_ipv4_addr(), Ipv4Addr::LOCALHOST);
        ns.set_ipv4_addr(Ipv4Addr::LOCALHOST);
        assert_eq!(ns.ipv4_addr, Ipv4Addr::LOCALHOST);
        assert_eq!(ns.tcp_handler.local_ipv4_addr(), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn test_default_ipv4_addr() {
        let actual = MmdsNetworkStack::default_ipv4_addr();
        let expected = Ipv4Addr::from(DEFAULT_IPV4_ADDR);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_break_speculative_check_detour_arp() {
        let mut buf = [0u8; 2000];
        let ip = Ipv4Addr::from(DEFAULT_IPV4_ADDR);
        let other_ip = Ipv4Addr::new(5, 6, 7, 8);
        let mac = MacAddr::from_bytes_unchecked(&[0; 6]);
        let mut ns =
            MmdsNetworkStack::new_with_defaults(Some(ip), Arc::new(Mutex::new(Mmds::default())));

        let mut eth =
            EthernetFrame::write_incomplete(buf.as_mut(), mac, mac, ETHERTYPE_ARP).unwrap();
        let mut arp = EthIPv4ArpFrame::from_bytes_unchecked(eth.inner_mut().payload_mut());
        arp.set_tpa(other_ip);
        let len = ns.write_arp_request(buf.as_mut(), false);

        eth = EthernetFrame::write_incomplete(buf.as_mut(), mac, mac, ETHERTYPE_ARP).unwrap();
        IPv4Packet::from_bytes_unchecked(eth.inner_mut().payload_mut()).set_destination_address(ip);

        assert!(!ns.is_mmds_frame(&buf[..len]));
    }

    #[test]
    fn test_break_speculative_check_detour_ipv4() {
        let mut buf = [0u8; 2000];
        let ip = Ipv4Addr::from(DEFAULT_IPV4_ADDR);
        let other_ip = Ipv4Addr::new(5, 6, 7, 8);
        let mac = MacAddr::from_bytes_unchecked(&[0; 6]);
        let ns =
            MmdsNetworkStack::new_with_defaults(Some(ip), Arc::new(Mutex::new(Mmds::default())));

        let mut eth =
            EthernetFrame::write_incomplete(buf.as_mut(), mac, mac, ETHERTYPE_IPV4).unwrap();
        IPv4Packet::from_bytes_unchecked(eth.inner_mut().payload_mut())
            .set_destination_address(other_ip);
        let len = ns.write_incoming_tcp_segment(buf.as_mut(), other_ip, TcpFlags::SYN);
        eth = EthernetFrame::write_incomplete(buf.as_mut(), mac, mac, ETHERTYPE_IPV4).unwrap();
        let mut arp = EthIPv4ArpFrame::from_bytes_unchecked(eth.inner_mut().payload_mut());
        arp.set_tpa(ip);
        assert!(!ns.is_mmds_frame(&buf[..len]));
    }

    #[test]
    fn test_wrong_ethertype() {
        let mut buf = [0u8; 2000];
        let ip = Ipv4Addr::from(DEFAULT_IPV4_ADDR);
        let other_ip = Ipv4Addr::new(5, 6, 7, 8);
        let mac = MacAddr::from_bytes_unchecked(&[0; 6]);
        let mut ns =
            MmdsNetworkStack::new_with_defaults(Some(ip), Arc::new(Mutex::new(Mmds::default())));

        // try IPv4 with detour_arp
        let mut eth =
            EthernetFrame::write_incomplete(buf.as_mut(), mac, mac, ETHERTYPE_IPV4).unwrap();
        IPv4Packet::from_bytes_unchecked(eth.inner_mut().payload_mut())
            .set_destination_address(other_ip);
        let len = ns.write_incoming_tcp_segment(buf.as_mut(), other_ip, TcpFlags::SYN);

        eth = EthernetFrame::write_incomplete(buf.as_mut(), mac, mac, ETHERTYPE_IPV4).unwrap();
        let mut arp = EthIPv4ArpFrame::from_bytes_unchecked(eth.inner_mut().payload_mut());
        arp.set_tpa(ip);

        assert!(ns.detour_ipv4(EthernetFrame::from_bytes(&buf[..len]).unwrap()));
        assert!(!ns.detour_arp(EthernetFrame::from_bytes(&buf[..len]).unwrap()));

        // try IPv4 with detour_arp
        let mut eth =
            EthernetFrame::write_incomplete(buf.as_mut(), mac, mac, ETHERTYPE_ARP).unwrap();
        let mut arp = EthIPv4ArpFrame::from_bytes_unchecked(eth.inner_mut().payload_mut());
        arp.set_tpa(other_ip);
        let len = ns.write_arp_request(buf.as_mut(), false);

        eth = EthernetFrame::write_incomplete(buf.as_mut(), mac, mac, ETHERTYPE_ARP).unwrap();
        IPv4Packet::from_bytes_unchecked(eth.inner_mut().payload_mut()).set_destination_address(ip);

        assert!(ns.detour_arp(EthernetFrame::from_bytes(&buf[..len]).unwrap()));
        assert!(!ns.detour_ipv4(EthernetFrame::from_bytes(&buf[..len]).unwrap()));
    }
}
