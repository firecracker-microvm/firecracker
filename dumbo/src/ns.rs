// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::From;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::result::Result;

use fc_util::timestamp_cycles;
use logger::{Metric, METRICS};
use net_util::MacAddr;
use pdu::arp::{test_speculative_tpa, Error as ArpFrameError, EthIPv4ArpFrame, ETH_IPV4_FRAME_LEN};
use pdu::ethernet::{Error as EthernetFrameError, EthernetFrame, ETHERTYPE_ARP, ETHERTYPE_IPV4};
use pdu::ipv4::{test_speculative_dst_addr, Error as IPv4PacketError, IPv4Packet, PROTOCOL_TCP};
use pdu::tcp::Error as TcpSegmentError;
use tcp::handler::{self, RecvEvent, TcpIPv4Handler, WriteEvent};
use tcp::NextSegmentStatus;

const DEFAULT_MAC_ADDR: &str = "06:01:23:45:67:01";
const DEFAULT_IPV4_ADDR: [u8; 4] = [169, 254, 169, 254];
const DEFAULT_TCP_PORT: u16 = 80;
const DEFAULT_MAX_CONNECTIONS: usize = 30;
const DEFAULT_MAX_PENDING_RESETS: usize = 100;

#[cfg_attr(test, derive(Debug, PartialEq))]
enum WriteArpReplyError {
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
        return false;
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
                        Ok(event) => match event {
                            RecvEvent::NewConnectionSuccessful => {
                                METRICS.mmds.connections_created.inc()
                            }
                            RecvEvent::NewConnectionReplacing => {
                                METRICS.mmds.connections_created.inc();
                                METRICS.mmds.connections_destroyed.inc();
                            }
                            _ => (),
                        },
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
                    Ok(something) => something,
                    Err(_) => {
                        METRICS.mmds.tx_errors.inc();
                        None
                    }
                };
            }
        }
        None
    }

    fn write_arp_reply(
        &mut self,
        buf: &mut [u8],
        dst_ipv4: Ipv4Addr,
    ) -> Result<Option<NonZeroUsize>, WriteArpReplyError> {
        let mut eth_unsized = EthernetFrame::write_incomplete(
            buf,
            self.remote_mac_addr,
            self.mac_addr,
            ETHERTYPE_ARP,
        ).map_err(WriteArpReplyError::Ethernet)?;

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
        ).map_err(WriteArpReplyError::Arp)?
        .len();

        Ok(Some(
            // The unwrap() is safe because arp_len > 0.
            NonZeroUsize::new(eth_unsized.with_payload_len_unchecked(arp_len).len()).unwrap(),
        ))
    }

    fn write_packet(&mut self, buf: &mut [u8]) -> Result<Option<NonZeroUsize>, WritePacketError> {
        let mut eth_unsized = EthernetFrame::write_incomplete(
            buf,
            self.remote_mac_addr,
            self.mac_addr,
            ETHERTYPE_IPV4,
        ).map_err(WritePacketError::Ethernet)?;

        let (maybe_len, event) = self
            .tcp_handler
            .write_next_packet(eth_unsized.inner_mut().payload_mut())?;

        match event {
            WriteEvent::EndpointDone => METRICS.mmds.connections_destroyed.inc(),
            _ => (),
        }

        if let Some(packet_len) = maybe_len {
            return Ok(Some(
                // The unwrap() is safe because packet_len > 0.
                NonZeroUsize::new(
                    eth_unsized
                        .with_payload_len_unchecked(packet_len.get())
                        .len(),
                ).unwrap(),
            ));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let ns = MmdsNetworkStack::new_with_defaults();
        assert_eq!(ns.mac_addr, MacAddr::parse_str(DEFAULT_MAC_ADDR).unwrap());
        assert_eq!(ns.ipv4_addr, Ipv4Addr::from(DEFAULT_IPV4_ADDR));
    }
}
