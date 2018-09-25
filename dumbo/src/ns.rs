use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::result::Result;

use logger::{Metric, METRICS};
use net_util::MacAddr;
use pdu::arp::{test_speculative_tpa, Error as ArpFrameError, EthIPv4ArpFrame, ETH_IPV4_FRAME_LEN};
use pdu::ethernet::{Error as EthernetFrameError, EthernetFrame, ETHERTYPE_ARP};

#[cfg_attr(test, derive(Debug, PartialEq))]
enum WriteArpReplyError {
    Arp(ArpFrameError),
    Ethernet(EthernetFrameError),
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
}

impl MmdsNetworkStack {
    pub fn new(mac_addr: MacAddr, ipv4_addr: Ipv4Addr) -> Self {
        MmdsNetworkStack {
            mac_addr,
            remote_mac_addr: mac_addr,
            ipv4_addr,
            pending_arp_reply: None,
        }
    }

    pub fn new_with_defaults() -> Self {
        // The unwrap is safe if parse_str() is implemented properly.
        let mac_addr = MacAddr::parse_str("06:01:23:45:67:01").unwrap();
        let ipv4_addr = Ipv4Addr::from([169, 254, 169, 254]);

        Self::new(mac_addr, ipv4_addr)
    }

    pub fn mac_addr(&self) -> MacAddr {
        self.mac_addr
    }

    pub fn remote_mac_addr(&self) -> MacAddr {
        self.remote_mac_addr
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.ipv4_addr
    }

    // This is the entry point into the MMDS network stack. The src slice should hold the contents
    // of an Ethernet frame (of that exact size, without the CRC).
    pub fn detour_frame(&mut self, src: &[u8]) -> bool {
        // The frame cannot possibly contain an ARP request for the MMDS IPv4 addr.
        if !test_speculative_tpa(src, self.ipv4_addr) {
            return false;
        }

        if let Ok(eth) = EthernetFrame::from_bytes(src) {
            match eth.ethertype() {
                ETHERTYPE_ARP => return self.detour_arp(eth),
                _ => (),
            };
        } else {
            METRICS.mmds.rx_bad_eth.inc();
        }
        return false;
    }

    fn detour_arp(&mut self, eth: EthernetFrame<&[u8]>) -> bool {
        if let Ok(arp) = EthIPv4ArpFrame::request_from_bytes(eth.payload()) {
            if arp.tpa() == self.ipv4_addr() {
                self.remote_mac_addr = arp.sha();
                self.pending_arp_reply = Some(arp.spa());
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
        if let Some(spa) = self.pending_arp_reply.take() {
            return match self.write_arp_reply(buf, spa) {
                Ok(something) => something,
                Err(_) => {
                    METRICS.mmds.tx_errors.inc();
                    None
                }
            };
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
            self.mac_addr(),
            self.ipv4_addr(),
            self.remote_mac_addr,
            dst_ipv4,
        ).map_err(WriteArpReplyError::Arp)?
        .len();

        Ok(Some(
            // The unwrap() is safe because arp_len > 0.
            NonZeroUsize::new(eth_unsized.with_payload_len(arp_len).len()).unwrap(),
        ))
    }
}
