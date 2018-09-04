use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::result::Result;

use net_util::MacAddr;
use pdu::arp::{ETH_IPV4_FRAME_LEN, EthIPv4ArpFrame};
use pdu::ethernet::{EthernetFrame, ETHERTYPE_ARP};
use pdu::{self, Error as PduError};

#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    Pdu(pdu::Error),
}

pub enum DetourFrameOutcome {
    // If the option is None, the frame has been accepted and successfully processed by the MMDS
    // network stack. Otherwise, it was addressed to the MMDS stack (it contains an IPv4 packet with
    // the appropriate destination address), but there was an error while processing it. The device
    // model should ignore the packet in either case.
    Accepted(Option<Error>),
    // The frame does not appear to head towards the MMDS  (its payload is not a valid IPv4 packet
    // with the appropriate destination address). The device model should continue to handle it.
    DoNotWant,
    // We could not manage to successfully parse the input as a valid Ethernet frame. The device
    // model might as well continue to handle it.
    UnexpectedFrame,
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

    // TODO: We'll shorty add some code which checks whether this frame can be heading towards the
    // MMDS by looking at where the destination IP address should be. If this test fails, we can
    // ignore the frame, and skip all the other checks which don't make sense anymore.
    pub fn detour_frame(&mut self, src: &[u8]) -> DetourFrameOutcome {
        if let Ok(eth) = EthernetFrame::from_bytes(src) {
            match eth.ethertype() {
                ETHERTYPE_ARP => return self.detour_arp(eth),
                _ => return DetourFrameOutcome::DoNotWant,
            };
        } else {
            return DetourFrameOutcome::UnexpectedFrame;
        }
    }

    fn detour_arp(&mut self, eth: EthernetFrame<&[u8]>) -> DetourFrameOutcome {
        if let Ok(arp) = EthIPv4ArpFrame::request_from_bytes(eth.payload()) {
            if arp.tpa() == self.ipv4_addr() {
                self.remote_mac_addr = arp.sha();
                self.pending_arp_reply = Some(arp.spa());
                return DetourFrameOutcome::Accepted(None);
            }
        }
        DetourFrameOutcome::DoNotWant
    }

    // Allows the MMDS network stack to write a frame to the specified buffer. Will return:
    // - Ok(None), if the MMDS network stack has no frame to send at this point. The buffer can be
    // used for something else by the device model.
    //
    // - Ok(len), if a frame of the given length has been written to the specified buffer.
    //
    // - Error(e), if the MMDS network stack has at least one frame to send, but did not manage to
    // write it successfully to the specified buffer. The device model can use the buffer for
    // something else.
    pub fn write_next_frame(&mut self, buf: &mut [u8]) -> Result<Option<NonZeroUsize>, Error> {
        let remote_mac_addr = self.remote_mac_addr;
        // We try to send ARP replies first.
        if let Some(spa) = self.pending_arp_reply.take() {
            return self
                .write_arp_reply(buf, remote_mac_addr, spa)
                .map_err(Error::Pdu);
        }
        Ok(None)
    }

    fn write_arp_reply(
        &mut self,
        buf: &mut [u8],
        dst_mac: MacAddr,
        dst_ipv4: Ipv4Addr,
    ) -> Result<Option<NonZeroUsize>, PduError> {
        let mut eth_unsized =
            EthernetFrame::write_incomplete(buf, dst_mac, self.mac_addr(), ETHERTYPE_ARP)
                .map_err(PduError::Ethernet)?;

        let arp_len = EthIPv4ArpFrame::write_reply(
            eth_unsized
                .inner_mut()
                .payload_mut()
                .split_at_mut(ETH_IPV4_FRAME_LEN)
                .0,
            self.mac_addr(),
            self.ipv4_addr(),
            dst_mac,
            dst_ipv4,
        ).map_err(PduError::Arp)?
            .len();

        Ok(Some(
            // The unwrap() is safe because arp_len > 0.
            NonZeroUsize::new(eth_unsized.with_payload_len(arp_len).len()).unwrap(),
        ))
    }
}
