use std::convert::From;
#[cfg(test)]
use std::fmt;
use std::net::Ipv4Addr;
use std::result::Result;

use super::bytes::{InnerBytes, NetworkBytes, NetworkBytesMut};
use super::ethernet::{self, ETHERTYPE_IPV4};
use net_util::{MacAddr, MAC_ADDR_LEN};

// A more detailed view into an ARP frame can be found here:
// https://en.wikipedia.org/wiki/Address_Resolution_Protocol

const HTYPE_OFFSET: usize = 0;
const HTYPE_ETHERNET: u16 = 0x0001;

const PTYPE_OFFSET: usize = 2;
const HLEN_OFFSET: usize = 4;
const PLEN_OFFSET: usize = 5;

const OPER_OFFSET: usize = 6;
const OPER_REQUEST: u16 = 0x0001;
const OPER_REPLY: u16 = 0x0002;

const SHA_OFFSET: usize = 8;

// The following constants are specific to ARP requests/responses
// associated with IPv4 over Ethernet.
const ETH_IPV4_SPA_OFFSET: usize = 14;
const ETH_IPV4_THA_OFFSET: usize = 18;
const ETH_IPV4_TPA_OFFSET: usize = 24;

const IPV4_ADDR_LEN: usize = 4;

pub const ETH_IPV4_FRAME_LEN: usize = 28;

#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    HLen,
    HType,
    Operation,
    PLen,
    PType,
    SliceLength,
}

// ARP is a generic protocol as far as data link layer and network layer protocols go, but we're
// specifically interested in ARP frames related to IPv4 over Ethernet.
pub struct EthIPv4ArpFrame<'a, T: 'a> {
    bytes: InnerBytes<'a, T>,
}

impl<'a, T: NetworkBytes> EthIPv4ArpFrame<'a, T> {
    #[inline]
    fn from_bytes_unchecked(bytes: T) -> Self {
        EthIPv4ArpFrame {
            bytes: InnerBytes::new(bytes),
        }
    }

    // Tries to interpret a byte slice as a valid Ethernet + IPv4 ARP request. It guarantees we can
    // safely call the accesor methods (which make use of various `_unchecked` functions), because
    // all predefined offsets will be valid.
    pub fn request_from_bytes(bytes: T) -> Result<Self, Error> {
        // This kind of frame has a fixed length, so we know what to expect.
        if bytes.len() != ETH_IPV4_FRAME_LEN {
            return Err(Error::SliceLength);
        }

        let maybe = EthIPv4ArpFrame::from_bytes_unchecked(bytes);

        if maybe.htype() != HTYPE_ETHERNET {
            return Err(Error::HType);
        }

        if maybe.ptype() != ETHERTYPE_IPV4 {
            return Err(Error::PType);
        }

        // We could theoretically skip the hlen and plen checks, since they are kinda implicit.
        if maybe.hlen() != MAC_ADDR_LEN as u8 {
            return Err(Error::HLen);
        }

        if maybe.plen() != IPV4_ADDR_LEN as u8 {
            return Err(Error::PLen);
        }

        if maybe.operation() != OPER_REQUEST {
            return Err(Error::Operation);
        }

        Ok(maybe)
    }

    #[inline]
    pub fn htype(&self) -> u16 {
        self.bytes.ntohs_unchecked(HTYPE_OFFSET)
    }

    #[inline]
    pub fn ptype(&self) -> u16 {
        self.bytes.ntohs_unchecked(PTYPE_OFFSET)
    }

    #[inline]
    pub fn hlen(&self) -> u8 {
        self.bytes[HLEN_OFFSET]
    }

    #[inline]
    pub fn plen(&self) -> u8 {
        self.bytes[PLEN_OFFSET]
    }

    #[inline]
    pub fn operation(&self) -> u16 {
        self.bytes.ntohs_unchecked(OPER_OFFSET)
    }

    #[inline]
    pub fn sha(&self) -> MacAddr {
        MacAddr::from_bytes_unchecked(&self.bytes[SHA_OFFSET..ETH_IPV4_SPA_OFFSET])
    }

    #[inline]
    pub fn spa(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.bytes.ntohl_unchecked(ETH_IPV4_SPA_OFFSET))
    }

    #[inline]
    pub fn tha(&self) -> MacAddr {
        MacAddr::from_bytes_unchecked(&self.bytes[ETH_IPV4_THA_OFFSET..ETH_IPV4_TPA_OFFSET])
    }

    #[inline]
    pub fn tpa(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.bytes.ntohl_unchecked(ETH_IPV4_TPA_OFFSET))
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl<'a, T: NetworkBytesMut> EthIPv4ArpFrame<'a, T> {
    fn write_raw(
        buf: T,
        htype: u16,
        ptype: u16,
        hlen: u8,
        plen: u8,
        operation: u16,
        sha: MacAddr,
        spa: Ipv4Addr,
        tha: MacAddr,
        tpa: Ipv4Addr,
    ) -> Result<Self, Error> {
        if buf.len() != ETH_IPV4_FRAME_LEN {
            return Err(Error::SliceLength);
        }

        // This is ok, because we've checked the length of the slice.
        let mut frame = EthIPv4ArpFrame::from_bytes_unchecked(buf);

        frame.set_htype(htype);
        frame.set_ptype(ptype);
        frame.set_hlen(hlen);
        frame.set_plen(plen);
        frame.set_operation(operation);
        frame.set_sha(sha);
        frame.set_spa(spa);
        frame.set_tha(tha);
        frame.set_tpa(tpa);

        Ok(frame)
    }

    #[inline]
    pub fn write_reply(
        buf: T,
        sha: MacAddr,
        spa: Ipv4Addr,
        tha: MacAddr,
        tpa: Ipv4Addr,
    ) -> Result<Self, Error> {
        Self::write_raw(
            buf,
            HTYPE_ETHERNET,
            ETHERTYPE_IPV4,
            MAC_ADDR_LEN as u8,
            IPV4_ADDR_LEN as u8,
            OPER_REPLY,
            sha,
            spa,
            tha,
            tpa,
        )
    }

    #[inline]
    pub fn set_htype(&mut self, value: u16) {
        self.bytes.htons_unchecked(HTYPE_OFFSET, value);
    }

    #[inline]
    pub fn set_ptype(&mut self, value: u16) {
        self.bytes.htons_unchecked(PTYPE_OFFSET, value);
    }

    #[inline]
    pub fn set_hlen(&mut self, value: u8) {
        self.bytes[HLEN_OFFSET] = value;
    }

    #[inline]
    pub fn set_plen(&mut self, value: u8) {
        self.bytes[PLEN_OFFSET] = value;
    }

    #[inline]
    pub fn set_operation(&mut self, value: u16) {
        self.bytes.htons_unchecked(OPER_OFFSET, value);
    }

    #[inline]
    pub fn set_sha(&mut self, addr: MacAddr) {
        self.bytes[SHA_OFFSET..ETH_IPV4_SPA_OFFSET].copy_from_slice(addr.get_bytes());
    }

    #[inline]
    pub fn set_spa(&mut self, addr: Ipv4Addr) {
        self.bytes
            .htonl_unchecked(ETH_IPV4_SPA_OFFSET, u32::from(addr));
    }

    #[inline]
    pub fn set_tha(&mut self, addr: MacAddr) {
        self.bytes[ETH_IPV4_THA_OFFSET..ETH_IPV4_TPA_OFFSET].copy_from_slice(addr.get_bytes());
    }

    #[inline]
    pub fn set_tpa(&mut self, addr: Ipv4Addr) {
        self.bytes
            .htonl_unchecked(ETH_IPV4_TPA_OFFSET, u32::from(addr));
    }
}

#[cfg(test)]
impl<'a, T: NetworkBytes> fmt::Debug for EthIPv4ArpFrame<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(EthIPv4ArpFrame frame)")
    }
}

/// This function checks if `buf` may hold an Ethernet frame which encapsulates an EthIPv4ArpRequest
/// for the given address. Cannot produce false negatives.
#[inline]
pub fn test_speculative_tpa(buf: &[u8], addr: Ipv4Addr) -> bool {
    // The unchecked methods are safe because we actually check the buffer length beforehand.
    if buf.len() >= ethernet::PAYLOAD_OFFSET + ETH_IPV4_FRAME_LEN {
        let bytes = &buf[ethernet::PAYLOAD_OFFSET..];
        if EthIPv4ArpFrame::from_bytes_unchecked(bytes).tpa() == addr {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eth_ipv4_arp_frame() {
        let mut a = [0u8; 1000];
        let mut bad_array = [0u8; 1];

        let sha = MacAddr::parse_str("01:23:45:67:89:ab").unwrap();
        let tha = MacAddr::parse_str("cd:ef:01:23:45:67").unwrap();
        let spa = Ipv4Addr::new(10, 1, 2, 3);
        let tpa = Ipv4Addr::new(10, 4, 5, 6);

        // Slice is too short.
        assert_eq!(
            EthIPv4ArpFrame::request_from_bytes(bad_array.as_ref()).unwrap_err(),
            Error::SliceLength
        );

        // Slice is too short.
        assert_eq!(
            EthIPv4ArpFrame::write_reply(bad_array.as_mut(), sha, spa, tha, tpa).unwrap_err(),
            Error::SliceLength
        );

        // Slice is too long.
        assert_eq!(
            EthIPv4ArpFrame::write_reply(a.as_mut(), sha, spa, tha, tpa).unwrap_err(),
            Error::SliceLength
        );

        // We write a valid ARP reply to the specified slice.
        {
            let f = EthIPv4ArpFrame::write_reply(&mut a[..ETH_IPV4_FRAME_LEN], sha, spa, tha, tpa)
                .unwrap();

            // This is a bit redundant given the following tests, but assert away!
            assert_eq!(f.htype(), HTYPE_ETHERNET);
            assert_eq!(f.ptype(), ETHERTYPE_IPV4);
            assert_eq!(f.hlen(), MAC_ADDR_LEN as u8);
            assert_eq!(f.plen(), IPV4_ADDR_LEN as u8);
            assert_eq!(f.operation(), OPER_REPLY);
            assert_eq!(f.sha(), sha);
            assert_eq!(f.spa(), spa);
            assert_eq!(f.tha(), tha);
            assert_eq!(f.tpa(), tpa);
        }

        // Now let's try to parse a request.

        // Slice is too long.
        assert_eq!(
            EthIPv4ArpFrame::request_from_bytes(a.as_ref()).unwrap_err(),
            Error::SliceLength
        );

        // The length is fine now, but the operation is a reply instead of request.
        assert_eq!(
            EthIPv4ArpFrame::request_from_bytes(&a[..ETH_IPV4_FRAME_LEN]).unwrap_err(),
            Error::Operation
        );

        // TODO: The following test code is way more verbose than it should've been. Make it
        // prettier at some point.

        // Let's write a valid request.
        EthIPv4ArpFrame::write_raw(
            &mut a[..ETH_IPV4_FRAME_LEN],
            HTYPE_ETHERNET,
            ETHERTYPE_IPV4,
            MAC_ADDR_LEN as u8,
            IPV4_ADDR_LEN as u8,
            OPER_REQUEST,
            sha,
            spa,
            tha,
            tpa,
        ).unwrap();
        assert!(EthIPv4ArpFrame::request_from_bytes(&a[..ETH_IPV4_FRAME_LEN]).is_ok());

        // Now we start writing invalid requests. We've already tried with an invalid operation.

        // Invalid htype.
        EthIPv4ArpFrame::write_raw(
            &mut a[..ETH_IPV4_FRAME_LEN],
            HTYPE_ETHERNET + 1,
            ETHERTYPE_IPV4,
            MAC_ADDR_LEN as u8,
            IPV4_ADDR_LEN as u8,
            OPER_REQUEST,
            sha,
            spa,
            tha,
            tpa,
        ).unwrap();
        assert_eq!(
            EthIPv4ArpFrame::request_from_bytes(&a[..ETH_IPV4_FRAME_LEN]).unwrap_err(),
            Error::HType
        );

        // Invalid ptype.
        EthIPv4ArpFrame::write_raw(
            &mut a[..ETH_IPV4_FRAME_LEN],
            HTYPE_ETHERNET,
            ETHERTYPE_IPV4 + 1,
            MAC_ADDR_LEN as u8,
            IPV4_ADDR_LEN as u8,
            OPER_REQUEST,
            sha,
            spa,
            tha,
            tpa,
        ).unwrap();
        assert_eq!(
            EthIPv4ArpFrame::request_from_bytes(&a[..ETH_IPV4_FRAME_LEN]).unwrap_err(),
            Error::PType
        );

        // Invalid hlen.
        EthIPv4ArpFrame::write_raw(
            &mut a[..ETH_IPV4_FRAME_LEN],
            HTYPE_ETHERNET,
            ETHERTYPE_IPV4,
            MAC_ADDR_LEN as u8 + 1,
            IPV4_ADDR_LEN as u8,
            OPER_REQUEST,
            sha,
            spa,
            tha,
            tpa,
        ).unwrap();
        assert_eq!(
            EthIPv4ArpFrame::request_from_bytes(&a[..ETH_IPV4_FRAME_LEN]).unwrap_err(),
            Error::HLen
        );

        // Invalid plen.
        EthIPv4ArpFrame::write_raw(
            &mut a[..ETH_IPV4_FRAME_LEN],
            HTYPE_ETHERNET,
            ETHERTYPE_IPV4,
            MAC_ADDR_LEN as u8,
            IPV4_ADDR_LEN as u8 + 1,
            OPER_REQUEST,
            sha,
            spa,
            tha,
            tpa,
        ).unwrap();
        assert_eq!(
            EthIPv4ArpFrame::request_from_bytes(&a[..ETH_IPV4_FRAME_LEN]).unwrap_err(),
            Error::PLen
        );
    }

    #[test]
    fn test_speculative() {
        let mut a = [0u8; 1000];
        let addr = Ipv4Addr::new(1, 2, 3, 4);

        assert!(!test_speculative_tpa(a.as_ref(), addr));

        {
            let mac = MacAddr::from_bytes_unchecked(&[0; 6]);
            let mut eth =
                ::pdu::ethernet::EthernetFrame::write_incomplete(a.as_mut(), mac, mac, 0).unwrap();
            let mut arp = EthIPv4ArpFrame::from_bytes_unchecked(eth.inner_mut().payload_mut());
            arp.set_tpa(addr);
        }

        assert!(test_speculative_tpa(a.as_ref(), addr));

        // Let's also test for a very small buffer.
        let small = [0u8; 1];
        assert!(!test_speculative_tpa(small.as_ref(), addr));
    }
}
