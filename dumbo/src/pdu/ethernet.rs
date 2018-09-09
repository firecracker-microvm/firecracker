#[cfg(test)]
use std::fmt;
use std::result::Result;

use super::bytes::{InnerBytes, NetworkBytes, NetworkBytesMut};
use super::Incomplete;
use net_util::MacAddr;

const DST_MAC_OFFSET: usize = 0;
const SRC_MAC_OFFSET: usize = 6;
const ETHERTYPE_OFFSET: usize = 12;

// We don't support 802.1Q tags.
// TODO: support 802.1Q tags?! If so, don't forget to change the speculative_test_* functions
// for ARP and IPv4.
pub(super) const PAYLOAD_OFFSET: usize = 14;

pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV4: u16 = 0x0800;

#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    SliceTooShort,
}

pub struct EthernetFrame<'a, T: 'a> {
    bytes: InnerBytes<'a, T>,
}

impl<'a, T: NetworkBytes> EthernetFrame<'a, T> {
    #[inline]
    pub fn from_bytes_unchecked(bytes: T) -> Self {
        EthernetFrame {
            bytes: InnerBytes::new(bytes),
        }
    }

    #[inline]
    pub fn from_bytes(bytes: T) -> Result<Self, Error> {
        if bytes.len() < PAYLOAD_OFFSET {
            return Err(Error::SliceTooShort);
        }

        Ok(EthernetFrame::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn dst_mac(&self) -> MacAddr {
        MacAddr::from_bytes_unchecked(&self.bytes[DST_MAC_OFFSET..SRC_MAC_OFFSET])
    }

    #[inline]
    pub fn src_mac(&self) -> MacAddr {
        MacAddr::from_bytes_unchecked(&self.bytes[SRC_MAC_OFFSET..ETHERTYPE_OFFSET])
    }

    #[inline]
    pub fn ethertype(&self) -> u16 {
        self.bytes.ntohs_unchecked(ETHERTYPE_OFFSET)
    }

    #[inline]
    pub fn payload_offset(&self) -> usize {
        PAYLOAD_OFFSET
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.bytes.split_at(self.payload_offset()).1
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl<'a, T: NetworkBytesMut> EthernetFrame<'a, T> {
    fn new_with_header(
        buf: T,
        dst_mac: MacAddr,
        src_mac: MacAddr,
        ethertype: u16,
    ) -> Result<Self, Error> {
        if buf.len() < PAYLOAD_OFFSET {
            return Err(Error::SliceTooShort);
        }

        let mut frame = EthernetFrame::from_bytes_unchecked(buf);

        frame.set_dst_mac(dst_mac);
        frame.set_src_mac(src_mac);
        frame.set_ethertype(ethertype);

        Ok(frame)
    }

    #[inline]
    pub fn write_incomplete(
        buf: T,
        dst_mac: MacAddr,
        src_mac: MacAddr,
        ethertype: u16,
    ) -> Result<Incomplete<Self>, Error> {
        Ok(Incomplete::new(Self::new_with_header(
            buf, dst_mac, src_mac, ethertype,
        )?))
    }

    #[inline]
    pub fn set_dst_mac(&mut self, addr: MacAddr) {
        self.bytes[DST_MAC_OFFSET..SRC_MAC_OFFSET].copy_from_slice(addr.get_bytes());
    }

    #[inline]
    pub fn set_src_mac(&mut self, addr: MacAddr) {
        self.bytes[SRC_MAC_OFFSET..ETHERTYPE_OFFSET].copy_from_slice(addr.get_bytes());
    }

    #[inline]
    pub fn set_ethertype(&mut self, value: u16) {
        self.bytes.htons_unchecked(ETHERTYPE_OFFSET, value);
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // We need this let to avoid confusing the borrow checker.
        let offset = self.payload_offset();
        self.bytes.split_at_mut(offset).1
    }
}

impl<'a, T: NetworkBytes> Incomplete<EthernetFrame<'a, T>> {
    #[inline]
    pub fn with_payload_len(mut self, payload_len: usize) -> EthernetFrame<'a, T> {
        let payload_offset = self.inner.payload_offset();
        self.inner
            .bytes
            .shrink_unchecked(payload_offset + payload_len);
        self.inner
    }
}

#[cfg(test)]
impl<'a, T: NetworkBytes> fmt::Debug for EthernetFrame<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(Ethernet frame)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_frame() {
        let mut a = [0u8; 10000];
        let mut bad_array = [0u8; 1];

        let dst_mac = MacAddr::parse_str("01:23:45:67:89:ab").unwrap();
        let src_mac = MacAddr::parse_str("cd:ef:01:23:45:67").unwrap();
        let ethertype = 1289;

        assert_eq!(
            EthernetFrame::from_bytes(bad_array.as_ref()).unwrap_err(),
            Error::SliceTooShort
        );
        assert_eq!(
            EthernetFrame::new_with_header(bad_array.as_mut(), dst_mac, src_mac, ethertype)
                .unwrap_err(),
            Error::SliceTooShort
        );

        {
            let mut f1 =
                EthernetFrame::new_with_header(a.as_mut(), dst_mac, src_mac, ethertype).unwrap();

            assert_eq!(f1.dst_mac(), dst_mac);
            assert_eq!(f1.src_mac(), src_mac);
            assert_eq!(f1.ethertype(), ethertype);
            f1.payload_mut()[1] = 132;
        }

        {
            let f2 = EthernetFrame::from_bytes(a.as_ref()).unwrap();

            assert_eq!(f2.dst_mac(), dst_mac);
            assert_eq!(f2.src_mac(), src_mac);
            assert_eq!(f2.ethertype(), ethertype);
            assert_eq!(f2.payload()[1], 132);
            assert_eq!(f2.len(), f2.bytes.len());
        }

        {
            let f3 =
                EthernetFrame::write_incomplete(a.as_mut(), dst_mac, src_mac, ethertype).unwrap();
            let f3_complete = f3.with_payload_len(123);
            assert_eq!(f3_complete.len(), f3_complete.payload_offset() + 123);
        }
    }
}
