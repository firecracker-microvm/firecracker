// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contains support for parsing and writing Ethernet frames. Does not currently offer support for
//! 802.1Q tags.

use std::result::Result;

use super::bytes::{InnerBytes, NetworkBytes, NetworkBytesMut};
use super::Incomplete;
use crate::MacAddr;

const DST_MAC_OFFSET: usize = 0;
const SRC_MAC_OFFSET: usize = 6;
const ETHERTYPE_OFFSET: usize = 12;

// We don't support 802.1Q tags.
// TODO: support 802.1Q tags?! If so, don't forget to change the speculative_test_* functions
// for ARP and IPv4.
/// Payload offset in an ethernet frame
pub const PAYLOAD_OFFSET: usize = 14;

/// Ethertype value for ARP frames.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// Ethertype value for IPv4 packets.
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// Describes the errors which may occur when handling Ethernet frames.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// The specified byte sequence is shorter than the Ethernet header length.
    SliceTooShort,
}

/// Interprets the inner bytes as an Ethernet frame.
pub struct EthernetFrame<'a, T: 'a> {
    bytes: InnerBytes<'a, T>,
}

#[allow(clippy::len_without_is_empty)]
impl<'a, T: NetworkBytes> EthernetFrame<'a, T> {
    /// Interprets `bytes` as an Ethernet frame without any validity checks.
    ///
    /// # Panics
    ///
    ///  This method does not panic, but further method calls on the resulting object may panic if
    /// `bytes` contains invalid input.
    #[inline]
    pub fn from_bytes_unchecked(bytes: T) -> Self {
        EthernetFrame {
            bytes: InnerBytes::new(bytes),
        }
    }

    /// Checks whether the specified byte sequence can be interpreted as an Ethernet frame.
    #[inline]
    pub fn from_bytes(bytes: T) -> Result<Self, Error> {
        if bytes.len() < PAYLOAD_OFFSET {
            return Err(Error::SliceTooShort);
        }

        Ok(EthernetFrame::from_bytes_unchecked(bytes))
    }

    /// Returns the destination MAC address.
    #[inline]
    pub fn dst_mac(&self) -> MacAddr {
        MacAddr::from_bytes_unchecked(&self.bytes[DST_MAC_OFFSET..SRC_MAC_OFFSET])
    }

    /// Returns the source MAC address.
    #[inline]
    pub fn src_mac(&self) -> MacAddr {
        MacAddr::from_bytes_unchecked(&self.bytes[SRC_MAC_OFFSET..ETHERTYPE_OFFSET])
    }

    /// Returns the ethertype of the frame.
    #[inline]
    pub fn ethertype(&self) -> u16 {
        self.bytes.ntohs_unchecked(ETHERTYPE_OFFSET)
    }

    /// Returns the offset of the payload within the frame.
    #[inline]
    pub fn payload_offset(&self) -> usize {
        PAYLOAD_OFFSET
    }

    /// Returns the payload of the frame as an `[&u8]` slice.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.bytes.split_at(self.payload_offset()).1
    }

    /// Returns the length of the frame.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl<'a, T: NetworkBytesMut> EthernetFrame<'a, T> {
    /// Attempts to write an Ethernet frame using the given header fields to `buf`.
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

        frame
            .set_dst_mac(dst_mac)
            .set_src_mac(src_mac)
            .set_ethertype(ethertype);

        Ok(frame)
    }

    /// Attempts to write an incomplete Ethernet frame (whose length is currently unknown) to `buf`,
    /// using the specified header fields.
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

    /// Sets the destination MAC address.
    #[inline]
    pub fn set_dst_mac(&mut self, addr: MacAddr) -> &mut Self {
        self.bytes[DST_MAC_OFFSET..SRC_MAC_OFFSET].copy_from_slice(addr.get_bytes());
        self
    }

    /// Sets the source MAC address.
    #[inline]
    pub fn set_src_mac(&mut self, addr: MacAddr) -> &mut Self {
        self.bytes[SRC_MAC_OFFSET..ETHERTYPE_OFFSET].copy_from_slice(addr.get_bytes());
        self
    }

    /// Sets the ethertype of the frame.
    #[inline]
    pub fn set_ethertype(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(ETHERTYPE_OFFSET, value);
        self
    }

    /// Returns the payload of the frame as a `&mut [u8]` slice.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // We need this let to avoid confusing the borrow checker.
        let offset = self.payload_offset();
        self.bytes.split_at_mut(offset).1
    }
}

impl<'a, T: NetworkBytes> Incomplete<EthernetFrame<'a, T>> {
    /// Completes the inner frame by shrinking it to its actual length.
    ///
    /// # Panics
    ///
    /// This method panics if `len` is greater than the length of the inner byte sequence.
    #[inline]
    pub fn with_payload_len_unchecked(mut self, payload_len: usize) -> EthernetFrame<'a, T> {
        let payload_offset = self.inner.payload_offset();
        self.inner
            .bytes
            .shrink_unchecked(payload_offset + payload_len);
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt;

    impl<'a, T: NetworkBytes> fmt::Debug for EthernetFrame<'a, T> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "(Ethernet frame)")
        }
    }

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
            let f3_complete = f3.with_payload_len_unchecked(123);
            assert_eq!(f3_complete.len(), f3_complete.payload_offset() + 123);
        }
    }
}
