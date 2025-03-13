// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contains support for parsing and writing Ethernet frames. Does not currently offer support for
//! 802.1Q tags.

use std::fmt::Debug;
use std::result::Result;

use super::Incomplete;
use super::bytes::{InnerBytes, NetworkBytes, NetworkBytesMut};
use crate::dumbo::MacAddr;

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
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum EthernetError {
    /// The specified byte sequence is shorter than the Ethernet header length.
    SliceTooShort,
}

/// Interprets the inner bytes as an Ethernet frame.
#[derive(Debug)]
pub struct EthernetFrame<'a, T: 'a> {
    bytes: InnerBytes<'a, T>,
}

#[allow(clippy::len_without_is_empty)]
impl<T: NetworkBytes + Debug> EthernetFrame<'_, T> {
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
    pub fn from_bytes(bytes: T) -> Result<Self, EthernetError> {
        if bytes.len() < PAYLOAD_OFFSET {
            return Err(EthernetError::SliceTooShort);
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

impl<T: NetworkBytesMut + Debug> EthernetFrame<'_, T> {
    /// Attempts to write an Ethernet frame using the given header fields to `buf`.
    fn new_with_header(
        buf: T,
        dst_mac: MacAddr,
        src_mac: MacAddr,
        ethertype: u16,
    ) -> Result<Self, EthernetError> {
        if buf.len() < PAYLOAD_OFFSET {
            return Err(EthernetError::SliceTooShort);
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
    ) -> Result<Incomplete<Self>, EthernetError> {
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

impl<'a, T: NetworkBytes + Debug> Incomplete<EthernetFrame<'a, T>> {
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
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_ethernet_frame() {
        let mut a = [0u8; 10000];
        let mut bad_array = [0u8; 1];

        let dst_mac = MacAddr::from_str("01:23:45:67:89:ab").unwrap();
        let src_mac = MacAddr::from_str("cd:ef:01:23:45:67").unwrap();
        let ethertype = 1289;

        assert_eq!(
            EthernetFrame::from_bytes(bad_array.as_ref()).unwrap_err(),
            EthernetError::SliceTooShort
        );
        assert_eq!(
            EthernetFrame::new_with_header(bad_array.as_mut(), dst_mac, src_mac, ethertype)
                .unwrap_err(),
            EthernetError::SliceTooShort
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

#[cfg(kani)]
#[allow(dead_code)] // Avoid warning when using stubs.
mod kani_proofs {
    use super::*;
    use crate::utils::net::mac::MAC_ADDR_LEN;

    // See the Virtual I/O Device (VIRTIO) specification, Sec. 5.1.6.2.
    // https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.pdf
    pub const MAX_FRAME_SIZE: usize = 1514;

    const MAC_ADDR_LEN_USIZE: usize = MAC_ADDR_LEN as usize;

    impl<'a, T: NetworkBytesMut + Debug> EthernetFrame<'a, T> {
        fn is_valid(&self) -> bool {
            self.len() >= PAYLOAD_OFFSET
        }
    }

    // We consider the MMDS Network Stack spec for all postconditions in the harnesses.
    // See https://github.com/firecracker-microvm/firecracker/blob/main/docs/mmds/mmds-design.md#mmds-network-stack

    #[kani::proof]
    fn verify_from_bytes_unchecked() {
        // Create non-deterministic stream of bytes up to MAX_FRAME_SIZE
        let mut bytes: [u8; MAX_FRAME_SIZE] = kani::Arbitrary::any_array::<MAX_FRAME_SIZE>();
        let slice_length = bytes.len();

        // Verify from_bytes_unchecked
        let ethernet = EthernetFrame::from_bytes_unchecked(bytes.as_mut());

        // Check for post-conditions
        assert_eq!(ethernet.len(), slice_length);
        assert!(
            !(ethernet.is_valid()) || (ethernet.payload().len() == slice_length - PAYLOAD_OFFSET)
        );
    }

    #[kani::proof]
    fn verify_from_bytes() {
        // Create non-deterministic stream of bytes up to MAX_FRAME_SIZE
        let mut bytes: [u8; MAX_FRAME_SIZE] = kani::Arbitrary::any_array::<MAX_FRAME_SIZE>();
        let slice_length = bytes.len();

        // Verify from_bytes
        let ethernet = EthernetFrame::from_bytes(bytes.as_mut());

        // Check for post-conditions
        if slice_length >= PAYLOAD_OFFSET {
            let ethernet = ethernet.unwrap();
            assert!(ethernet.is_valid());
            assert_eq!(ethernet.len(), slice_length);
            assert_eq!(ethernet.payload().len(), slice_length - PAYLOAD_OFFSET);
        } else {
            ethernet.unwrap_err();
        }
    }

    #[kani::proof]
    fn verify_dst_mac() {
        // Create non-deterministic stream of bytes up to MAX_FRAME_SIZE
        let mut bytes: [u8; MAX_FRAME_SIZE] = kani::Arbitrary::any_array::<MAX_FRAME_SIZE>();

        // Create valid non-deterministic ethernet
        let ethernet = EthernetFrame::from_bytes(bytes.as_mut());
        kani::assume(ethernet.is_ok());
        let mut ethernet = ethernet.unwrap();

        // Verify set_dst_mac
        let mac_bytes: [u8; MAC_ADDR_LEN as usize] = kani::any();
        let dst_mac = MacAddr::from(mac_bytes);
        ethernet.set_dst_mac(dst_mac);

        // Verify dst_mac
        let dst_addr = EthernetFrame::dst_mac(&ethernet);

        // Check for post-conditions

        // MAC addresses should always have 48 bits
        assert_eq!(dst_addr.get_bytes().len(), MAC_ADDR_LEN as usize);

        // Check duality between set_dst_mac and dst_mac operations
        let i: usize = kani::any();
        kani::assume(i < mac_bytes.len());
        assert_eq!(mac_bytes[i], dst_addr.get_bytes()[i]);
    }

    #[kani::proof]
    fn verify_src_mac() {
        // Create non-deterministic stream of bytes up to MAX_FRAME_SIZE
        let mut bytes: [u8; MAX_FRAME_SIZE] = kani::Arbitrary::any_array::<MAX_FRAME_SIZE>();

        // Create valid non-deterministic ethernet
        let ethernet = EthernetFrame::from_bytes(bytes.as_mut());
        kani::assume(ethernet.is_ok());
        let mut ethernet = ethernet.unwrap();

        // Verify set_src_mac
        let mac_bytes: [u8; MAC_ADDR_LEN as usize] = kani::any();
        let src_mac = MacAddr::from(mac_bytes);
        ethernet.set_src_mac(src_mac);

        // Verify src_mac
        let src_addr = EthernetFrame::src_mac(&ethernet);

        // Check for post-conditions

        // MAC addresses should always have 48 bits
        assert_eq!(src_addr.get_bytes().len(), MAC_ADDR_LEN as usize);

        // Check duality between set_src_mac and src_mac operations
        let i: usize = kani::any();
        kani::assume(i < mac_bytes.len());
        assert_eq!(mac_bytes[i], src_addr.get_bytes()[i]);
    }

    #[kani::proof]
    fn verify_src_mac_isolation() {
        // Create non-deterministic stream of bytes up to MAX_FRAME_SIZE
        let mut bytes: [u8; MAX_FRAME_SIZE] = kani::Arbitrary::any_array::<MAX_FRAME_SIZE>();

        // Create valid non-deterministic ethernet
        let ethernet = EthernetFrame::from_bytes(bytes.as_mut());
        kani::assume(ethernet.is_ok());
        let mut ethernet = ethernet.unwrap();

        // Verify set_src_mac
        let mac_bytes: [u8; MAC_ADDR_LEN as usize] = kani::any();
        let src_mac = MacAddr::from(mac_bytes);
        ethernet.set_src_mac(src_mac);

        let payload_offset = ethernet.payload_offset();

        if kani::any() {
            let dst_mac_bytes: [u8; MAC_ADDR_LEN as usize] = kani::any();
            let dst_mac = MacAddr::from(dst_mac_bytes);
            ethernet.set_dst_mac(dst_mac);
        }
        if kani::any() {
            let ethertype_in: u16 = kani::any();
            ethernet.set_ethertype(ethertype_in);
        }

        // Payload info doesn't change
        assert_eq!(ethernet.payload_offset(), payload_offset);

        // Verify src_mac
        let src_addr = EthernetFrame::src_mac(&ethernet);

        // Check for post-conditions

        // MAC addresses should always have 48 bits
        assert_eq!(src_addr.get_bytes().len(), MAC_ADDR_LEN as usize);

        // Check duality between set_src_mac and src_mac operations
        let i: usize = kani::any();
        kani::assume(i < mac_bytes.len());
        assert_eq!(mac_bytes[i], src_addr.get_bytes()[i]);
    }

    #[kani::proof]
    fn verify_ethertype() {
        // Create non-deterministic stream of bytes up to MAX_FRAME_SIZE
        let mut bytes: [u8; MAX_FRAME_SIZE] = kani::Arbitrary::any_array::<MAX_FRAME_SIZE>();

        // Create valid non-deterministic ethernet
        let ethernet = EthernetFrame::from_bytes(bytes.as_mut());
        kani::assume(ethernet.is_ok());
        let mut ethernet = ethernet.unwrap();

        // Verify set_ethertype
        let ethertype_in: u16 = kani::any();
        ethernet.set_ethertype(ethertype_in);

        // Verify ethertype
        let ethertype_out = ethernet.ethertype();

        // Check for post-conditions

        // Check duality between set_ethertype and ethertype operations
        assert_eq!(ethertype_in, ethertype_out);
    }

    #[kani::proof]
    #[kani::unwind(1515)]
    fn verify_payload() {
        // Create non-deterministic stream of bytes up to MAX_FRAME_SIZE
        let mut bytes: [u8; MAX_FRAME_SIZE] = kani::Arbitrary::any_array::<MAX_FRAME_SIZE>();

        // Create valid non-deterministic ethernet
        let ethernet = EthernetFrame::from_bytes(bytes.as_mut());
        kani::assume(ethernet.is_ok());
        let ethernet = ethernet.unwrap();

        // Verify payload_offset
        let payload_offset = ethernet.payload_offset();

        // Verify payload()
        let payload = ethernet.payload();

        // Verify payload_mut
        let payload_mut = ethernet.payload();

        // Check for post-conditions

        // Check payload_offset value
        assert_eq!(payload_offset, PAYLOAD_OFFSET);

        // Check equivalence
        assert_eq!(payload, payload_mut);
    }

    #[kani::proof]
    fn verify_new_with_header() {
        // Create non-deterministic stream of bytes up to MAX_FRAME_SIZE
        let mut bytes: [u8; MAX_FRAME_SIZE] = kani::Arbitrary::any_array::<MAX_FRAME_SIZE>();
        let bytes_length = bytes.len();

        // Create valid non-deterministic dst_mac
        let dst_mac_bytes: [u8; MAC_ADDR_LEN as usize] =
            kani::Arbitrary::any_array::<MAC_ADDR_LEN_USIZE>();
        let dst_mac = MacAddr::from(dst_mac_bytes);

        // Create valid non-deterministic src_mac
        let src_mac_bytes: [u8; MAC_ADDR_LEN as usize] =
            kani::Arbitrary::any_array::<MAC_ADDR_LEN_USIZE>();
        let src_mac = MacAddr::from(src_mac_bytes);

        // Create valid non-deterministic ethertype
        let ethertype: u16 = kani::any();

        // Verify new_with_header
        let frame =
            EthernetFrame::new_with_header(bytes.as_mut(), dst_mac, src_mac, ethertype).unwrap();

        // Check for post-conditions
        assert_eq!(frame.dst_mac(), dst_mac);
        assert_eq!(frame.src_mac(), src_mac);
        assert_eq!(frame.ethertype(), ethertype);
        assert_eq!(frame.len(), bytes_length);
        assert!(frame.is_valid() && (frame.payload().len() == bytes_length - PAYLOAD_OFFSET));
    }

    #[kani::proof]
    fn verify_write_incomplete() {
        // Create non-deterministic stream of bytes up to MAX_FRAME_SIZE
        let mut bytes: [u8; MAX_FRAME_SIZE] = kani::Arbitrary::any_array::<MAX_FRAME_SIZE>();

        // Create valid non-deterministic dst_mac
        let dst_mac_bytes: [u8; MAC_ADDR_LEN as usize] =
            kani::Arbitrary::any_array::<MAC_ADDR_LEN_USIZE>();
        let dst_mac = MacAddr::from(dst_mac_bytes);

        // Create valid non-deterministic src_mac
        let src_mac_bytes: [u8; MAC_ADDR_LEN as usize] =
            kani::Arbitrary::any_array::<MAC_ADDR_LEN_USIZE>();
        let src_mac = MacAddr::from(src_mac_bytes);

        // Create valid non-deterministic ethertype
        let ethertype: u16 = kani::any();

        // Verify write_incomplete
        let incomplete_frame =
            EthernetFrame::write_incomplete(bytes.as_mut(), dst_mac, src_mac, ethertype).unwrap();

        // Check for post-conditions
        assert_eq!(incomplete_frame.inner.dst_mac(), dst_mac);
        assert_eq!(incomplete_frame.inner.src_mac(), src_mac);
        assert_eq!(incomplete_frame.inner.ethertype(), ethertype);
    }

    #[kani::proof]
    #[kani::solver(cadical)]
    fn verify_with_payload_len_unchecked() {
        // Create non-deterministic stream of bytes up to MAX_FRAME_SIZE
        let mut bytes: [u8; MAX_FRAME_SIZE] = kani::Arbitrary::any_array::<MAX_FRAME_SIZE>();

        // Create valid non-deterministic dst_mac
        let dst_mac_bytes: [u8; MAC_ADDR_LEN as usize] =
            kani::Arbitrary::any_array::<MAC_ADDR_LEN_USIZE>();
        let dst_mac = MacAddr::from(dst_mac_bytes);

        // Create valid non-deterministic src_mac
        let src_mac_bytes: [u8; MAC_ADDR_LEN as usize] =
            kani::Arbitrary::any_array::<MAC_ADDR_LEN_USIZE>();
        let src_mac = MacAddr::from(src_mac_bytes);

        // Create valid non-deterministic ethertype
        let ethertype: u16 = kani::any();

        // Create a non-deterministic incomplete frame
        let incomplete_frame =
            EthernetFrame::write_incomplete(bytes.as_mut(), dst_mac, src_mac, ethertype).unwrap();
        let incomplete_frame_payload_offset = incomplete_frame.inner.payload_offset();
        let incomplete_frame_len = incomplete_frame.inner.len();

        // Create a non-deterministic payload_len
        let payload_len: usize = kani::any();
        kani::assume(payload_len <= incomplete_frame_len - incomplete_frame_payload_offset);

        // Verify with_payload_len_unchecked
        let unchecked_frame = incomplete_frame.with_payload_len_unchecked(payload_len);

        // Check for post-conditions
        assert!(unchecked_frame.is_valid());
        assert_eq!(unchecked_frame.dst_mac(), dst_mac);
        assert_eq!(unchecked_frame.src_mac(), src_mac);
        assert_eq!(unchecked_frame.ethertype(), ethertype);
    }
}
