//! Contains support for parsing and writing IPv4 packets.
//!
//! A picture of the IPv4 packet header can be found [here] (watch out for the MSB 0 bit numbering).
//!
//! [here]: https://en.wikipedia.org/wiki/IPv4#Packet_structure

use std::convert::From;
use std::net::Ipv4Addr;
use std::result::Result;

use pdu::bytes::{InnerBytes, NetworkBytes, NetworkBytesMut};
use pdu::ethernet;
use pdu::Incomplete;

const VERSION_AND_IHL_OFFSET: usize = 0;
const DSCP_AND_ECN_OFFSET: usize = 1;
const TOTAL_LEN_OFFSET: usize = 2;
const IDENTIFICATION_OFFSET: usize = 4;
const FLAGS_AND_FRAGMENTOFF_OFFSET: usize = 6;
const TTL_OFFSET: usize = 8;
const PROTOCOL_OFFSET: usize = 9;
const HEADER_CHECKSUM_OFFSET: usize = 10;
const SOURCE_ADDRESS_OFFSET: usize = 12;
const DESTINATION_ADDRESS_OFFSET: usize = 16;
const OPTIONS_OFFSET: usize = 20;

const IPV4_VERSION: u8 = 0x04;
const DEFAULT_TTL: u8 = 200;

/// The IP protocol number associated with TCP.
pub const PROTOCOL_TCP: u8 = 0x06;

/// Describes the errors which may occur while handling IPv4 packets.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// The header checksum is invalid.
    Checksum,
    /// The header length is invalid.
    HeaderLen,
    /// The total length of the packet is invalid.
    InvalidTotalLen,
    /// The length of the given slice does not match the length of the packet.
    SliceExactLength,
    /// The length of the given slice is less than the IPv4 header length.
    SliceTooShort,
    /// The version header field is invalid.
    Version,
}

/// Interprets the inner bytes as an IPv4 packet.
pub struct IPv4Packet<'a, T: 'a> {
    bytes: InnerBytes<'a, T>,
}

impl<'a, T: NetworkBytes> IPv4Packet<'a, T> {
    /// Interpret `bytes` as an IPv4Packet without checking the validity of the header fields, and
    /// the length of the inner byte sequence.
    ///
    /// # Panics
    ///
    /// This method does not panic, but further method calls on the resulting object may panic if
    /// `bytes` contains invalid input.
    #[inline]
    pub fn from_bytes_unchecked(bytes: T) -> Self {
        IPv4Packet {
            bytes: InnerBytes::new(bytes),
        }
    }

    /// Attempts to interpret `bytes` as an IPv4 packet, checking the validity of the header fields
    /// and the length of the inner byte sequence.
    pub fn from_bytes(bytes: T, verify_checksum: bool) -> Result<Self, Error> {
        let bytes_len = bytes.len();

        if bytes_len < OPTIONS_OFFSET {
            return Err(Error::SliceTooShort);
        }

        let packet = IPv4Packet::from_bytes_unchecked(bytes);

        let (version, header_len) = packet.version_and_header_len();

        if version != IPV4_VERSION {
            return Err(Error::Version);
        }

        let total_len = packet.total_len() as usize;

        if total_len < header_len {
            return Err(Error::InvalidTotalLen);
        }

        if total_len != bytes_len {
            return Err(Error::SliceExactLength);
        }

        if header_len < OPTIONS_OFFSET {
            return Err(Error::HeaderLen);
        }

        // We ignore the TTL field since only routers should care about it. An end host has no
        // reason really to discard an otherwise valid packet.

        if verify_checksum && packet.compute_checksum_unchecked(header_len) != 0 {
            return Err(Error::Checksum);
        }

        Ok(packet)
    }

    /// Returns the value of the `version` header field, and the header length.
    ///
    /// This method returns the actual length (in bytes) of the header, and not the value of the
    /// `ihl` header field).
    #[inline]
    pub fn version_and_header_len(&self) -> (u8, usize) {
        let x = self.bytes[VERSION_AND_IHL_OFFSET];
        let ihl = x & 0x0f;
        let header_len = (ihl << 2) as usize;
        (x >> 4, header_len)
    }

    /// Returns the packet header length (in bytes).
    #[inline]
    pub fn header_len(&self) -> usize {
        let (_, header_len) = self.version_and_header_len();
        header_len
    }

    /// Returns the values of the `dscp` and `ecn` header fields.
    #[inline]
    pub fn dscp_and_ecn(&self) -> (u8, u8) {
        let x = self.bytes[DSCP_AND_ECN_OFFSET];
        (x >> 2, x & 0b11)
    }

    /// Returns the value of the 'total length' header field.
    #[inline]
    pub fn total_len(&self) -> u16 {
        self.bytes.ntohs_unchecked(TOTAL_LEN_OFFSET)
    }

    /// Returns the value of the `identification` header field.
    #[inline]
    pub fn identification(&self) -> u16 {
        self.bytes.ntohs_unchecked(IDENTIFICATION_OFFSET)
    }

    /// Returns the values of the `flags` and `fragment offset` header fields.
    #[inline]
    pub fn flags_and_fragment_offset(&self) -> (u8, u16) {
        let x = self.bytes.ntohs_unchecked(FLAGS_AND_FRAGMENTOFF_OFFSET);
        ((x >> 13) as u8, x & 0x1fff)
    }

    /// Returns the value of the `ttl` header field.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.bytes[TTL_OFFSET]
    }

    /// Returns the value of the `protocol` header field.
    #[inline]
    pub fn protocol(&self) -> u8 {
        self.bytes[PROTOCOL_OFFSET]
    }

    /// Returns the value of the `header checksum` header field.
    #[inline]
    pub fn header_checksum(&self) -> u16 {
        self.bytes.ntohs_unchecked(HEADER_CHECKSUM_OFFSET)
    }

    /// Returns the source IPv4 address of the packet.
    #[inline]
    pub fn source_address(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.bytes.ntohl_unchecked(SOURCE_ADDRESS_OFFSET))
    }

    /// Returns the destination IPv4 address of the packet.
    #[inline]
    pub fn destination_address(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.bytes.ntohl_unchecked(DESTINATION_ADDRESS_OFFSET))
    }

    /// Returns a byte slice containing the payload, using the given header length value to compute
    /// the payload offset.
    ///
    /// # Panics
    ///
    /// This method may panic if the value of `header_len` is invalid.
    #[inline]
    pub fn payload_unchecked(&self, header_len: usize) -> &[u8] {
        self.bytes.split_at(header_len).1
    }

    /// Returns a byte slice that contains the payload of the packet.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.payload_unchecked(self.header_len())
    }

    /// Returns the length of the inner byte sequence.
    ///
    /// This is equal to the output of the `total_len()` method for properly constructed instances
    /// of `IPv4Packet`.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Computes and returns the packet header checksum using the provided header length.
    ///
    /// A nice description of how this works can be found [here]. May panic for invalid values of
    /// `header_len`.
    ///
    /// # Panics
    ///
    /// This method may panic if the value of `header_len` is invalid.
    ///
    /// [here]: https://en.wikipedia.org/wiki/IPv4_header_checksum
    pub fn compute_checksum_unchecked(&self, header_len: usize) -> u16 {
        let mut sum = 0u32;
        for i in 0..header_len / 2 {
            sum += self.bytes.ntohs_unchecked(i * 2) as u32;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Computes and returns the packet header checksum.
    #[inline]
    pub fn compute_checksum(&self) -> u16 {
        self.compute_checksum_unchecked(self.header_len())
    }
}

impl<'a, T: NetworkBytesMut> IPv4Packet<'a, T> {
    /// Attempts to write an IPv4 packet header to `buf`, making sure there is enough space.
    ///
    /// This method returns an incomplete packet, because the size of the payload might be unknown
    /// at this point. IP options are not allowed, which means `header_len == OPTIONS_OFFSET`. The
    /// `dscp`, `ecn`, `identification`, `flags`, and `fragment_offset` fields are set to 0. The
    /// `ttl` is set to a default value. The `total_len` and `checksum` fields will be set when
    /// the length of the incomplete packet is determined.
    pub fn write_header(
        buf: T,
        protocol: u8,
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> Result<Incomplete<Self>, Error> {
        if buf.len() < OPTIONS_OFFSET {
            return Err(Error::SliceTooShort);
        }
        let mut packet = IPv4Packet::from_bytes_unchecked(buf);
        packet
            .set_version_and_header_len(IPV4_VERSION, OPTIONS_OFFSET)
            .set_dscp_and_ecn(0, 0)
            .set_identification(0)
            .set_flags_and_fragment_offset(0, 0)
            .set_ttl(DEFAULT_TTL)
            .set_protocol(protocol)
            .set_source_address(src_addr)
            .set_destination_address(dst_addr);

        Ok(Incomplete::new(packet))
    }

    /// Sets the values of the `version` and `ihl` header fields (the latter is computed from the
    /// value of `header_len`).
    #[inline]
    pub fn set_version_and_header_len(&mut self, version: u8, header_len: usize) -> &mut Self {
        let version = version << 4;
        let ihl = ((header_len as u8) >> 2) & 0xf;
        self.bytes[VERSION_AND_IHL_OFFSET] = version | ihl;
        self
    }

    /// Sets the values of the `dscp` and `ecn` header fields.
    #[inline]
    pub fn set_dscp_and_ecn(&mut self, dscp: u8, ecn: u8) -> &mut Self {
        self.bytes[DSCP_AND_ECN_OFFSET] = (dscp << 2) | ecn;
        self
    }

    /// Sets the value of the `total length` header field.
    #[inline]
    pub fn set_total_len(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(TOTAL_LEN_OFFSET, value);
        self
    }

    /// Sets the value of the `identification` header field.
    #[inline]
    pub fn set_identification(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(IDENTIFICATION_OFFSET, value);
        self
    }

    /// Sets the values of the `flags` and `fragment offset` header fields.
    #[inline]
    pub fn set_flags_and_fragment_offset(&mut self, flags: u8, fragment_offset: u16) -> &mut Self {
        let value = ((flags as u16) << 13) | fragment_offset;
        self.bytes
            .htons_unchecked(FLAGS_AND_FRAGMENTOFF_OFFSET, value);
        self
    }

    /// Sets the value of the `ttl` header field.
    #[inline]
    pub fn set_ttl(&mut self, value: u8) -> &mut Self {
        self.bytes[TTL_OFFSET] = value;
        self
    }

    /// Sets the value of the `protocol` header field.
    #[inline]
    pub fn set_protocol(&mut self, value: u8) -> &mut Self {
        self.bytes[PROTOCOL_OFFSET] = value;
        self
    }

    /// Sets the value of the `header checksum` header field.
    #[inline]
    pub fn set_header_checksum(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(HEADER_CHECKSUM_OFFSET, value);
        self
    }

    /// Sets the source address of the packet.
    #[inline]
    pub fn set_source_address(&mut self, addr: Ipv4Addr) -> &mut Self {
        self.bytes
            .htonl_unchecked(SOURCE_ADDRESS_OFFSET, u32::from(addr));
        self
    }

    /// Sets the destination address of the packet.
    #[inline]
    pub fn set_destination_address(&mut self, addr: Ipv4Addr) -> &mut Self {
        self.bytes
            .htonl_unchecked(DESTINATION_ADDRESS_OFFSET, u32::from(addr));
        self
    }

    /// Returns a mutable byte slice representing the payload of the packet, using the provided
    /// header length to compute the payload offset.
    ///
    /// # Panics
    ///
    /// This method may panic if the value of `header_len` is invalid.
    #[inline]
    pub fn payload_mut_unchecked(&mut self, header_len: usize) -> &mut [u8] {
        self.bytes.split_at_mut(header_len).1
    }

    /// Returns a mutable byte slice representing the payload of the packet.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // Can't use self.header_len() as a fn parameter on the following line, because
        // the borrow checker complains. This may change when it becomes smarter.
        let header_len = self.header_len();
        self.payload_mut_unchecked(header_len)
    }
}

/// An incomplete packet is one where the payload length has not been determined yet.
///
/// It can be transformed into an `IPv4Packet` by specifying the size of the payload, and
/// shrinking the inner byte sequence to be as large as the packet itself (this includes setting
/// the `total length` header field).
impl<'a, T: NetworkBytesMut> Incomplete<IPv4Packet<'a, T>> {
    /// Transforms `self` into an `IPv4Packet` based on the supplied header and payload length. May
    /// panic for invalid values of the input parameters.
    ///
    /// # Panics
    ///
    /// This method may panic if the combination of `header_len` and `payload_len` is invalid,
    /// or any of the individual values are invalid.
    #[inline]
    pub fn with_header_and_payload_len_unchecked(
        mut self,
        header_len: usize,
        payload_len: usize,
        compute_checksum: bool,
    ) -> IPv4Packet<'a, T> {
        let total_len = header_len + payload_len;
        {
            let packet = &mut self.inner;

            // This unchecked is fine as long as total_len is smaller than the length of the
            // original slice, which should be the case if our code is not wrong.
            packet.bytes.shrink_unchecked(total_len);
            // Set the total_len.
            packet.set_total_len(total_len as u16);
            if compute_checksum {
                // Ensure this is set to 0 first.
                packet.set_header_checksum(0);
                // Now compute the actual checksum.
                let checksum = packet.compute_checksum_unchecked(header_len);
                packet.set_header_checksum(checksum);
            }
        }
        self.inner
    }

    /// Transforms `self` into an `IPv4Packet` based on the supplied options and payload length.
    ///
    /// # Panics
    ///
    /// This method may panic if the combination of `options_len` and `payload_len` is invalid,
    /// or any of the individual values are invalid.
    #[inline]
    pub fn with_options_and_payload_len_unchecked(
        self,
        options_len: usize,
        payload_len: usize,
        compute_checksum: bool,
    ) -> IPv4Packet<'a, T> {
        let header_len = OPTIONS_OFFSET + options_len;
        self.with_header_and_payload_len_unchecked(header_len, payload_len, compute_checksum)
    }

    /// Transforms `self` into an `IPv4Packet` based on the supplied payload length. May panic for
    /// invalid values of the input parameters.
    ///
    /// # Panics
    ///
    /// This method may panic if the value of `header_len` is invalid.
    #[inline]
    pub fn with_payload_len_unchecked(
        self,
        payload_len: usize,
        compute_checksum: bool,
    ) -> IPv4Packet<'a, T> {
        let header_len = self.inner().header_len();
        self.with_header_and_payload_len_unchecked(header_len, payload_len, compute_checksum)
    }
}

/// This function checks if `buf` may hold an IPv4Packet heading towards the given address. Cannot
/// produce false negatives.
#[inline]
pub fn test_speculative_dst_addr(buf: &[u8], addr: Ipv4Addr) -> bool {
    // The unchecked methods are safe because we actually check the buffer length beforehand.
    if buf.len() >= ethernet::PAYLOAD_OFFSET + OPTIONS_OFFSET {
        let bytes = &buf[ethernet::PAYLOAD_OFFSET..];
        if IPv4Packet::from_bytes_unchecked(bytes).destination_address() == addr {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use net_util::MacAddr;

    use super::*;

    const MAX_HEADER_LEN: usize = 60;

    impl<'a, T: NetworkBytes> fmt::Debug for IPv4Packet<'a, T> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "(IPv4 packet)")
        }
    }

    impl<'a, T: NetworkBytes> fmt::Debug for Incomplete<IPv4Packet<'a, T>> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "(Incomplete IPv4 packet)")
        }
    }

    #[test]
    fn test_set_get() {
        let mut a = [0u8; 100];
        let mut p = IPv4Packet::from_bytes_unchecked(a.as_mut());

        assert_eq!(p.version_and_header_len(), (0, 0));
        p.set_version_and_header_len(IPV4_VERSION, 24);
        assert_eq!(p.version_and_header_len(), (IPV4_VERSION, 24));

        assert_eq!(p.dscp_and_ecn(), (0, 0));
        p.set_dscp_and_ecn(3, 2);
        assert_eq!(p.dscp_and_ecn(), (3, 2));

        assert_eq!(p.total_len(), 0);
        p.set_total_len(123);
        assert_eq!(p.total_len(), 123);

        assert_eq!(p.identification(), 0);
        p.set_identification(1112);
        assert_eq!(p.identification(), 1112);

        assert_eq!(p.flags_and_fragment_offset(), (0, 0));
        p.set_flags_and_fragment_offset(7, 1000);
        assert_eq!(p.flags_and_fragment_offset(), (7, 1000));

        assert_eq!(p.ttl(), 0);
        p.set_ttl(123);
        assert_eq!(p.ttl(), 123);

        assert_eq!(p.protocol(), 0);
        p.set_protocol(114);
        assert_eq!(p.protocol(), 114);

        assert_eq!(p.header_checksum(), 0);
        p.set_header_checksum(1234);
        assert_eq!(p.header_checksum(), 1234);

        let addr = Ipv4Addr::new(10, 11, 12, 13);

        assert_eq!(p.source_address(), Ipv4Addr::from(0));
        p.set_source_address(addr);
        assert_eq!(p.source_address(), addr);

        assert_eq!(p.destination_address(), Ipv4Addr::from(0));
        p.set_destination_address(addr);
        assert_eq!(p.destination_address(), addr);
    }

    #[test]
    fn test_constructors() {
        // We fill this with 1 to notice if the appropriate values get zeroed out.
        let mut buf = [1u8; 100];

        let src = Ipv4Addr::new(10, 100, 11, 21);
        let dst = Ipv4Addr::new(192, 168, 121, 35);

        let buf_len = buf.len();
        // No IPv4 option support for now.
        let header_len = OPTIONS_OFFSET;
        let payload_len = buf_len - OPTIONS_OFFSET;

        {
            let mut p = IPv4Packet::write_header(buf.as_mut(), PROTOCOL_TCP, src, dst)
                .unwrap()
                .with_header_and_payload_len_unchecked(header_len, payload_len, true);

            assert_eq!(p.version_and_header_len(), (IPV4_VERSION, header_len));
            assert_eq!(p.dscp_and_ecn(), (0, 0));
            assert_eq!(p.total_len() as usize, buf_len);
            assert_eq!(p.identification(), 0);
            assert_eq!(p.flags_and_fragment_offset(), (0, 0));
            assert_eq!(p.ttl(), DEFAULT_TTL);
            assert_eq!(p.protocol(), PROTOCOL_TCP);

            let checksum = p.header_checksum();
            p.set_header_checksum(0);
            let computed_checksum = p.compute_checksum();
            assert_eq!(computed_checksum, checksum);

            p.set_header_checksum(computed_checksum);
            assert_eq!(p.compute_checksum(), 0);

            assert_eq!(p.source_address(), src);
            assert_eq!(p.destination_address(), dst);

            // The mutable borrow of buf will end here.
        }

        assert!(IPv4Packet::from_bytes(buf.as_ref(), true).is_ok());

        // Now let's check some error conditions.

        // Using a helper function here instead of a closure because it's hard (impossible?) to
        // specify lifetime bounds for closure arguments.
        fn p(buf: &mut [u8]) -> IPv4Packet<&mut [u8]> {
            IPv4Packet::from_bytes_unchecked(buf)
        }

        // Just a helper closure.
        let look_for_error = |buf: &[u8], err: Error| {
            assert_eq!(IPv4Packet::from_bytes(buf, true).unwrap_err(), err);
        };

        // Invalid version.
        p(buf.as_mut()).set_version_and_header_len(IPV4_VERSION + 1, header_len);
        look_for_error(buf.as_ref(), Error::Version);

        // Short header length.
        p(buf.as_mut()).set_version_and_header_len(IPV4_VERSION, OPTIONS_OFFSET - 1);
        look_for_error(buf.as_ref(), Error::HeaderLen);

        // Header length too large. We have to add at least 4 here, because the setter converts
        // header_len into the ihl field via division by 4, so anything less will lead to a valid
        // result (the ihl corresponding to IPV4_MAX_HEADER_LEN). When decoding the header_len back
        // from the packet, we'll get a smaller value than OPTIONS_OFFSET, because it wraps around
        // modulo 60, since the ihl field is only four bits wide, and then gets multiplied with 4.
        p(buf.as_mut()).set_version_and_header_len(IPV4_VERSION, MAX_HEADER_LEN + 4);
        look_for_error(buf.as_ref(), Error::HeaderLen);

        // Total length smaller than header length.
        p(buf.as_mut())
            .set_version_and_header_len(IPV4_VERSION, OPTIONS_OFFSET)
            .set_total_len(OPTIONS_OFFSET as u16 - 1);
        look_for_error(buf.as_ref(), Error::InvalidTotalLen);

        // Total len not matching slice length.
        p(buf.as_mut()).set_total_len(buf_len as u16 - 1);
        look_for_error(buf.as_ref(), Error::SliceExactLength);

        // The original packet header should contain a valid checksum.
        assert_eq!(
            p(buf.as_mut())
                .set_total_len(buf_len as u16)
                .compute_checksum(),
            0
        );

        // Let's make it invalid.
        let checksum = p(buf.as_mut()).header_checksum();
        p(buf.as_mut()).set_header_checksum(checksum.wrapping_add(1));
        look_for_error(buf.as_ref(), Error::Checksum);

        // Finally, a couple of tests for a small buffer.
        let mut small_buf = [0u8; 1];

        look_for_error(small_buf.as_ref(), Error::SliceTooShort);

        assert_eq!(
            IPv4Packet::write_header(small_buf.as_mut(), PROTOCOL_TCP, src, dst).unwrap_err(),
            Error::SliceTooShort
        );
    }

    #[test]
    fn test_incomplete() {
        let mut buf = [0u8; 100];
        let src = Ipv4Addr::new(10, 100, 11, 21);
        let dst = Ipv4Addr::new(192, 168, 121, 35);
        let payload_len = 30;
        // This is kinda mandatory, since we don't implement options support yet.
        let options_len = 0;
        let header_len = OPTIONS_OFFSET + options_len;

        {
            let p = IPv4Packet::write_header(buf.as_mut(), PROTOCOL_TCP, src, dst)
                .unwrap()
                .with_payload_len_unchecked(payload_len, true);

            assert_eq!(p.compute_checksum(), 0);
            assert_eq!(p.total_len() as usize, p.len());
            assert_eq!(p.len(), header_len + payload_len);
        }

        {
            let p = IPv4Packet::write_header(buf.as_mut(), PROTOCOL_TCP, src, dst)
                .unwrap()
                .with_options_and_payload_len_unchecked(options_len, payload_len, true);

            assert_eq!(p.compute_checksum(), 0);
            assert_eq!(p.total_len() as usize, p.len());
            assert_eq!(p.len(), header_len + payload_len);
        }
    }

    #[test]
    fn test_speculative() {
        let mut buf = [0u8; 1000];
        let mac = MacAddr::from_bytes_unchecked(&[0; 6]);
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let other_ip = Ipv4Addr::new(5, 6, 7, 8);

        {
            let mut eth =
                ::pdu::ethernet::EthernetFrame::write_incomplete(buf.as_mut(), mac, mac, 0)
                    .unwrap();
            IPv4Packet::from_bytes_unchecked(eth.inner_mut().payload_mut())
                .set_destination_address(ip);
        }
        assert!(test_speculative_dst_addr(buf.as_ref(), ip));

        {
            let mut eth =
                ::pdu::ethernet::EthernetFrame::write_incomplete(buf.as_mut(), mac, mac, 0)
                    .unwrap();
            IPv4Packet::from_bytes_unchecked(eth.inner_mut().payload_mut())
                .set_destination_address(other_ip);
        }
        assert!(!test_speculative_dst_addr(buf.as_ref(), ip));

        let small = [0u8; 1];
        assert!(!test_speculative_dst_addr(small.as_ref(), ip));
    }
}
