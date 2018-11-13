//! Contains support for parsing and writing TCP segments.
//!
//! [Here]'s a useful depiction of the TCP header layout (watch out for the MSB 0 bit numbering.)
//!
//! [Here]: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure

use std::cmp::min;
use std::convert::From;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::result::Result;

use super::bytes::{InnerBytes, NetworkBytes, NetworkBytesMut};
use super::ipv4::PROTOCOL_TCP;
use super::Incomplete;
use ByteBuffer;

const SOURCE_PORT_OFFSET: usize = 0;
const DESTINATION_PORT_OFFSET: usize = 2;
const SEQ_NUMBER_OFFSET: usize = 4;
const ACK_NUMBER_OFFSET: usize = 8;
const DATAOFF_RSVD_NS_OFFSET: usize = 12;
const FLAGS_AFTER_NS_OFFSET: usize = 13;
const WINDOW_SIZE_OFFSET: usize = 14;
const CHECKSUM_OFFSET: usize = 16;
const URG_POINTER_OFFSET: usize = 18;
const OPTIONS_OFFSET: usize = 20;

const MAX_HEADER_LEN: usize = 60;

const OPTION_KIND_EOL: u8 = 0x00;
const OPTION_KIND_NOP: u8 = 0x01;
const OPTION_KIND_MSS: u8 = 0x02;

const OPTION_LEN_MSS: usize = 0x04;

// An arbitrarily chosen value, used for sanity checks.
const MSS_MIN: u16 = 100;

bitflags! {
    /// Represents the TCP header flags, with the exception of `NS`.
    ///
    /// These values are only valid in conjunction with the [`flags_after_ns()`] method (and its
    /// associated setter method), which operates on the header byte containing every other flag
    /// besides `NS`.
    ///
    /// [`flags_after_ns()`]: struct.TcpSegment.html#method.flags_after_ns
    pub struct Flags: u8 {
        /// Congestion window reduced.
        const CWR = 1 << 7;
        /// ECN-echo.
        const ECE = 1 << 6;
        /// Urgent pointer.
        const URG = 1 << 5;
        /// The acknowledgement number field is valid.
        const ACK = 1 << 4;
        /// Push flag.
        const PSH = 1 << 3;
        /// Reset the connection.
        const RST = 1 << 2;
        /// SYN flag.
        const SYN = 1 << 1;
        /// FIN flag.
        const FIN = 1 << 0;
    }
}

/// Describes the errors which may occur while handling TCP segments.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Invalid checksum.
    Checksum,
    /// A payload has been specified for the segment, but the maximum readable length is 0.
    EmptyPayload,
    /// Invalid header length.
    HeaderLen,
    /// The MSS option contains an invalid value.
    MssOption,
    /// The remaining segment length cannot accommodate the MSS option.
    MssRemaining,
    /// The specified slice is shorter than the header length.
    SliceTooShort,
}

// TODO: The implementation of TcpSegment is IPv4 specific in regard to checksum computation. Maybe
// make it more generic at some point.

/// Interprets the inner bytes as a TCP segment.
pub struct TcpSegment<'a, T: 'a> {
    bytes: InnerBytes<'a, T>,
}

impl<'a, T: NetworkBytes> TcpSegment<'a, T> {
    /// Returns the source port.
    #[inline]
    pub fn source_port(&self) -> u16 {
        self.bytes.ntohs_unchecked(SOURCE_PORT_OFFSET)
    }

    /// Returns the destination port.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        self.bytes.ntohs_unchecked(DESTINATION_PORT_OFFSET)
    }

    /// Returns the sequence number.
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        self.bytes.ntohl_unchecked(SEQ_NUMBER_OFFSET)
    }

    /// Returns the acknowledgement number (only valid if the `ACK` flag is set).
    #[inline]
    pub fn ack_number(&self) -> u32 {
        self.bytes.ntohl_unchecked(ACK_NUMBER_OFFSET)
    }

    /// Returns the header length, the value of the reserved bits, and whether the `NS` flag
    /// is set or not.
    #[inline]
    pub fn header_len_rsvd_ns(&self) -> (usize, u8, bool) {
        let value = self.bytes[DATAOFF_RSVD_NS_OFFSET];
        let data_offset = value >> 4;
        let header_len = data_offset as usize * 4;
        let rsvd = value & 0x0e;
        let ns = (value & 1) != 0;
        (header_len, rsvd, ns)
    }

    /// Returns the length of the header.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.header_len_rsvd_ns().0
    }

    /// Returns the TCP header flags, with the exception of `NS`.
    #[inline]
    pub fn flags_after_ns(&self) -> Flags {
        Flags::from_bits_truncate(self.bytes[FLAGS_AFTER_NS_OFFSET])
    }

    /// Returns the value of the `window size` header field.
    #[inline]
    pub fn window_size(&self) -> u16 {
        self.bytes.ntohs_unchecked(WINDOW_SIZE_OFFSET)
    }

    /// Returns the value of the `checksum` header field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.bytes.ntohs_unchecked(CHECKSUM_OFFSET)
    }

    /// Returns the value of the `urgent pointer` header field (only valid if the
    /// `URG` flag is set).
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        self.bytes.ntohs_unchecked(URG_POINTER_OFFSET)
    }

    /// Returns the TCP header options as an `[&u8]` slice.
    ///
    /// # Panics
    ///
    /// This method may panic if the value of `header_len` is invalid.
    #[inline]
    pub fn options_unchecked(&self, header_len: usize) -> &[u8] {
        &self.bytes[OPTIONS_OFFSET..header_len]
    }

    /// Returns a slice which contains the payload of the segment. May panic if the value of
    /// `header_len` is invalid.
    ///
    /// # Panics
    ///
    /// This method may panic if the value of `header_len` is invalid.
    #[inline]
    pub fn payload_unchecked(&self, header_len: usize) -> &[u8] {
        self.bytes.split_at(header_len).1
    }

    /// Returns the length of the segment.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns a slice which contains the payload of the segment.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.payload_unchecked(self.header_len())
    }

    /// Returns the length of the payload.
    #[inline]
    pub fn payload_len(&self) -> usize {
        self.len() - self.header_len()
    }

    /// Computes the TCP checksum of the segment. More details about TCP checksum computation can
    /// be found [here].
    ///
    /// [here]: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
    pub fn compute_checksum(&self, src_addr: Ipv4Addr, dst_addr: Ipv4Addr) -> u16 {
        // TODO: Is u32 enough to prevent overflow for the code in this function? I think so, but it
        // would be nice to double-check.
        let mut sum = 0u32;

        let a = u32::from(src_addr);
        sum += a & 0xffff;
        sum += a >> 16;

        let b = u32::from(dst_addr);
        sum += b & 0xffff;
        sum += b >> 16;

        let len = self.len();
        sum += PROTOCOL_TCP as u32;
        sum += len as u32;

        for i in 0..len / 2 {
            sum += self.bytes.ntohs_unchecked(i * 2) as u32;
        }

        if len % 2 != 0 {
            sum += (self.bytes[len - 1] as u32) << 8;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Parses TCP header options (only `MSS` is supported for now).
    ///
    /// If no error is encountered, returns the `MSS` value, or `None` if the option is not
    /// present.
    ///
    /// # Panics
    ///
    /// This method may panic if the value of `header_len` is invalid.
    pub fn parse_mss_option_unchecked(
        &self,
        header_len: usize,
    ) -> Result<Option<NonZeroU16>, Error> {
        let b = self.options_unchecked(header_len);
        let mut i = 0;

        // All TCP options (except EOL and NOP) are encoded using x bytes (x >= 2), where the first
        // byte represents the option kind, the second is the option length (including these first two
        // bytes), and finally the next x - 2 bytes represent option data. The length of the MSS option
        // is 4, so the option data encodes an u16 in network order.

        // The MSS option is 4 bytes wide, so we need at least 4 more bytes to look for it.
        while i + 3 < b.len() {
            match b[i] {
                OPTION_KIND_EOL => break,
                OPTION_KIND_NOP => {
                    i += 1;
                    continue;
                }
                OPTION_KIND_MSS => {
                    // Read from option data (we skip checking if the len is valid).
                    // TODO: To be super strict, we should make sure there aren't additional MSS
                    // options present (which would be super wrong). Should we be super strict?
                    let mss = b.ntohs_unchecked(i + 2);
                    if mss < MSS_MIN {
                        return Err(Error::MssOption);
                    }
                    // The unwarp() is safe because mms >= MSS_MIN at this point.
                    return Ok(Some(NonZeroU16::new(mss).unwrap()));
                }
                _ => {
                    // Some other option; just skip opt_len bytes in total.
                    i += b[i + 1] as usize;
                    continue;
                }
            }
        }
        Ok(None)
    }

    /// Interprets `bytes` as a TCP segment without any validity checks.
    ///
    /// # Panics
    ///
    /// This method does not panic, but further method calls on the resulting object may panic if
    /// `bytes` contains invalid input.
    #[inline]
    pub fn from_bytes_unchecked(bytes: T) -> Self {
        TcpSegment {
            bytes: InnerBytes::new(bytes),
        }
    }

    /// Attempts to interpret `bytes` as a TCP segment, checking the validity of the header fields.
    ///
    /// The `verify_checksum` parameter must contain the source and destination addresses from the
    /// enclosing IPv4 packet if the TCP checksum must be validated.
    #[inline]
    pub fn from_bytes(
        bytes: T,
        verify_checksum: Option<(Ipv4Addr, Ipv4Addr)>,
    ) -> Result<Self, Error> {
        if bytes.len() < OPTIONS_OFFSET {
            return Err(Error::SliceTooShort);
        }

        let segment = Self::from_bytes_unchecked(bytes);

        // We skip checking if the reserved bits are 0b000 (and a couple of other things).

        let header_len = segment.header_len();

        if header_len < OPTIONS_OFFSET || header_len > min(MAX_HEADER_LEN, segment.len()) {
            return Err(Error::HeaderLen);
        }

        if let Some((src_addr, dst_addr)) = verify_checksum {
            if segment.compute_checksum(src_addr, dst_addr) != 0 {
                return Err(Error::Checksum);
            }
        }

        Ok(segment)
    }
}

impl<'a, T: NetworkBytesMut> TcpSegment<'a, T> {
    /// Sets the source port.
    #[inline]
    pub fn set_source_port(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(SOURCE_PORT_OFFSET, value);
        self
    }

    /// Sets the destination port.
    #[inline]
    pub fn set_destination_port(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(DESTINATION_PORT_OFFSET, value);
        self
    }

    /// Sets the value of the sequence number field.
    #[inline]
    pub fn set_sequence_number(&mut self, value: u32) -> &mut Self {
        self.bytes.htonl_unchecked(SEQ_NUMBER_OFFSET, value);
        self
    }

    /// Sets the value of the acknowledgement number field.
    #[inline]
    pub fn set_ack_number(&mut self, value: u32) -> &mut Self {
        self.bytes.htonl_unchecked(ACK_NUMBER_OFFSET, value);
        self
    }

    /// Sets the value of the `ihl` header field based on `header_len` (which should be a multiple
    /// of 4), clears the reserved bits, and sets the `NS` flag according to the last parameter.
    // TODO: Check that header_len | 0b11 == 0 and the resulting data_offset is valid?
    #[inline]
    pub fn set_header_len_rsvd_ns(&mut self, header_len: usize, ns: bool) -> &mut Self {
        let mut value = (header_len as u8) << 2;
        if ns {
            value |= 1;
        }
        self.bytes[DATAOFF_RSVD_NS_OFFSET] = value;
        self
    }

    /// Sets the value of the header byte containing every TCP flag except `NS`.
    #[inline]
    pub fn set_flags_after_ns(&mut self, flags: Flags) -> &mut Self {
        self.bytes[FLAGS_AFTER_NS_OFFSET] = flags.bits();
        self
    }

    /// Sets the value of the `window size` field.
    #[inline]
    pub fn set_window_size(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(WINDOW_SIZE_OFFSET, value);
        self
    }

    /// Sets the value of the `checksum` field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(CHECKSUM_OFFSET, value);
        self
    }

    /// Sets the value of the `urgent pointer` field.
    #[inline]
    pub fn set_urgent_pointer(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(URG_POINTER_OFFSET, value);
        self
    }

    /// Returns a mutable slice containing the segment payload.
    ///
    /// # Panics
    ///
    /// This method may panic if the value of `header_len` is invalid.
    #[inline]
    pub fn payload_mut_unchecked(&mut self, header_len: usize) -> &mut [u8] {
        self.bytes.split_at_mut(header_len).1
    }

    /// Returns a mutable slice containing the segment payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len();
        self.payload_mut_unchecked(header_len)
    }

    /// Writes a complete TCP segment.
    ///
    /// # Arguments
    ///
    /// * `buf` - Write the segment to this buffer.
    /// * `src_port` - Source port.
    /// * `dst_port` - Destination port.
    /// * `seq_number` - Sequence number.
    /// * `ack_number` - Acknowledgement number.
    /// * `flags_after_ns` - TCP flags to set (except `NS`, which is always set to 0).
    /// * `window_size` - Value to write in the `window size` field.
    /// * `mss_option` - When a value is specified, use it to add a TCP MSS option to the header.
    /// * `mss_remaining` - Represents an upper bound on the payload length (the number of bytes
    ///    used up by things like IP options have to be subtracted from the MSS). There is some
    ///    redundancy looking at this argument and the next one, so we might end up removing
    ///    or changing something.
    /// * `payload` - May contain a buffer which holds payload data and the maximum amount of bytes
    ///    we should read from that buffer. When `None`, the TCP segment will carry no payload.
    /// * `compute_checksum` - May contain the pair addresses from the enclosing IPv4 packet, which
    ///    are required for TCP checksum computation. Skip the checksum altogether when `None`.
    #[inline]
    pub fn write_segment<R: ByteBuffer + ?Sized>(
        buf: T,
        src_port: u16,
        dst_port: u16,
        seq_number: u32,
        ack_number: u32,
        flags_after_ns: Flags,
        window_size: u16,
        mss_option: Option<u16>,
        mss_remaining: u16,
        payload: Option<(&R, usize)>,
        compute_checksum: Option<(Ipv4Addr, Ipv4Addr)>,
    ) -> Result<Self, Error> {
        Ok(Self::write_incomplete_segment(
            buf,
            seq_number,
            ack_number,
            flags_after_ns,
            window_size,
            mss_option,
            mss_remaining,
            payload,
        )?.finalize(src_port, dst_port, compute_checksum))
    }

    /// Writes an incomplete TCP segment, which is missing the `source port`, `destination port`,
    /// and `checksum` fields.
    ///
    /// This method writes the rest of the segment, including data (when available). Only the `MSS`
    /// option is supported for now. The `NS` flag, `URG` flag, and `urgent pointer` field are set
    /// to 0.
    ///
    /// # Arguments
    ///
    /// * `buf` - Write the segment to this buffer.
    /// * `seq_number` - Sequence number.
    /// * `ack_number` - Acknowledgement number.
    /// * `flags_after_ns` - TCP flags to set (except `NS`, which is always set to 0).
    /// * `window_size` - Value to write in the `window size` field.
    /// * `mss_option` - When a value is specified, use it to add a TCP MSS option to the header.
    /// * `mss_remaining` - Represents an upper bound on the payload length (the number of bytes
    ///    used up by things like IP options have to be subtracted from the MSS). There is some
    ///    redundancy looking at this argument and the next one, so we might end up removing
    ///    or changing something.
    /// * `payload` - May contain a buffer which holds payload data and the maximum amount of bytes
    ///    we should read from that buffer. When `None`, the TCP segment will carry no payload.
    // Marked inline because a lot of code vanishes after constant folding when
    // we don't add TCP options, or when mss_remaining is actually a constant, etc.
    #[inline]
    pub fn write_incomplete_segment<R: ByteBuffer + ?Sized>(
        buf: T,
        seq_number: u32,
        ack_number: u32,
        flags_after_ns: Flags,
        window_size: u16,
        mss_option: Option<u16>,
        mss_remaining: u16,
        payload: Option<(&R, usize)>,
    ) -> Result<Incomplete<Self>, Error> {
        let mut mss_left = mss_remaining as usize;

        // We're going to need at least this many bytes.
        let mut segment_len = OPTIONS_OFFSET;

        // The TCP options will require this much more bytes.
        let options_len = if mss_option.is_some() {
            mss_left = mss_left
                .checked_sub(OPTION_LEN_MSS)
                .ok_or(Error::MssRemaining)?;
            OPTION_LEN_MSS
        } else {
            0
        };

        segment_len += options_len;

        if buf.len() < segment_len {
            return Err(Error::SliceTooShort);
        }

        // The unchecked call is safe because buf.len() >= segment_len.
        let mut segment = Self::from_bytes_unchecked(buf);

        segment
            .set_sequence_number(seq_number)
            .set_ack_number(ack_number)
            .set_header_len_rsvd_ns(OPTIONS_OFFSET + options_len, false)
            .set_flags_after_ns(flags_after_ns)
            .set_window_size(window_size)
            .set_urgent_pointer(0);

        // Let's write the MSS option if we have to.
        if let Some(value) = mss_option {
            segment.bytes[OPTIONS_OFFSET] = OPTION_KIND_MSS;
            segment.bytes[OPTIONS_OFFSET + 1] = OPTION_LEN_MSS as u8;
            segment.bytes.htons_unchecked(OPTIONS_OFFSET + 2, value);
        }

        segment_len += if let Some((payload_buf, max_payload_bytes)) = payload {
            let left_to_read = min(payload_buf.len(), max_payload_bytes);

            // The subtraction makes sense because we previously checked that
            // buf.len() >= segment_len.
            let mut room_for_payload = min(segment.len() - segment_len, mss_left);
            room_for_payload = min(room_for_payload, left_to_read);

            if room_for_payload == 0 {
                return Err(Error::EmptyPayload);
            }

            payload_buf.read_to_slice(
                0,
                &mut segment.bytes[segment_len..segment_len + room_for_payload],
            );
            room_for_payload
        } else {
            0
        };

        // This is ok because segment_len <= buf.len().
        segment.bytes.shrink_unchecked(segment_len);

        //Shrink the resulting segment to a slice of exact size, so using self.len() makes sense.
        Ok(Incomplete::new(segment))
    }
}

impl<'a, T: NetworkBytesMut> Incomplete<TcpSegment<'a, T>> {
    /// Transforms `self` into a `TcpSegment<T>` by specifying values for the `source port`,
    /// `destination port`, and (optionally) the information required to compute the TCP checksum.
    pub fn finalize(
        mut self,
        src_port: u16,
        dst_port: u16,
        compute_checksum: Option<(Ipv4Addr, Ipv4Addr)>,
    ) -> TcpSegment<'a, T> {
        self.inner.set_source_port(src_port);
        self.inner.set_destination_port(dst_port);
        if let Some((src_addr, dst_addr)) = compute_checksum {
            // Set this to 0 first.
            self.inner.set_checksum(0);
            let checksum = self.inner.compute_checksum(src_addr, dst_addr);
            self.inner.set_checksum(checksum);
        }
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    impl<'a, T: NetworkBytes> fmt::Debug for TcpSegment<'a, T> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "(TCP segment)")
        }
    }

    impl<'a, T: NetworkBytes> fmt::Debug for Incomplete<TcpSegment<'a, T>> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "(Incomplete TCP segment)")
        }
    }

    #[test]
    fn test_set_get() {
        let mut a = [0u8; 100];
        let mut p = TcpSegment::from_bytes_unchecked(a.as_mut());

        assert_eq!(p.source_port(), 0);
        p.set_source_port(123);
        assert_eq!(p.source_port(), 123);

        assert_eq!(p.destination_port(), 0);
        p.set_destination_port(322);
        assert_eq!(p.destination_port(), 322);

        assert_eq!(p.sequence_number(), 0);
        p.set_sequence_number(1234567);
        assert_eq!(p.sequence_number(), 1234567);

        assert_eq!(p.ack_number(), 0);
        p.set_ack_number(345234);
        assert_eq!(p.ack_number(), 345234);

        assert_eq!(p.header_len_rsvd_ns(), (0, 0, false));
        assert_eq!(p.header_len(), 0);
        // Header_len must be a multiple of 4 here to be valid.
        let header_len = 60;
        p.set_header_len_rsvd_ns(header_len, true);
        assert_eq!(p.header_len_rsvd_ns(), (header_len, 0, true));
        assert_eq!(p.header_len(), header_len);

        assert_eq!(p.flags_after_ns().bits(), 0);
        p.set_flags_after_ns(Flags::SYN | Flags::URG);
        assert_eq!(p.flags_after_ns(), Flags::SYN | Flags::URG);

        assert_eq!(p.window_size(), 0);
        p.set_window_size(60000);
        assert_eq!(p.window_size(), 60000);

        assert_eq!(p.checksum(), 0);
        p.set_checksum(4321);
        assert_eq!(p.checksum(), 4321);

        assert_eq!(p.urgent_pointer(), 0);
        p.set_urgent_pointer(5554);
        assert_eq!(p.urgent_pointer(), 5554);
    }

    #[test]
    fn test_constructors() {
        let mut a = [1u8; 1460];
        let b = [2u8; 1000];
        let c = [3u8; 2000];

        let src_addr = Ipv4Addr::new(10, 1, 2, 3);
        let dst_addr = Ipv4Addr::new(192, 168, 44, 77);
        let src_port = 1234;
        let dst_port = 5678;
        let seq_number = 11111222;
        let ack_number = 34566543;
        let flags_after_ns = Flags::SYN | Flags::RST;
        let window_size = 19999;
        let mss_left = 1460;
        let mss_option = Some(mss_left);
        let payload = Some((b.as_ref(), b.len()));

        let header_len = OPTIONS_OFFSET + OPTION_LEN_MSS;

        let segment_len = {
            let mut p = TcpSegment::write_segment(
                a.as_mut(),
                src_port,
                dst_port,
                seq_number,
                ack_number,
                flags_after_ns,
                window_size,
                mss_option,
                mss_left,
                payload,
                Some((src_addr, dst_addr)),
            ).unwrap();

            assert_eq!(p.source_port(), src_port);
            assert_eq!(p.destination_port(), dst_port);
            assert_eq!(p.sequence_number(), seq_number);
            assert_eq!(p.ack_number(), ack_number);
            assert_eq!(p.header_len_rsvd_ns(), (header_len, 0, false));
            assert_eq!(p.flags_after_ns(), flags_after_ns);
            assert_eq!(p.window_size(), window_size);

            let checksum = p.checksum();
            p.set_checksum(0);
            let computed_checksum = p.compute_checksum(src_addr, dst_addr);
            assert_eq!(checksum, computed_checksum);

            p.set_checksum(checksum);
            assert_eq!(p.compute_checksum(src_addr, dst_addr), 0);

            assert_eq!(p.urgent_pointer(), 0);

            {
                let options = p.options_unchecked(header_len);
                assert_eq!(options.len(), OPTION_LEN_MSS);
                assert_eq!(options[0], OPTION_KIND_MSS);
                assert_eq!(options[1], OPTION_LEN_MSS as u8);
                assert_eq!(options.ntohs_unchecked(2), mss_left);
            }

            // Payload was smaller than mss_left after options.
            assert_eq!(p.len(), header_len + b.len());

            p.len()
            // Mutable borrow of a goes out of scope.
        };

        {
            let p = TcpSegment::from_bytes(&a[..segment_len], Some((src_addr, dst_addr))).unwrap();
            assert_eq!(
                p.parse_mss_option_unchecked(header_len),
                Ok(Some(NonZeroU16::new(mss_left as u16).unwrap()))
            );
        }

        // Let's quickly see what happens when the payload buf is larger than our mutable slice.
        {
            let len = TcpSegment::write_segment(
                a.as_mut(),
                src_port,
                dst_port,
                seq_number,
                ack_number,
                flags_after_ns,
                window_size,
                mss_option,
                mss_left,
                Some((c.as_ref(), c.len())),
                Some((src_addr, dst_addr)),
            ).unwrap()
            .len();

            assert_eq!(len, mss_left as usize);
        }

        // Now let's test the error value for from_bytes().

        // Using a helper function here instead of a closure because it's hard (impossible?) to
        // specify lifetime bounds for closure arguments.
        fn p(buf: &mut [u8]) -> TcpSegment<&mut [u8]> {
            TcpSegment::from_bytes_unchecked(buf)
        }

        // Just a helper closure.
        let look_for_error = |buf: &[u8], err: Error| {
            assert_eq!(
                TcpSegment::from_bytes(buf, Some((src_addr, dst_addr))).unwrap_err(),
                err
            );
        };

        // Header length too short.
        p(a.as_mut()).set_header_len_rsvd_ns(OPTIONS_OFFSET.checked_sub(1).unwrap(), false);
        look_for_error(a.as_ref(), Error::HeaderLen);

        // Header length too large.
        p(a.as_mut()).set_header_len_rsvd_ns(MAX_HEADER_LEN.checked_add(4).unwrap(), false);
        look_for_error(a.as_ref(), Error::HeaderLen);

        // The previously set checksum should be valid.
        assert_eq!(
            p(a.as_mut())
                .set_header_len_rsvd_ns(header_len, false)
                .compute_checksum(src_addr, dst_addr),
            0
        );

        // Let's make it invalid.
        let checksum = p(a.as_mut()).checksum();
        p(a.as_mut()).set_checksum(checksum.wrapping_add(1));
        look_for_error(a.as_ref(), Error::Checksum);

        // Now we use a very small buffer.
        let mut small_buf = [0u8; 1];
        look_for_error(small_buf.as_ref(), Error::SliceTooShort);

        assert_eq!(
            TcpSegment::write_segment(
                small_buf.as_mut(),
                src_port,
                dst_port,
                seq_number,
                ack_number,
                flags_after_ns,
                window_size,
                mss_option,
                mss_left,
                payload,
                Some((src_addr, dst_addr)),
            ).unwrap_err(),
            Error::SliceTooShort
        );

        // Make sure we get the proper error for an insufficient value of mss_remaining.
        assert_eq!(
            TcpSegment::write_segment(
                small_buf.as_mut(),
                src_port,
                dst_port,
                seq_number,
                ack_number,
                flags_after_ns,
                window_size,
                mss_option,
                0,
                payload,
                Some((src_addr, dst_addr)),
            ).unwrap_err(),
            Error::MssRemaining
        );
    }
}
