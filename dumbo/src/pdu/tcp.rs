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
    // These values are pretty much only valid in conjunction with the flags_after_ns() function,
    // which returns the byte containing every other flag except NS.
    pub struct Flags: u8 {
        const CWR = 1 << 7;
        const ECE = 1 << 6;
        const URG = 1 << 5;
        const ACK = 1 << 4;
        const PSH = 1 << 3;
        const RST = 1 << 2;
        const SYN = 1 << 1;
        const FIN = 1 << 0;
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    Checksum,
    EmptyPayload,
    HeaderLen,
    MssOption,
    MssRemaining,
    SliceTooShort,
}

// TODO: The implementation of TcpSegment is IPv4 specific in regard to checksum computation. Maybe
// make it more generic at some point.

pub struct TcpSegment<'a, T: 'a> {
    bytes: InnerBytes<'a, T>,
}

impl<'a, T: NetworkBytes> TcpSegment<'a, T> {
    // Here's a useful depiction of the TCP header layout:
    // https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    // (watch out for the stupid MSB 0 bit numbering, which isn't even stated this time)

    #[inline]
    pub fn source_port(&self) -> u16 {
        self.bytes.ntohs_unchecked(SOURCE_PORT_OFFSET)
    }

    #[inline]
    pub fn destination_port(&self) -> u16 {
        self.bytes.ntohs_unchecked(DESTINATION_PORT_OFFSET)
    }

    #[inline]
    pub fn sequence_number(&self) -> u32 {
        self.bytes.ntohl_unchecked(SEQ_NUMBER_OFFSET)
    }

    #[inline]
    pub fn ack_number(&self) -> u32 {
        self.bytes.ntohl_unchecked(ACK_NUMBER_OFFSET)
    }

    #[inline]
    pub fn header_len_rsvd_ns(&self) -> (usize, u8, bool) {
        let value = self.bytes[DATAOFF_RSVD_NS_OFFSET];
        let data_offset = value >> 4;
        let header_len = data_offset as usize * 4;
        let rsvd = value & 0x0e;
        let ns = (value & 1) != 0;
        (header_len, rsvd, ns)
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        self.header_len_rsvd_ns().0
    }

    #[inline]
    pub fn flags_after_ns(&self) -> Flags {
        Flags::from_bits_truncate(self.bytes[FLAGS_AFTER_NS_OFFSET])
    }

    #[inline]
    pub fn window_size(&self) -> u16 {
        self.bytes.ntohs_unchecked(WINDOW_SIZE_OFFSET)
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        self.bytes.ntohs_unchecked(CHECKSUM_OFFSET)
    }

    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        self.bytes.ntohs_unchecked(URG_POINTER_OFFSET)
    }

    #[inline]
    pub fn options_unchecked(&self, header_len: usize) -> &[u8] {
        &self.bytes[OPTIONS_OFFSET..header_len]
    }

    #[inline]
    pub fn payload_unchecked(&self, header_len: usize) -> &[u8] {
        self.bytes.split_at(header_len).1
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.payload_unchecked(self.header_len())
    }

    #[inline]
    pub fn payload_len(&self) -> usize {
        self.len() - self.header_len()
    }

    // More details about TCP checksum computation can be found here:
    // https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
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

    // We only care about the MSS option right now (and only for incoming SYNs, btw). At some point
    // we might want to have a more general parsing framework.
    // All TCP options (besides EOL and NOP) are encoded using x bytes (x >= 2), where the first
    // byte represents the option kind, the second is the option length (including these first two
    // bytes), and finally the next x - 2 bytes represent option data. The length of the MSS option
    // is 4, so the option data encodes an u16 in network order.
    pub fn parse_mss_option(&self, header_len: usize) -> Result<Option<NonZeroU16>, Error> {
        let b = self.options_unchecked(header_len);
        let mut i = 0;
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

    #[inline]
    fn from_bytes_unchecked(bytes: T) -> Self {
        TcpSegment {
            bytes: InnerBytes::new(bytes),
        }
    }

    // If we want to verify the checksum, we need to provide the src and dst IPv4 addresses.
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
    #[inline]
    pub fn set_source_port(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(SOURCE_PORT_OFFSET, value);
        self
    }

    #[inline]
    pub fn set_destination_port(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(DESTINATION_PORT_OFFSET, value);
        self
    }

    #[inline]
    pub fn set_sequence_number(&mut self, value: u32) -> &mut Self {
        self.bytes.htonl_unchecked(SEQ_NUMBER_OFFSET, value);
        self
    }

    #[inline]
    pub fn set_ack_number(&mut self, value: u32) -> &mut Self {
        self.bytes.htonl_unchecked(ACK_NUMBER_OFFSET, value);
        self
    }

    // Header_len should be a multiple of 4. Reserved is implicitly set to 0b000.
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

    #[inline]
    pub fn set_flags_after_ns(&mut self, flags: Flags) -> &mut Self {
        self.bytes[FLAGS_AFTER_NS_OFFSET] = flags.bits();
        self
    }

    #[inline]
    pub fn set_window_size(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(WINDOW_SIZE_OFFSET, value);
        self
    }

    #[inline]
    pub fn set_checksum(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(CHECKSUM_OFFSET, value);
        self
    }

    #[inline]
    pub fn set_urgent_pointer(&mut self, value: u16) -> &mut Self {
        self.bytes.htons_unchecked(URG_POINTER_OFFSET, value);
        self
    }

    #[inline]
    pub fn payload_mut_unchecked(&mut self, header_len: usize) -> &mut [u8] {
        self.bytes.split_at_mut(header_len).1
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len();
        self.payload_mut_unchecked(header_len)
    }

    // This writes an entire segment.
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

    /*
     An incomplete segment is missing the source port, destination port, and checksum fields (which
     are often available at lower levels in the stack). This function writes the rest of the
     segment, including data (when available). Since we only support the MSS option for now, we're
     not terribly generic in that regard. The NS flag and urgent pointer are set to 0 (we don't have
     any plans of using the URG flag either). A few words about the less self-explanatory
     parameters:
     - When mss_option.is_some(), we write a MSS option with the specified value to the header.
     - When payload.is_some(), we attempt to write as much data as possible into the payload. The
     parameter is a tuple containing a buffer we can read from, and the maximum allowed size of the
     payload (restricted by factors such as flow control).
     - mss_remaining represents how much bytes we can use for the TCP header + data. We need this
     parameter because the MSS definition is a bit tricky; its value represents the largest amount
     of data allowed to be sent on a single TCP segment. However, if any IP or TCP options are
     present, we have to subtract their combined length from the MSS. Thus, mss_remaining represents
     the remaining MSS after IP options are considered (it will be equal to the original MSS
     pretty much every time; as someone once said, "IP options are not an option").
    */

    // This is marked inline because a lot of code vanishes after constant folding when
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
    // We skip checksum computation if compute_checksum == None.
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
                p.parse_mss_option(header_len),
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
