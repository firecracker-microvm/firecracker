// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::common::{VENDOR_ID_AMD, VENDOR_ID_INTEL};
use std::arch::x86_64::__cpuid as host_cpuid;
use std::slice;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    NotSupported,
    Overflow(String),
}

/// Register designations used to get/set specific register values within the brand string buffer.
pub enum Reg {
    EAX = 0,
    EBX = 1,
    ECX = 2,
    EDX = 3,
}

const BRAND_STRING_INTEL: &[u8] = b"Intel(R) Xeon(R) Processor";
const BRAND_STRING_AMD: &[u8] = b"AMD EPYC";

/// A CPUID brand string wrapper, providing some efficient manipulation primitives.
///
/// This is achieved by bypassing the `O(n)` indexing, heap allocation, and the unicode checks
/// done by `std::string::String`.
#[derive(Clone)]
pub struct BrandString {
    /// Flattened buffer, holding an array of 32-bit register values.
    ///
    /// It has the following layout:
    ///   reg_buf[0] = leaf_0x80000002.EAX
    ///   reg_buf[1] = leaf_0x80000002.EBX
    ///   reg_buf[2] = leaf_0x80000002.ECX
    ///   reg_buf[3] = leaf_0x80000002.EDX
    ///   reg_buf[4] = leaf_0x80000003.EAX
    ///   ...
    ///   reg_buf[10] = leaf_0x80000004.ECX
    ///   reg_buf[11] = leaf_0x80000004.EDX
    /// When seen as a byte-array, this buffer holds the ASCII-encoded CPU brand string.
    reg_buf: [u32; BrandString::REG_BUF_SIZE],

    /// Actual string length, in bytes.
    ///
    /// E.g. For "Intel CPU", this would be `strlen("Intel CPU") == 9`.
    len: usize,
}

impl BrandString {
    /// Register buffer size (in number of registers).
    ///
    /// There are 3 leaves (0x800000002 through 0x80000004), each with 4 regs (EAX, EBX, ECX, EDX).
    const REG_BUF_SIZE: usize = 3 * 4;

    /// Max Brand string length, in bytes (also in chars, since it is ASCII-encoded).
    ///
    /// The string is NULL-terminated, so the max string length is actually one byte
    /// less than the buffer size in bytes
    const MAX_LEN: usize = Self::REG_BUF_SIZE * 4 - 1;

    /// Creates an empty brand string (0-initialized)
    fn new() -> Self {
        Self {
            reg_buf: [0; Self::REG_BUF_SIZE],
            len: 0,
        }
    }

    /// Generates the emulated brand string.
    ///
    /// For Intel CPUs, the brand string we expose will be:
    ///    "Intel(R) Xeon(R) Processor @ {host freq}"
    /// where {host freq} is the CPU frequency, as present in the
    /// host brand string (e.g. 4.01GHz).
    ///
    /// For AMD CPUs, the brand string we expose will be AMD EPYC.
    ///
    /// For other CPUs, we'll just expose an empty string.
    ///
    /// This is safe because we know BRAND_STRING_INTEL and BRAND_STRING_AMD to hold valid data
    /// (allowed length and holding only valid ASCII chars).
    pub fn from_vendor_id(vendor_id: &[u8; 12]) -> BrandString {
        match vendor_id {
            VENDOR_ID_INTEL => {
                let mut this = BrandString::from_bytes_unchecked(BRAND_STRING_INTEL);
                if let Ok(host_bstr) = BrandString::from_host_cpuid() {
                    if let Some(freq) = host_bstr.find_freq() {
                        this.push_bytes(b" @ ").unwrap();
                        this.push_bytes(freq)
                            .expect("Unexpected frequency information in host CPUID");
                    }
                }
                this
            }
            VENDOR_ID_AMD => BrandString::from_bytes_unchecked(BRAND_STRING_AMD),
            _ => BrandString::from_bytes_unchecked(b""),
        }
    }

    /// Creates a brand string, initialized from the CPUID leaves 0x80000002 through 0x80000004
    /// of the host CPU.
    pub fn from_host_cpuid() -> Result<Self, Error> {
        let mut this = Self::new();
        let mut cpuid_regs = unsafe { host_cpuid(0x8000_0000) };

        if cpuid_regs.eax < 0x8000_0004 {
            // Brand string not supported by the host CPU
            return Err(Error::NotSupported);
        }

        for leaf in 0x8000_0002..=0x8000_0004 {
            cpuid_regs = unsafe { host_cpuid(leaf) };
            this.set_reg_for_leaf(leaf, Reg::EAX, cpuid_regs.eax);
            this.set_reg_for_leaf(leaf, Reg::EBX, cpuid_regs.ebx);
            this.set_reg_for_leaf(leaf, Reg::ECX, cpuid_regs.ecx);
            this.set_reg_for_leaf(leaf, Reg::EDX, cpuid_regs.edx);
        }

        let mut len = Self::MAX_LEN;
        {
            let this_bytes = this.as_bytes();
            while this_bytes[len - 1] == 0 && len > 0 {
                len -= 1;
            }
        }
        this.len = len;

        Ok(this)
    }

    /// Creates a (custom) brand string, initialized from `src`.
    ///
    /// No checks are performed on the length of `src` or its contents (`src` should be an
    /// ASCII-encoded string).
    #[inline]
    pub fn from_bytes_unchecked(src: &[u8]) -> Self {
        let mut this = Self::new();
        this.len = src.len();
        this.as_bytes_mut()[..src.len()].copy_from_slice(src);
        this
    }

    /// Returns the given register value for the given CPUID leaf.
    ///
    /// `leaf` must be between 0x80000002 and 0x80000004.
    #[inline]
    pub fn get_reg_for_leaf(&self, leaf: u32, reg: Reg) -> u32 {
        // It's ok not to validate parameters here, leaf and reg should
        // both be compile-time constants. If there's something wrong with them,
        // that's a programming error and we should panic anyway.
        self.reg_buf[(leaf - 0x8000_0002) as usize * 4 + reg as usize]
    }

    /// Sets the value for the given leaf/register pair.
    ///
    /// `leaf` must be between 0x80000002 and 0x80000004.
    #[inline]
    fn set_reg_for_leaf(&mut self, leaf: u32, reg: Reg, val: u32) {
        // It's ok not to validate parameters here, leaf and reg should
        // both be compile-time constants. If there's something wrong with them,
        // that's a programming error and we should panic anyway.
        self.reg_buf[(leaf - 0x8000_0002) as usize * 4 + reg as usize] = val;
    }

    /// Gets an immutable `u8` slice view into the brand string buffer.
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        // This is actually safe, because self.reg_buf has a fixed, known size,
        // and also there's no risk of misalignment, since we're downgrading
        // alignment constraints from dword to byte.
        unsafe { slice::from_raw_parts(self.reg_buf.as_ptr() as *const u8, Self::REG_BUF_SIZE * 4) }
    }

    /// Gets a mutable `u8` slice view into the brand string buffer.
    #[inline]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self.reg_buf.as_mut_ptr() as *mut u8, Self::REG_BUF_SIZE * 4)
        }
    }

    /// Asserts whether or not there is enough room to append `src` to the brand string.
    fn check_push(&mut self, src: &[u8]) -> bool {
        src.len() <= Self::MAX_LEN - self.len
    }

    /// Appends `src` to the brand string if there is enough room to append it.
    pub fn push_bytes(&mut self, src: &[u8]) -> Result<(), Error> {
        if !self.check_push(src) {
            // No room to push all of src.
            return Err(Error::Overflow(
                "Appending to the brand string failed.".to_string(),
            ));
        }
        let start = self.len;
        let count = src.len();
        self.len += count;
        self.as_bytes_mut()[start..(start + count)].copy_from_slice(src);
        Ok(())
    }

    /// Searches the brand string for the CPU frequency data it may contain (e.g. 4.01GHz),
    /// and, if found, returns it as an `u8` slice.
    ///
    /// Basically, we're implementing a search for this regex: "([0-9]+\.[0-9]+[MGT]Hz)".
    pub fn find_freq(&self) -> Option<&[u8]> {
        // The algorithm for matching the regular expression above is based
        // on a Moore machine, and 'stage' represents the current state of
        // the machine.
        enum Stages {
            /// Initial state, looking for a digit.
            Initial,
            /// Found integer part of the frequency.
            FoundFreqIntPart,
            /// Found the decimal point.
            FoundFreqDecimalPoint,
            /// Found the decimal part.
            FoundFreqDecimalPart,
            /// Found the unit size.
            FoundFreqUnitSize,
            /// Found the H in 'Hz'.
            FoundH,
        };

        let mut freq_start = 0;
        let mut decimal_start = 0;

        let mut stage = Stages::Initial;

        for (i, &ch) in self.as_bytes().iter().enumerate() {
            match stage {
                Stages::Initial => {
                    // Looking for one or more digits.
                    if ch.is_ascii_digit() {
                        freq_start = i;
                        stage = Stages::FoundFreqIntPart;
                    }
                }
                Stages::FoundFreqIntPart => {
                    // Looking for a decimal point.
                    if !ch.is_ascii_digit() {
                        if ch == b'.' {
                            stage = Stages::FoundFreqDecimalPoint;
                        } else {
                            stage = Stages::Initial;
                        }
                    }
                }
                Stages::FoundFreqDecimalPoint => {
                    // Looking for the decimal part.
                    if ch.is_ascii_digit() {
                        stage = Stages::FoundFreqDecimalPart;
                        decimal_start = i;
                    } else {
                        stage = Stages::Initial;
                    }
                }
                Stages::FoundFreqDecimalPart => {
                    // Looking for the unit of measure.
                    if !ch.is_ascii_digit() {
                        if ch == b'.' {
                            stage = Stages::FoundFreqDecimalPoint;
                            freq_start = decimal_start;
                        } else if ch == b'M' || ch == b'G' || ch == b'T' {
                            stage = Stages::FoundFreqUnitSize;
                        } else {
                            stage = Stages::Initial;
                        }
                    }
                }
                Stages::FoundFreqUnitSize => {
                    // Looking for the 'H' in 'Hz'.
                    if ch == b'H' {
                        stage = Stages::FoundH;
                    } else if ch.is_ascii_digit() {
                        stage = Stages::FoundFreqIntPart;
                        freq_start = i;
                    } else {
                        stage = Stages::Initial;
                    }
                }
                Stages::FoundH => {
                    // Looking for the 'z' in 'Hz'.
                    // If found, we stop the search and return the slice.
                    if ch == b'z' {
                        let freq_end = i + 1;
                        return Some(&self.as_bytes()[freq_start..freq_end]);
                    } else if ch.is_ascii_digit() {
                        stage = Stages::FoundFreqIntPart;
                        freq_start = i;
                    } else {
                        stage = Stages::Initial;
                    }
                }
            };
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::iter::repeat;

    use super::*;

    #[test]
    fn test_brand_string() {
        #[inline]
        fn pack_u32(src: &[u8]) -> u32 {
            assert!(src.len() >= 4);
            u32::from(src[0])
                | (u32::from(src[1]) << 8)
                | (u32::from(src[2]) << 16)
                | (u32::from(src[3]) << 24)
        }

        const TEST_STR: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut bstr = BrandString::from_bytes_unchecked(TEST_STR);

        // Test the immutable bitwise casts
        //
        {
            for i in 0_usize..=1_usize {
                let eax_offs = (4 * 4) * i;
                let ebx_offs = (4 * 4) * i + 4;
                let ecx_offs = (4 * 4) * i + 8;
                let edx_offs = (4 * 4) * i + 12;
                assert_eq!(
                    bstr.get_reg_for_leaf(0x8000_0002 + i as u32, Reg::EAX),
                    pack_u32(&TEST_STR[eax_offs..(eax_offs + 4)])
                );
                assert_eq!(
                    bstr.get_reg_for_leaf(0x8000_0002 + i as u32, Reg::EBX),
                    pack_u32(&TEST_STR[ebx_offs..(ebx_offs + 4)])
                );
                assert_eq!(
                    bstr.get_reg_for_leaf(0x8000_0002 + i as u32, Reg::ECX),
                    pack_u32(&TEST_STR[ecx_offs..(ecx_offs + 4)])
                );
                assert_eq!(
                    bstr.get_reg_for_leaf(0x8000_0002 + i as u32, Reg::EDX),
                    pack_u32(&TEST_STR[edx_offs..(edx_offs + 4)])
                );
            }
        }

        // Test find_freq() failure path
        //
        assert!(bstr.find_freq().is_none());

        // Test mutable bitwise casting and finding the frequency substring
        //
        bstr.set_reg_for_leaf(0x8000_0003, Reg::EBX, pack_u32(b"5.20"));
        bstr.set_reg_for_leaf(0x8000_0003, Reg::ECX, pack_u32(b"GHz "));
        assert_eq!(bstr.find_freq().unwrap(), b"5.20GHz");

        let _overflow: [u8; 50] = [b'a'; 50];

        // Test BrandString::check_push()
        //
        bstr = BrandString::new();
        assert!(bstr.check_push(b"Hello"));
        bstr.push_bytes(b"Hello").unwrap();
        assert!(bstr.check_push(b", world!"));
        bstr.push_bytes(b", world!").unwrap();

        assert!(!bstr.check_push(&_overflow));

        // Test BrandString::push_bytes()
        //
        let actual_len = bstr.as_bytes().len();
        let mut old_bytes: Vec<u8> = repeat(0).take(actual_len).collect();
        old_bytes.copy_from_slice(bstr.as_bytes());
        assert_eq!(
            bstr.push_bytes(&_overflow),
            Err(Error::Overflow(
                "Appending to the brand string failed.".to_string()
            ))
        );
        assert!(bstr.as_bytes().to_vec() == old_bytes);

        // Test BrandString::from_host_cpuid() and get_reg_for_leaf()
        //
        match BrandString::from_host_cpuid() {
            Ok(bstr) => {
                for leaf in 0x8000_0002..=0x8000_0004_u32 {
                    let host_regs = unsafe { host_cpuid(leaf) };
                    assert_eq!(bstr.get_reg_for_leaf(leaf, Reg::EAX), host_regs.eax);
                    assert_eq!(bstr.get_reg_for_leaf(leaf, Reg::EBX), host_regs.ebx);
                    assert_eq!(bstr.get_reg_for_leaf(leaf, Reg::ECX), host_regs.ecx);
                    assert_eq!(bstr.get_reg_for_leaf(leaf, Reg::EDX), host_regs.edx);
                }
            }
            Err(Error::NotSupported) => {
                // from_host_cpuid() should only fail if the host CPU doesn't support
                // CPUID leaves up to 0x80000004, so let's make sure that's what happened.
                let host_regs = unsafe { host_cpuid(0x8000_0000) };
                assert!(host_regs.eax < 0x8000_0004);
            }
            _ => panic!("This function should not return another type of error"),
        }

        // Test BrandString::from_vendor_id()
        let bstr = BrandString::from_vendor_id(VENDOR_ID_INTEL);
        assert!(bstr.as_bytes().starts_with(BRAND_STRING_INTEL));
        let bstr = BrandString::from_vendor_id(VENDOR_ID_AMD);
        assert!(bstr.as_bytes().starts_with(BRAND_STRING_AMD));
        let bstr = BrandString::from_vendor_id(b"............");
        assert!(bstr.as_bytes() == vec![b'\0'; 48].as_slice());
    }

    #[test]
    fn test_find_freq_fails() {
        let bstr_thz = BrandString::from_bytes_unchecked(b"5.20THz");
        assert_eq!(bstr_thz.find_freq().unwrap(), b"5.20THz");

        let bstr_unused_end = BrandString::from_bytes_unchecked(b"AAA5.20MHzXz");
        assert_eq!(bstr_unused_end.find_freq().unwrap(), b"5.20MHz");

        let bstr_faulty_unit = BrandString::from_bytes_unchecked(b"5.20BHz ");
        assert!(bstr_faulty_unit.find_freq().is_none());

        let short_bstr = BrandString::from_bytes_unchecked(b"z");
        assert!(short_bstr.find_freq().is_none());

        let skip_from_unit = BrandString::from_bytes_unchecked(b"Mz");
        assert!(skip_from_unit.find_freq().is_none());

        let short_bstr = BrandString::from_bytes_unchecked(b"Hz");
        assert!(short_bstr.find_freq().is_none());

        let short_bstr = BrandString::from_bytes_unchecked(b"GHz");
        assert!(short_bstr.find_freq().is_none());

        let multiple_points_bstr = BrandString::from_bytes_unchecked(b"50.5.20GHz");
        assert_eq!(multiple_points_bstr.find_freq().unwrap(), b"5.20GHz");

        let no_decimal_bstr = BrandString::from_bytes_unchecked(b"5GHz");
        assert!(no_decimal_bstr.find_freq().is_none());

        let interrupted_bstr = BrandString::from_bytes_unchecked(b"500.00M5.20GHz");
        assert_eq!(interrupted_bstr.find_freq().unwrap(), b"5.20GHz");

        let split_bstr = BrandString::from_bytes_unchecked(b"5.30AMHz");
        assert!(split_bstr.find_freq().is_none());

        let long_bstr = BrandString::from_bytes_unchecked(b"1.12bc5.30MaHz2.4.25THz");
        assert_eq!(long_bstr.find_freq().unwrap(), b"4.25THz");

        let found_h_bstr = BrandString::from_bytes_unchecked(b"1.A5.2MH3.20GHx4.30GHz");
        assert_eq!(found_h_bstr.find_freq().unwrap(), b"4.30GHz");
    }
}
