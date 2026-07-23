// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module with helpers to read/write bytes into slices
pub mod byte_order;
/// Module with network related helpers
pub mod net;
/// Module with external libc functions
pub mod signal;

use std::fs::{File, OpenOptions};
use std::num::Wrapping;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use libc::O_NONBLOCK;

/// How many bits to left-shift by to convert MiB to bytes
const MIB_TO_BYTES_SHIFT: usize = 20;

/// Safely converts a u64 value to a usize value.
/// This bypasses the Clippy lint check because we only support 64-bit platforms.
#[cfg(target_pointer_width = "64")]
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub const fn u64_to_usize(num: u64) -> usize {
    num as usize
}

/// Safely converts a usize value to a u64 value.
/// This bypasses the Clippy lint check because we only support 64-bit platforms.
#[cfg(target_pointer_width = "64")]
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub const fn usize_to_u64(num: usize) -> u64 {
    num as u64
}

/// Converts a usize into a wrapping u32.
#[inline]
pub const fn wrap_usize_to_u32(num: usize) -> Wrapping<u32> {
    Wrapping(((num as u64) & 0xFFFFFFFF) as u32)
}

/// Converts MiB to Bytes
pub const fn mib_to_bytes(mib: usize) -> usize {
    mib << MIB_TO_BYTES_SHIFT
}

/// Converts Bytes to MiB, truncating any remainder
pub const fn bytes_to_mib(bytes: usize) -> usize {
    bytes >> MIB_TO_BYTES_SHIFT
}

/// Align address up to the alignment.
///
/// Works with any integer type (`u64`, `usize`, etc.).
/// `$align` must be a power of two.
#[macro_export]
macro_rules! align_up {
    ($addr:expr, $align:expr) => {{
        assert!($align.is_power_of_two());
        ($addr.wrapping_add($align - 1)) & !($align - 1)
    }};
}

/// Align address down to the alignment.
///
/// Works with any integer type (`u64`, `usize`, etc.).
/// `$align` must be a power of two.
#[macro_export]
macro_rules! align_down {
    ($addr:expr, $align:expr) => {{
        assert!($align.is_power_of_two());
        $addr & !($align - 1)
    }};
}

/// Create and open a file for both reading and writing to it with a O_NONBLOCK flag.
/// In case we open a FIFO, we need all READ, WRITE and O_NONBLOCK in order to not block the process
/// if nobody is consuming the message. Otherwise opening the FIFO with only WRITE and O_NONBLOCK
/// will fail with ENXIO if there is no readier already attached to it.
/// NOTE: writing to a pipe will start failing when reaching 64K of unconsumed content.
pub fn open_file_nonblock(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new()
        .custom_flags(O_NONBLOCK)
        .create(true)
        .read(true)
        .write(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up_already_aligned() {
        assert_eq!(align_up!(0u64, 4096u64), 0);
        assert_eq!(align_up!(4096u64, 4096u64), 4096);
        assert_eq!(align_up!(8192u64, 4096u64), 8192);
        assert_eq!(align_up!(0x20_0000u64, 0x20_0000u64), 0x20_0000); // 2 MiB
    }

    #[test]
    fn test_align_up_rounds_up() {
        assert_eq!(align_up!(1u64, 4096u64), 4096);
        assert_eq!(align_up!(4095u64, 4096u64), 4096);
        assert_eq!(align_up!(4097u64, 4096u64), 8192);
        assert_eq!(align_up!(0x10_0001u64, 0x20_0000u64), 0x20_0000); // 1 MiB + 1 -> 2 MiB
    }

    #[test]
    fn test_align_up_power_of_two_alignments() {
        for shift in 1..20 {
            let align = 1u64 << shift;
            // One byte before alignment boundary rounds up.
            assert_eq!(align_up!(align - 1, align), align);
            // Exact boundary stays.
            assert_eq!(align_up!(align, align), align);
            // One byte after boundary rounds to next.
            assert_eq!(align_up!(align + 1, align), align * 2);
        }
    }

    #[test]
    fn test_align_up_alignment_of_one() {
        // Alignment of 1 is a no-op: every address is 1-aligned.
        assert_eq!(align_up!(0u64, 1u64), 0);
        assert_eq!(align_up!(1u64, 1u64), 1);
        assert_eq!(align_up!(123u64, 1u64), 123);
    }

    #[test]
    fn test_align_up_works_with_usize() {
        let test_cases: &[(usize, usize)] = &[
            (0, 4096),
            (1, 4096),
            (4095, 4096),
            (4096, 4096),
            (4097, 4096),
            (0x1F_FFFF, 0x20_0000),
            (0x20_0000, 0x20_0000),
            (0x20_0001, 0x20_0000),
        ];
        for &(addr, align) in test_cases {
            assert_eq!(
                align_up!(addr, align),
                u64_to_usize(align_up!(usize_to_u64(addr), usize_to_u64(align))),
                "mismatch for addr={addr:#x} align={align:#x}"
            );
        }
    }

    #[test]
    fn test_align_down_already_aligned() {
        assert_eq!(align_down!(0u64, 4096u64), 0);
        assert_eq!(align_down!(4096u64, 4096u64), 4096);
        assert_eq!(align_down!(8192u64, 4096u64), 8192);
        assert_eq!(align_down!(0x20_0000u64, 0x20_0000u64), 0x20_0000); // 2 MiB
    }

    #[test]
    fn test_align_down_rounds_down() {
        assert_eq!(align_down!(1u64, 4096u64), 0);
        assert_eq!(align_down!(4095u64, 4096u64), 0);
        assert_eq!(align_down!(4097u64, 4096u64), 4096);
        assert_eq!(align_down!(0x2F_FFFF_u64, 0x20_0000u64), 0x20_0000); // 3 MiB - 1 -> 2 MiB
    }

    #[test]
    fn test_align_down_power_of_two_alignments() {
        for shift in 1..20 {
            let align = 1u64 << shift;
            // One byte before alignment boundary rounds down.
            assert_eq!(align_down!(align - 1, align), 0);
            // Exact boundary stays.
            assert_eq!(align_down!(align, align), align);
            // One byte after boundary stays at boundary.
            assert_eq!(align_down!(align + 1, align), align);
        }
    }

    #[test]
    fn test_align_down_alignment_of_one() {
        // Alignment of 1 is a no-op: every address is 1-aligned.
        assert_eq!(align_down!(0u64, 1u64), 0);
        assert_eq!(align_down!(1u64, 1u64), 1);
        assert_eq!(align_down!(123u64, 1u64), 123);
    }

    #[test]
    fn test_align_up_and_down_relationship() {
        // For any aligned address, both functions are identity.
        // For non-aligned addresses, align_down < addr < align_up.
        for shift in [12, 16, 21] {
            let align = 1u64 << shift;
            for offset in [1u64, align / 2, align - 1] {
                let addr = align + offset;
                assert_eq!(align_down!(addr, align), align);
                assert_eq!(align_up!(addr, align), align * 2);
            }
        }
    }
}
