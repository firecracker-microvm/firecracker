// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module with helpers to read/write bytes into slices
pub mod byte_order;
/// Module with network related helpers
pub mod net;
/// Module with external libc functions
pub mod signal;
/// Module with state machine
pub mod sm;

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

/// Align address up to the aligment.
pub const fn align_up(addr: u64, align: u64) -> u64 {
    debug_assert!(align != 0);
    (addr + align - 1) & !(align - 1)
}

/// Align address down to the aligment.
pub const fn align_down(addr: u64, align: u64) -> u64 {
    debug_assert!(align != 0);
    addr & !(align - 1)
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

/// Simple compact version type encoded as `major << 24 | minor << 16 | patch`
/// Encoding as `u32` allows for trivial comparison.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32);

impl Version {
    /// Create new version
    pub const fn new(major: u8, minor: u8, patch: u16) -> Self {
        Self(((major as u32) << 24) | ((minor as u32) << 16) | (patch as u32))
    }

    /// Get the `major` part.
    pub const fn major(self) -> u8 {
        ((self.0 >> 24) & 0xff) as u8
    }

    /// Get the `minor` part.
    pub const fn minor(self) -> u8 {
        ((self.0 >> 16) & 0xff) as u8
    }

    /// Get the `patch` part.
    pub const fn patch(self) -> u16 {
        (self.0 & 0xffff) as u16
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major(), self.minor(), self.patch())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let v = Version::new(42, 69, 1234);
        assert_eq!(v.major(), 42);
        assert_eq!(v.minor(), 69);
        assert_eq!(v.patch(), 1234);
        assert_eq!(v.to_string(), "42.69.1234");

        assert!(Version::new(0, 2, 3) < Version::new(1, 2, 3));
        assert!(Version::new(1, 0, 3) < Version::new(1, 2, 3));
        assert!(Version::new(1, 2, 0) < Version::new(1, 2, 3));
    }
}
