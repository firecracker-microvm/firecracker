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
use std::result::Result;

use libc::O_NONBLOCK;

/// How many bits to left-shift by to convert MiB to bytes
const MIB_TO_BYTES_SHIFT: usize = 20;

/// Return the default page size of the platform, in bytes.
pub fn get_page_size() -> Result<usize, vmm_sys_util::errno::Error> {
    // SAFETY: Safe because the parameters are valid.
    match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        -1 => Err(vmm_sys_util::errno::Error::last()),
        ps => Ok(usize::try_from(ps).unwrap()),
    }
}

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

/// Create and open a File for writing to it.
/// In case we open a FIFO, in order to not block the instance if nobody is consuming the message
/// that is flushed to it, we are opening it with `O_NONBLOCK` flag.
/// In this case, writing to a pipe will start failing when reaching 64K of unconsumed content.
pub fn open_file_write_nonblock(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new()
        .custom_flags(O_NONBLOCK)
        .create(true)
        .write(true)
        .open(path)
}
