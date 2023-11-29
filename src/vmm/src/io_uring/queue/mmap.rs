// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Error as IOError;
use std::os::unix::io::RawFd;

use vm_memory::mmap::MmapRegionError;

use crate::vstate::memory::MmapRegion;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MmapError {
    /// Os: {0}
    Os(IOError),
    /// BuildMmapRegion: {0}
    BuildMmapRegion(MmapRegionError),
}

pub(crate) fn mmap(size: usize, fd: RawFd, offset: i64) -> Result<MmapRegion, MmapError> {
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let flags = libc::MAP_SHARED | libc::MAP_POPULATE;

    // SAFETY: Safe because values are valid and we check the return value.
    let ptr = unsafe { libc::mmap(std::ptr::null_mut(), size, prot, flags, fd, offset) };
    if (ptr as isize) < 0 {
        return Err(MmapError::Os(IOError::last_os_error()));
    }

    // SAFETY: Safe because the mmap did not return error.
    unsafe {
        MmapRegion::build_raw(ptr.cast::<u8>(), size, prot, flags)
            .map_err(MmapError::BuildMmapRegion)
    }
}
