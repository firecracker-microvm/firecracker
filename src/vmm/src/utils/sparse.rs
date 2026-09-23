// Copyright 2026 Superserve. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Walking a sparse file's allocated extents.

use std::fs::File;
use std::os::fd::AsRawFd;

/// Call `f(start, end)` for every allocated data extent of `file` within its
/// first `size` bytes, in ascending order. Ends are exclusive; an extent that
/// runs to the end of the file ends at `size`.
pub fn for_each_data_extent(
    file: &File,
    size: u64,
    mut f: impl FnMut(u64, u64),
) -> std::io::Result<()> {
    let fd = file.as_raw_fd();
    let mut off: libc::off_t = 0;
    while (off as u64) < size {
        // SAFETY: fd is a valid open file; SEEK_DATA returns the next data offset
        // at or after `off`, or -1/ENXIO once no data remains.
        let data = unsafe { libc::lseek(fd, off, libc::SEEK_DATA) };
        if data < 0 {
            let err = std::io::Error::last_os_error();
            // ENXIO is the documented "no more data" signal; any other errno is a real
            // failure that must not be mistaken for a fully-scanned (sparse) file.
            if err.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(err);
        }
        // SAFETY: same fd; SEEK_HOLE returns the next hole at or after `data`,
        // or EOF if the extent runs to the end of the file.
        let mut hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            hole = size as libc::off_t;
        }
        let end = (hole as u64).min(size);
        if (data as u64) < end {
            f(data as u64, end);
        }
        off = hole;
    }
    Ok(())
}
