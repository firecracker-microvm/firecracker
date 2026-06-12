// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utilities for reading /proc/self/pagemap to track dirty pages.

#![allow(clippy::cast_possible_wrap)]

use std::fs::File;
use std::os::unix::io::AsRawFd;

use crate::arch::host_page_size;

const PAGEMAP_ENTRY_SIZE: usize = 8;

/// Errors related to pagemap operations
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PagemapError {
    /// Failed to open /proc/self/pagemap: {0}
    OpenPagemap(#[source] std::io::Error),
    /// Failed to read pagemap entry: {0}
    ReadEntry(#[source] std::io::Error),
    /// Failed to open /proc/self/clear_refs: {0}
    OpenClearRefs(#[source] std::io::Error),
    /// Failed to clear soft-dirty bits: {0}
    ClearSoftDirty(#[source] std::io::Error),
}

/// Represents a single entry in /proc/pid/pagemap.
///
/// Each virtual page has an 8-byte entry with the following layout:
/// - Bits 0-54:  Page frame number (PFN) if present
/// - Bit 55:     Page is soft-dirty (written to since last clear)
/// - Bit 56:     Page is exclusively mapped
/// - Bit 57:     Page is write-protected via userfaultfd
/// - Bit 58:     Unused
/// - Bit 59-60:  Unused
/// - Bit 61:     Page is file-page or shared-anon
/// - Bit 62:     Page is swapped
/// - Bit 63:     Page is present in RAM
#[derive(Debug, Clone, Copy)]
pub struct PagemapEntry {
    raw: u64,
}

impl PagemapEntry {
    /// Create a PagemapEntry from bytes (little-endian)
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self {
            raw: u64::from_ne_bytes(bytes),
        }
    }

    /// Check if page is write-protected via userfaultfd
    pub fn is_write_protected(&self) -> bool {
        (self.raw & (1u64 << 57)) != 0
    }

    /// Check if page is present in RAM (bit 63)
    pub fn is_present(&self) -> bool {
        (self.raw & (1u64 << 63)) != 0
    }
}

/// Reader for /proc/self/pagemap
#[derive(Debug)]
pub struct PagemapReader {
    pagemap_fd: File,
}

impl PagemapReader {
    /// Create a new PagemapReader
    pub fn new(_page_size: usize) -> Result<Self, PagemapError> {
        let pagemap_fd = File::open("/proc/self/pagemap").map_err(PagemapError::OpenPagemap)?;

        Ok(Self { pagemap_fd })
    }

    /// Check if a single page is dirty (write-protected bit cleared).
    ///
    /// Checks the first host page (4K) of the guest page at the given address.
    /// For huge pages, all host pages within the huge page typically have the same
    /// dirty status, so sampling the first is sufficient.
    ///
    /// # Arguments
    /// * `virt_addr` - Virtual address of the page to check
    ///
    /// # Returns
    /// True if the page is present and write-protected bit is cleared (dirty).
    pub fn is_page_dirty(&self, virt_addr: usize) -> Result<bool, PagemapError> {
        // Pagemap always uses host (4K) page size
        let host_page_size = host_page_size();

        // Calculate offset for this virtual page (using host page size)
        let host_vpn = virt_addr / host_page_size;
        let offset = (host_vpn * PAGEMAP_ENTRY_SIZE) as i64;

        let mut entry_bytes = [0u8; 8];

        // SAFETY: pread is safe as long as the fd is valid and the buffer is properly sized
        let ret = unsafe {
            libc::pread(
                self.pagemap_fd.as_raw_fd(),
                entry_bytes.as_mut_ptr().cast(),
                PAGEMAP_ENTRY_SIZE,
                offset,
            )
        };

        if ret != PAGEMAP_ENTRY_SIZE as isize {
            return Err(PagemapError::ReadEntry(std::io::Error::last_os_error()));
        }

        let entry = PagemapEntry::from_bytes(entry_bytes);

        // Page must be present and the write_protected bit cleared (indicating it was written to)
        Ok(entry.is_present() && !entry.is_write_protected())
    }
}
