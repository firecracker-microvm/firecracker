// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclave info page: header, TOC, and serial ring buffer reader.
//!
//! The info page is a 2 MiB-aligned shared memory region containing
//! a TOC with entries for serial ring buffers. The enclave VMM writes device
//! state here; the parent VMM polls it.

use std::io;

use vm_memory::{ByteValued, Bytes, VolatileSlice, WriteVolatile};

use super::ne_ioctl::EnclaveFd;
use crate::logger::error;

/// Info page magic number (`NISC` in little-endian).
pub const INFO_PAGE_MAGIC: u32 = 0x5343_494E;

/// Info page size (2 MiB).
pub const INFO_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// TOC entry type for serial ring buffer.
const TOC_TYPE_SERIAL: u16 = 1;

/// Maximum number of TOC entries that fit in the info page.
const MAX_TOC_ENTRIES: usize = (INFO_PAGE_SIZE - std::mem::size_of::<NitroInfoHeader>())
    / std::mem::size_of::<NitroTocEntry>();

// ---------------------------------------------------------------------------
// ABI structures shared with the NE driver
// ---------------------------------------------------------------------------

/// Info page header -- lives at the start of the 2 MiB region.
#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NitroInfoHeader {
    /// Magic number, must equal [`INFO_PAGE_MAGIC`].
    pub magic: u32,
    /// Header version.
    pub version: u32,
    /// Number of TOC entries following this header.
    pub num_entries: u32,
    /// CRC32 checksum (reserved, not currently validated).
    pub crc32: u32,
    // toc[] follows immediately in memory
}

// SAFETY: NitroInfoHeader is a #[repr(C, packed)] POD with no padding.
// All members are simple numbers and any value is valid.
unsafe impl ByteValued for NitroInfoHeader {}

/// TOC entry describing a region within the info page.
#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NitroTocEntry {
    /// Entry type (1 = serial ring buffer).
    pub entry_type: u16,
    /// Entry flags (reserved).
    pub flags: u16,
    /// Byte offset from the start of the info page.
    pub offset: u32,
    /// Size of the region in bytes.
    pub size: u64,
    /// Extra data (type-specific, currently unused).
    pub extra: [u8; 32],
}

// SAFETY: NitroTocEntry is a #[repr(C, packed)] POD with no padding.
// All members are simple numbers and any value is valid.
unsafe impl ByteValued for NitroTocEntry {}

/// Serial ring buffer header — first 8 bytes of a serial TOC region.
#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
struct SerialRingHeader {
    /// Number of bytes written (monotonically increasing).
    write_idx: u32,
    /// Ring buffer capacity in bytes (data follows immediately).
    capacity: u32,
}

// SAFETY: SerialRingHeader is a #[repr(C, packed)] POD with no padding.
unsafe impl ByteValued for SerialRingHeader {}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during info page operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InfoPageError {
    /// mmap allocation failed: {0}
    Alloc(io::Error),
    /// NE_SET_INFO_PAGE ioctl failed: {0}
    Register(io::Error),
    /// invalid info page header magic
    InvalidHeader,
}

// ---------------------------------------------------------------------------
// InfoPage -- allocation, registration, and serial ring reading
// ---------------------------------------------------------------------------

/// A 2 MiB-aligned info page shared with the enclave VMM.
#[derive(Debug)]
pub struct InfoPage {
    /// Pointer to the start of the mapped 2 MiB region.
    ptr: *mut u8,
}

// SAFETY: InfoPage is only accessed via VolatileSlice (volatile reads/writes),
// never through shared references to the underlying memory. Concurrent writes
// from the enclave VMM are observed safely through volatile operations.
unsafe impl Send for InfoPage {}
// SAFETY: See Send impl.
unsafe impl Sync for InfoPage {}

impl InfoPage {
    /// Allocate a 2 MiB info page via CMA (mmap on the NE device fd).
    ///
    /// PCIE mode requires physically contiguous memory from the NE driver's
    /// CMA pool.
    pub fn new(ne_dev_fd: &super::ne_ioctl::NitroEnclavesDevFd) -> Result<Self, InfoPageError> {
        let ptr = ne_dev_fd
            .allocate_cma(INFO_PAGE_SIZE)
            .map_err(InfoPageError::Alloc)?;
        Ok(Self { ptr })
    }

    /// Allocate a 2 MiB-aligned info page for testing without a real NE device.
    #[cfg(test)]
    pub fn allocate_anonymous() -> Result<Self, InfoPageError> {
        // SAFETY: mmap with MAP_ANONYMOUS|MAP_HUGETLB returns a 2 MiB-aligned mapping.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                INFO_PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_HUGETLB | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(InfoPageError::Alloc(io::Error::last_os_error()));
        }
        // SAFETY: ptr is valid for INFO_PAGE_SIZE bytes.
        unsafe { std::ptr::write_bytes(ptr.cast::<u8>(), 0, INFO_PAGE_SIZE) };
        Ok(Self {
            ptr: ptr.cast::<u8>(),
        })
    }

    /// Register this info page with the NE kernel driver.
    pub fn register(&self, enclave_fd: &EnclaveFd) -> Result<(), InfoPageError> {
        enclave_fd
            .set_info_page(self.ptr as u64, INFO_PAGE_SIZE as u64)
            .map_err(InfoPageError::Register)
    }

    /// Get the userspace address of the info page.
    #[cfg(test)]
    pub fn addr(&self) -> usize {
        self.ptr as usize
    }

    /// Returns `true` if the info page header has valid magic.
    #[cfg(test)]
    pub fn header_valid(&self) -> bool {
        self.header().is_some()
    }

    /// Write new serial data since `last_write_idx` directly into `dst`.
    ///
    /// Returns the current `write_idx` if there is new data,
    /// or `None` if there is no serial ring buffer or no new data.
    pub fn write_serial_since<W: WriteVolatile>(
        &self,
        last_write_idx: u32,
        dst: &mut W,
    ) -> Option<u32> {
        let header = self.header()?;
        let num = (header.num_entries as usize).min(MAX_TOC_ENTRIES);
        for i in 0..num {
            let toc = self.toc_entry(i)?;
            if toc.entry_type != TOC_TYPE_SERIAL {
                continue;
            }
            let offset = toc.offset as usize;
            // Safe: INFO_PAGE_SIZE is 2 MiB, so any valid size fits in usize.
            #[allow(clippy::cast_possible_truncation)]
            let size = toc.size as usize;
            if offset + size > INFO_PAGE_SIZE || size < std::mem::size_of::<SerialRingHeader>() {
                error!("info page TOC entry {i}: invalid offset={offset} size={size}");
                break;
            }
            let vs = self.as_volatile_slice();
            // TODO(enclave): handle write_idx wrapping past u32::MAX (unlikely in
            // practice — ~4 GiB of serial output would be needed).
            let ring: SerialRingHeader = vs.read_obj(offset).ok()?;
            let data_offset = offset + std::mem::size_of::<SerialRingHeader>();
            if ring.capacity == 0
                || ring.write_idx <= last_write_idx
                || ring.capacity as usize > size - std::mem::size_of::<SerialRingHeader>()
            {
                return None;
            }
            let new_bytes = ring.write_idx - last_write_idx;
            let read_len = new_bytes.min(ring.capacity);
            let start_pos = last_write_idx % ring.capacity;
            if start_pos + read_len <= ring.capacity {
                vs.write_all_volatile_to(data_offset + start_pos as usize, dst, read_len as usize)
                    .ok()?;
            } else {
                let first_chunk = ring.capacity - start_pos;
                vs.write_all_volatile_to(
                    data_offset + start_pos as usize,
                    dst,
                    first_chunk as usize,
                )
                .ok()?;
                vs.write_all_volatile_to(data_offset, dst, (read_len - first_chunk) as usize)
                    .ok()?;
            }
            return Some(ring.write_idx);
        }
        None
    }

    fn as_volatile_slice(&self) -> VolatileSlice<'_> {
        // SAFETY: ptr is valid for INFO_PAGE_SIZE bytes, and the info page
        // lifetime is tied to &self.
        unsafe { VolatileSlice::new(self.ptr, INFO_PAGE_SIZE) }
    }

    /// Read the info page header via volatile read.
    ///
    /// Returns `None` if the magic number does not match.
    fn header(&self) -> Option<NitroInfoHeader> {
        let header: NitroInfoHeader = self.as_volatile_slice().read_obj(0).ok()?;
        if header.magic != INFO_PAGE_MAGIC {
            return None;
        }
        Some(header)
    }

    /// Read a TOC entry by index via volatile read.
    ///
    /// Returns `None` if the entry would be out of bounds.
    fn toc_entry(&self, index: usize) -> Option<NitroTocEntry> {
        let toc_start = std::mem::size_of::<NitroInfoHeader>();
        let entry_offset = toc_start + index * std::mem::size_of::<NitroTocEntry>();
        self.as_volatile_slice().read_obj(entry_offset).ok()
    }

    #[cfg(test)]
    pub(crate) fn from_raw_ptr(ptr: *mut u8) -> Self {
        Self { ptr }
    }
}

impl Drop for InfoPage {
    fn drop(&mut self) {
        // SAFETY: ptr was returned by mmap with INFO_PAGE_SIZE.
        unsafe {
            libc::munmap(self.ptr.cast::<libc::c_void>(), INFO_PAGE_SIZE);
        }
    }
}

/// Create a test info page with a serial ring buffer for unit tests.
///
/// Allocates an anonymous page, writes a valid header + TOC + ring buffer,
/// and returns an `InfoPage` wrapping it.
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks)]
pub(crate) fn make_test_page(write_idx: u32, capacity: u32, data: &[u8]) -> InfoPage {
    use std::ptr;
    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            INFO_PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);
    let base = ptr.cast::<u8>();
    let header = NitroInfoHeader {
        magic: INFO_PAGE_MAGIC,
        version: 1,
        num_entries: 1,
        crc32: 0,
    };
    unsafe { ptr::write(base.cast::<NitroInfoHeader>(), header) };
    let serial_data_offset: u32 = 4096;
    let serial_region_size: u64 = (capacity as u64) + 8;
    let toc = NitroTocEntry {
        entry_type: TOC_TYPE_SERIAL,
        flags: 0,
        offset: serial_data_offset,
        size: serial_region_size,
        extra: [0u8; 32],
    };
    let toc_offset = std::mem::size_of::<NitroInfoHeader>();
    unsafe { ptr::write(base.add(toc_offset).cast::<NitroTocEntry>(), toc) };
    let ring_base = unsafe { base.add(serial_data_offset as usize) };
    unsafe {
        ptr::write(ring_base.cast::<u32>(), write_idx);
        ptr::write(ring_base.add(4).cast::<u32>(), capacity);
    }
    if !data.is_empty() {
        let data_base = unsafe { ring_base.add(8) };
        let len = data.len().min(capacity as usize);
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), data_base, len) };
    }
    InfoPage::from_raw_ptr(base)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    #![allow(clippy::cast_possible_truncation)]

    use std::ptr;

    use super::*;

    // 1024 bytes total serial region minus 8-byte ring header (write_idx + capacity fields).
    const TEST_RING_CAPACITY: u32 = 1016;

    fn mmap_page() -> *mut libc::c_void {
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                INFO_PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        ptr
    }

    #[test]
    fn test_header_valid() {
        let ptr = mmap_page();
        let page = InfoPage {
            ptr: ptr.cast::<u8>(),
        };
        assert!(!page.header_valid());

        unsafe { *ptr.cast::<u32>() = INFO_PAGE_MAGIC };
        assert!(page.header_valid());
    }

    #[test]
    fn test_addr() {
        let ptr = mmap_page();
        let page = InfoPage {
            ptr: ptr.cast::<u8>(),
        };
        assert_eq!(page.addr(), ptr as usize);
    }

    #[test]
    fn test_read_serial_since() {
        // Basic read from offset 0.
        let page = make_test_page(5, TEST_RING_CAPACITY, b"hello");
        let mut buf = Vec::new();
        let new_idx = page.write_serial_since(0, &mut buf).unwrap();
        assert_eq!(new_idx, 5);
        assert_eq!(&buf, b"hello");

        // Incremental read from offset 5.
        let page = make_test_page(10, TEST_RING_CAPACITY, b"helloworld");
        buf.clear();
        let new_idx = page.write_serial_since(5, &mut buf).unwrap();
        assert_eq!(new_idx, 10);
        assert_eq!(&buf, b"world");

        // No new data when already caught up.
        let page = make_test_page(5, TEST_RING_CAPACITY, b"hello");
        buf.clear();
        assert!(page.write_serial_since(5, &mut buf).is_none());
    }

    #[test]
    fn test_serial_ring_buffer_wrap_around() {
        // write_idx (20) > capacity (16): reader should get at most `capacity` bytes.
        let page = make_test_page(20, 16, b"ABCDEFGHIJKLMNOP");
        let mut buf = Vec::new();
        let new_idx = page.write_serial_since(0, &mut buf).unwrap();
        assert_eq!(new_idx, 20);
        assert_eq!(buf.len(), 16);
    }
}
