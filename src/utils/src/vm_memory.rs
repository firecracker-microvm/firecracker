// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::io::{Error as IoError, ErrorKind};
use std::os::unix::io::AsRawFd;

pub use vm_memory::bitmap::{AtomicBitmap, Bitmap, BitmapSlice, BS};
use vm_memory::mmap::{check_file_offset, NewBitmap};
pub use vm_memory::mmap::{MmapRegionBuilder, MmapRegionError};
pub use vm_memory::{
    address, Address, ByteValued, Bytes, Error, FileOffset, GuestAddress, GuestMemory,
    GuestMemoryError, GuestMemoryRegion, GuestUsize, MemoryRegionAddress, MmapRegion,
    VolatileMemory, VolatileMemoryError, VolatileSlice,
};

pub type GuestMemoryMmap = vm_memory::GuestMemoryMmap<Option<AtomicBitmap>>;
pub type GuestRegionMmap = vm_memory::GuestRegionMmap<Option<AtomicBitmap>>;
pub type GuestMmapRegion = vm_memory::MmapRegion<Option<AtomicBitmap>>;

const GUARD_PAGE_COUNT: usize = 1;

/// Build a `MmapRegion` surrounded by guard pages.
///
/// Initially, we map a `PROT_NONE` guard region of size:
/// `size` + (GUARD_PAGE_COUNT * 2 * page_size).
/// The guard region is mapped with `PROT_NONE`, so that any access to this region will cause
/// a SIGSEGV.
///
/// The actual accessible region is going to be nested in the larger guard region.
/// This is done by mapping over the guard region, starting at an address of
/// `guard_region_addr + (GUARD_PAGE_COUNT * page_size)`.
/// This results in a border of `GUARD_PAGE_COUNT` pages on either side of the region, which
/// acts as a safety net for accessing out-of-bounds addresses that are not allocated for the
/// guest's memory.
fn build_guarded_region(
    maybe_file_offset: Option<FileOffset>,
    size: usize,
    prot: i32,
    flags: i32,
    track_dirty_pages: bool,
) -> Result<GuestMmapRegion, MmapRegionError> {
    let page_size = crate::get_page_size().expect("Cannot retrieve page size.");
    // Create the guarded range size (received size + X pages),
    // where X is defined as a constant GUARD_PAGE_COUNT.
    let guarded_size = size + GUARD_PAGE_COUNT * 2 * page_size;

    // Map the guarded range to PROT_NONE
    // SAFETY: Safe because the parameters are valid.
    let guard_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            guarded_size,
            libc::PROT_NONE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };

    if guard_addr == libc::MAP_FAILED {
        return Err(MmapRegionError::Mmap(IoError::last_os_error()));
    }

    let (fd, offset) = match maybe_file_offset {
        Some(ref file_offset) => {
            check_file_offset(file_offset, size)?;
            (file_offset.file().as_raw_fd(), file_offset.start())
        }
        None => (-1, 0),
    };

    let region_start_addr = guard_addr as usize + page_size * GUARD_PAGE_COUNT;

    // Inside the protected range, starting with guard_addr + PAGE_SIZE,
    // map the requested range with received protection and flags
    // SAFETY: Safe because the parameters are valid.
    let region_addr = unsafe {
        libc::mmap(
            region_start_addr as *mut libc::c_void,
            size,
            prot,
            flags | libc::MAP_FIXED,
            fd,
            offset as libc::off_t,
        )
    };

    if region_addr == libc::MAP_FAILED {
        return Err(MmapRegionError::Mmap(IoError::last_os_error()));
    }

    let bitmap = match track_dirty_pages {
        true => Some(AtomicBitmap::with_len(size)),
        false => None,
    };

    // SAFETY: Safe because the parameters are valid.
    unsafe {
        MmapRegionBuilder::new_with_bitmap(size, bitmap)
            .with_raw_mmap_pointer(region_addr.cast::<u8>())
            .with_mmap_prot(prot)
            .with_mmap_flags(flags)
            .build()
    }
}

/// Helper for creating the guest memory.
pub fn create_guest_memory(
    regions: &[(Option<FileOffset>, GuestAddress, usize)],
    track_dirty_pages: bool,
) -> std::result::Result<GuestMemoryMmap, Error> {
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let mut mmap_regions = Vec::with_capacity(regions.len());

    for region in regions {
        let flags = match region.0 {
            None => libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            Some(_) => libc::MAP_NORESERVE | libc::MAP_SHARED,
        };

        let mmap_region =
            build_guarded_region(region.0.clone(), region.2, prot, flags, track_dirty_pages)
                .map_err(Error::MmapRegion)?;

        mmap_regions.push(GuestRegionMmap::new(mmap_region, region.1)?);
    }

    GuestMemoryMmap::from_regions(mmap_regions)
}

pub fn mark_dirty_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: usize) {
    let _ = mem.try_access(len, addr, |_total, count, caddr, region| {
        if let Some(bitmap) = region.bitmap() {
            bitmap.mark_dirty(caddr.0 as usize, count);
        }
        Ok(count)
    });
}

/// A version of the standard library's [`Read`] trait that operates on volatile memory instead of
/// slices
///
/// This trait is needed as rust slices (`&[u8]` and `&mut [u8]`) cannot be used when operating on
/// guest memory [1].
///
/// [1]: https://github.com/rust-vmm/vm-memory/pull/217
pub trait ReadVolatile {
    /// Tries to read some bytes into the given [`VolatileSlice`] buffer, returning how many bytes
    /// were read.
    ///
    /// The behavior of implementations should be identical to [`Read::read`]
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError>;

    /// Tries to fill the given [`VolatileSlice`] buffer by reading from `self` returning an error
    /// if insufficient bytes could be read.
    ///
    /// The default implementation is identical to that of [`Read::read_exact`]
    fn read_exact_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<(), VolatileMemoryError> {
        // Implementation based on https://github.com/rust-lang/rust/blob/7e7483d26e3cec7a44ef00cf7ae6c9c8c918bec6/library/std/src/io/mod.rs#L465

        let mut partial_buf = buf.offset(0)?;

        while !partial_buf.is_empty() {
            match self.read_volatile(&mut partial_buf) {
                Err(VolatileMemoryError::IOError(err)) if err.kind() == ErrorKind::Interrupted => {
                    continue
                }
                Ok(0) => {
                    return Err(VolatileMemoryError::IOError(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    )))
                }
                Ok(bytes_read) => partial_buf = partial_buf.offset(bytes_read)?,
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }
}

/// A version of the standard library's [`Write`] trait that operates on volatile memory instead of
/// slices
///
/// This trait is needed as rust slices (`&[u8]` and `&mut [u8]`) cannot be used when operating on
/// guest memory [1].
///
/// [1]: https://github.com/rust-vmm/vm-memory/pull/217
pub trait WriteVolatile {
    /// Tries to write some bytes from the given [`VolatileSlice`] buffer, returning how many bytes
    /// were written.
    ///
    /// The behavior of implementations should be identical to [`Write::write`]
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError>;

    /// Tries write the entire content of the given [`VolatileSlice`] buffer to `self` returning an
    /// error if not all bytes could be written.
    ///
    /// The default implementation is identical to that of [`Write::write_all`]
    fn write_all_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<(), VolatileMemoryError> {
        // Based on https://github.com/rust-lang/rust/blob/7e7483d26e3cec7a44ef00cf7ae6c9c8c918bec6/library/std/src/io/mod.rs#L1570

        let mut partial_buf = buf.offset(0)?;

        while !partial_buf.is_empty() {
            match self.write_volatile(&partial_buf) {
                Err(VolatileMemoryError::IOError(err)) if err.kind() == ErrorKind::Interrupted => {
                    continue
                }
                Ok(0) => {
                    return Err(VolatileMemoryError::IOError(std::io::Error::new(
                        ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    )))
                }
                Ok(bytes_written) => partial_buf = partial_buf.offset(bytes_written)?,
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }
}

// We explicitly implement our traits for [`std::fs::File`] and [`std::os::unix::net::UnixStream`]
// instead of providing blanket implementation for [`AsRawFd`] due to trait coherence limitations: A
// blanket implementation would prevent us from providing implementations for `&mut [u8]` below, as
// "an upstream crate could implement AsRawFd for &mut [u8]`.

impl ReadVolatile for std::fs::File {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        read_volatile_raw_fd(self, buf)
    }
}

impl ReadVolatile for std::os::unix::net::UnixStream {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        read_volatile_raw_fd(self, buf)
    }
}

/// Tries to do a single `read` syscall on the provided file descriptor, storing the data raed in
/// the given [`VolatileSlice`].
///
/// Returns the numbers of bytes read.
fn read_volatile_raw_fd(
    raw_fd: &mut impl AsRawFd,
    buf: &mut VolatileSlice<impl BitmapSlice>,
) -> Result<usize, VolatileMemoryError> {
    let fd = raw_fd.as_raw_fd();
    let dst = buf.as_ptr().cast::<libc::c_void>();

    // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `dst` is
    // valid for writes of length `buf.len() by the invariants upheld by the constructor
    // of `VolatileSlice`.
    let bytes_read = unsafe { libc::read(fd, dst, buf.len()) };

    if bytes_read < 0 {
        // We don't know if a partial read might have happened, so mark everything as dirty
        buf.bitmap().mark_dirty(0, buf.len());

        Err(VolatileMemoryError::IOError(std::io::Error::last_os_error()))
    } else {
        let bytes_read = bytes_read.try_into().unwrap();
        buf.bitmap().mark_dirty(0, bytes_read);
        Ok(bytes_read)
    }
}

impl WriteVolatile for std::fs::File {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        write_volatile_raw_fd(self, buf)
    }
}

impl WriteVolatile for std::os::unix::net::UnixStream {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        write_volatile_raw_fd(self, buf)
    }
}

/// Tries to do a single `write` syscall on the provided file descriptor, attempting to write the
/// data stored in the given [`VolatileSlice`].
///
/// Returns the numbers of bytes written.
fn write_volatile_raw_fd(
    raw_fd: &mut impl AsRawFd,
    buf: &VolatileSlice<impl BitmapSlice>,
) -> Result<usize, VolatileMemoryError> {
    let fd = raw_fd.as_raw_fd();
    let src = buf.as_ptr().cast::<libc::c_void>();

    // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `src` is
    // valid for reads of length `buf.len() by the invariants upheld by the constructor
    // of `VolatileSlice`.
    let bytes_written = unsafe { libc::write(fd, src, buf.len()) };

    if bytes_written < 0 {
        Err(VolatileMemoryError::IOError(std::io::Error::last_os_error()))
    } else {
        Ok(bytes_written.try_into().unwrap())
    }
}

impl WriteVolatile for &mut [u8] {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        // NOTE: The duality of read <-> write here is correct. This is because we translate a call
        // "slice.write(buf)" (e.g. write into slice from buf) into "buf.read(slice)" (e.g. read
        // from buffer into slice). Both express data transfer from the buffer to the slice
        let read = buf.read(self, 0)?;

        // Advance the slice, just like the stdlib: https://doc.rust-lang.org/src/std/io/impls.rs.html#335
        *self = std::mem::take(self).split_at_mut(read).1;

        Ok(read)
    }

    fn write_all_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<(), VolatileMemoryError> {
        // Based on https://github.com/rust-lang/rust/blob/f7b831ac8a897273f78b9f47165cf8e54066ce4b/library/std/src/io/impls.rs#L376-L382
        if self.write_volatile(buf)? == buf.len() {
            Ok(())
        } else {
            Err(VolatileMemoryError::IOError(std::io::Error::new(
                ErrorKind::WriteZero,
                "failed to write whole buffer",
            )))
        }
    }
}

impl ReadVolatile for &[u8] {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        // NOTE: the duality of read <-> write here is correct. This is because we translate a call
        // "slice.read(buf)" (e.g. "read from slice into buf") into "buf.write(slice)" (e.g. write
        // into buf from slice)
        let written = buf.write(self, 0)?;

        // Advance the slice, just like the stdlib: https://doc.rust-lang.org/src/std/io/impls.rs.html#232-310
        *self = self.split_at(written).1;

        Ok(written)
    }

    fn read_exact_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<(), VolatileMemoryError> {
        // Based on https://github.com/rust-lang/rust/blob/f7b831ac8a897273f78b9f47165cf8e54066ce4b/library/std/src/io/impls.rs#L282-L302
        if buf.len() > self.len() {
            return Err(VolatileMemoryError::IOError(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            )));
        }

        self.read_volatile(buf).map(|_| ())
    }
}

pub mod test_utils {
    use super::*;

    /// Test helper used to initialize the guest memory without adding guard pages.
    /// This is needed because the default `create_guest_memory`
    /// uses MmapRegionBuilder::build_raw() for setting up the memory with guard pages, which would
    /// error if the size is not a multiple of the page size.
    /// There are unit tests which need a custom memory size, not a multiple of the page size.
    pub fn create_guest_memory_unguarded(
        regions: &[(GuestAddress, usize)],
        track_dirty_pages: bool,
    ) -> std::result::Result<GuestMemoryMmap, Error> {
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let mut mmap_regions = Vec::with_capacity(regions.len());

        for region in regions {
            mmap_regions.push(GuestRegionMmap::new(
                MmapRegionBuilder::new_with_bitmap(
                    region.1,
                    match track_dirty_pages {
                        true => Some(AtomicBitmap::with_len(region.1)),
                        false => None,
                    },
                )
                .with_mmap_prot(prot)
                .with_mmap_flags(flags)
                .build()
                .map_err(Error::MmapRegion)?,
                region.0,
            )?);
        }
        GuestMemoryMmap::from_regions(mmap_regions)
    }

    /// Test helper used to initialize the guest memory, without the option of file-backed mmap.
    /// It is just a little syntactic sugar that helps deduplicate test code.
    pub fn create_anon_guest_memory(
        regions: &[(GuestAddress, usize)],
        track_dirty_pages: bool,
    ) -> std::result::Result<GuestMemoryMmap, Error> {
        create_guest_memory(
            &regions.iter().map(|r| (None, r.0, r.1)).collect::<Vec<_>>(),
            track_dirty_pages,
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::io::{Read, Seek, Write};

    use super::*;
    use crate::get_page_size;
    use crate::tempfile::TempFile;

    enum AddrOp {
        Read,
        Write,
    }

    impl AddrOp {
        fn apply_on_addr(&self, addr: *mut u8) {
            match self {
                AddrOp::Read => {
                    // We have to do something perform a read_volatile, otherwise
                    // the Release version will optimize it out, making the test fail.
                    unsafe { std::ptr::read_volatile(addr) };
                }
                AddrOp::Write => unsafe {
                    std::ptr::write(addr, 0xFF);
                },
            }
        }
    }

    fn fork_and_run(function: &dyn Fn(), expect_sigsegv: bool) {
        let pid = unsafe { libc::fork() };
        match pid {
            0 => {
                function();
            }
            child_pid => {
                let mut child_status: i32 = -1;
                let pid_done = unsafe { libc::waitpid(child_pid, &mut child_status, 0) };
                assert_eq!(pid_done, child_pid);

                if expect_sigsegv {
                    // Asserts that the child process terminated because
                    // it received a signal that was not handled.
                    assert!(libc::WIFSIGNALED(child_status));
                    // Signal code should be a SIGSEGV
                    assert_eq!(libc::WTERMSIG(child_status), libc::SIGSEGV);
                } else {
                    assert!(libc::WIFEXITED(child_status));
                    // Signal code should be a SIGSEGV
                    assert_eq!(libc::WEXITSTATUS(child_status), 0);
                }
            }
        };
    }

    fn validate_guard_region(region: &GuestMmapRegion) {
        let page_size = get_page_size().unwrap();

        // Check that the created range allows us to write inside it
        let addr = region.as_ptr();

        unsafe {
            std::ptr::write(addr, 0xFF);
            assert_eq!(std::ptr::read(addr), 0xFF);
        }

        // Try a read/write operation against the left guard border of the range
        let left_border = (addr as usize - page_size) as *mut u8;
        fork_and_run(&|| AddrOp::Read.apply_on_addr(left_border), true);
        fork_and_run(&|| AddrOp::Write.apply_on_addr(left_border), true);

        // Try a read/write operation against the right guard border of the range
        let right_border = (addr as usize + region.size()) as *mut u8;
        fork_and_run(&|| AddrOp::Read.apply_on_addr(right_border), true);
        fork_and_run(&|| AddrOp::Write.apply_on_addr(right_border), true);
    }

    fn loop_guard_region_to_sigsegv(region: &GuestMmapRegion) {
        let page_size = get_page_size().unwrap();
        let right_page_guard = region.as_ptr() as usize + region.size();

        fork_and_run(
            &|| {
                let mut addr = region.as_ptr() as usize;
                loop {
                    if addr >= right_page_guard {
                        break;
                    }
                    AddrOp::Write.apply_on_addr(addr as *mut u8);

                    addr += page_size;
                }
            },
            false,
        );

        fork_and_run(
            &|| {
                AddrOp::Write.apply_on_addr(right_page_guard as *mut u8);
            },
            true,
        );
    }

    #[test]
    fn test_build_guarded_region() {
        // Create anonymous guarded region.
        {
            let page_size = get_page_size().unwrap();
            let size = page_size * 10;
            let prot = libc::PROT_READ | libc::PROT_WRITE;
            let flags = libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_PRIVATE;

            let region = build_guarded_region(None, size, prot, flags, false).unwrap();

            // Verify that the region was built correctly
            assert_eq!(region.size(), size);
            assert!(region.file_offset().is_none());
            assert_eq!(region.prot(), prot);
            assert_eq!(region.flags(), flags);

            validate_guard_region(&region);
        }

        // Create guarded region from file.
        {
            let file = TempFile::new().unwrap().into_file();
            let page_size = get_page_size().unwrap();

            let prot = libc::PROT_READ | libc::PROT_WRITE;
            let flags = libc::MAP_NORESERVE | libc::MAP_PRIVATE;
            let offset = 0;
            let size = 10 * page_size;
            assert_eq!(unsafe { libc::ftruncate(file.as_raw_fd(), 4096 * 10) }, 0);

            let region = build_guarded_region(
                Some(FileOffset::new(file, offset)),
                size,
                prot,
                flags,
                false,
            )
            .unwrap();

            // Verify that the region was built correctly
            assert_eq!(region.size(), size);
            // assert_eq!(region.file_offset().unwrap().start(), offset as u64);
            assert_eq!(region.prot(), prot);
            assert_eq!(region.flags(), flags);

            validate_guard_region(&region);
        }
    }

    #[test]
    fn test_create_guest_memory() {
        // Test that all regions are guarded.
        {
            let region_size = 0x10000;
            let regions = vec![
                (None, GuestAddress(0x0), region_size),
                (None, GuestAddress(0x10000), region_size),
                (None, GuestAddress(0x20000), region_size),
                (None, GuestAddress(0x30000), region_size),
            ];

            let guest_memory = create_guest_memory(&regions, false).unwrap();
            guest_memory.iter().for_each(|region| {
                validate_guard_region(region);
                loop_guard_region_to_sigsegv(region);
            });
        }

        // Check dirty page tracking is off.
        {
            let region_size = 0x10000;
            let regions = vec![
                (None, GuestAddress(0x0), region_size),
                (None, GuestAddress(0x10000), region_size),
                (None, GuestAddress(0x20000), region_size),
                (None, GuestAddress(0x30000), region_size),
            ];

            let guest_memory = create_guest_memory(&regions, false).unwrap();
            guest_memory.iter().for_each(|region| {
                assert!(region.bitmap().is_none());
            });
        }

        // Check dirty page tracking is on.
        {
            let region_size = 0x10000;
            let regions = vec![
                (None, GuestAddress(0x0), region_size),
                (None, GuestAddress(0x10000), region_size),
                (None, GuestAddress(0x20000), region_size),
                (None, GuestAddress(0x30000), region_size),
            ];

            let guest_memory = create_guest_memory(&regions, true).unwrap();
            guest_memory.iter().for_each(|region| {
                assert!(region.bitmap().is_some());
            });
        }
    }

    #[test]
    fn test_mark_dirty_mem() {
        let page_size = crate::get_page_size().unwrap();
        let region_size = page_size * 3;

        let regions = vec![
            (None, GuestAddress(0), region_size), // pages 0-2
            (None, GuestAddress(region_size as u64), region_size), // pages 3-5
            (None, GuestAddress(region_size as u64 * 2), region_size), // pages 6-8
        ];
        let guest_memory = create_guest_memory(&regions, true).unwrap();

        let dirty_map = [
            // page 0: not dirty
            (0, page_size, false),
            // pages 1-2: dirty range in one region
            (page_size, page_size * 2, true),
            // page 3: not dirty
            (page_size * 3, page_size, false),
            // pages 4-7: dirty range across 2 regions,
            (page_size * 4, page_size * 4, true),
            // page 8: not dirty
            (page_size * 8, page_size, false),
        ];

        // Mark dirty memory
        for (addr, len, dirty) in &dirty_map {
            if *dirty {
                mark_dirty_mem(&guest_memory, GuestAddress(*addr as u64), *len);
            }
        }

        // Check that the dirty memory was set correctly
        for (addr, len, dirty) in &dirty_map {
            guest_memory
                .try_access(
                    *len,
                    GuestAddress(*addr as u64),
                    |_total, count, caddr, region| {
                        let offset = caddr.0 as usize;
                        let bitmap = region.bitmap().as_ref().unwrap();
                        for i in offset..offset + count {
                            assert_eq!(bitmap.dirty_at(i), *dirty);
                        }
                        Ok(count)
                    },
                )
                .unwrap();
        }
    }

    #[test]
    fn test_read_volatile() {
        let test_cases = [
            (vec![1u8, 2], [1u8, 2, 0, 0, 0]),
            (vec![1, 2, 3, 4], [1, 2, 3, 4, 0]),
            // ensure we don't have a buffer overrun
            (vec![5, 6, 7, 8, 9], [5, 6, 7, 8, 0]),
        ];

        for (input, output) in test_cases {
            // ---- Test ReadVolatile for &[u8] ----
            //
            // Test read_volatile for &[u8] works
            let mut memory = vec![0u8; 5];

            assert_eq!(
                (&input[..])
                    .read_volatile(&mut VolatileSlice::from(&mut memory[..4]))
                    .unwrap(),
                input.len().min(4)
            );
            assert_eq!(&memory, &output);

            // Test read_exact_volatile for &[u8] works
            let mut memory = vec![0u8; 5];
            let result =
                (&input[..]).read_exact_volatile(&mut VolatileSlice::from(&mut memory[..4]));

            // read_exact fails if there are not enough bytes in input to completely fill
            // memory[..4]
            if input.len() < 4 {
                match result.unwrap_err() {
                    VolatileMemoryError::IOError(ioe) => {
                        assert_eq!(ioe.kind(), ErrorKind::UnexpectedEof)
                    }
                    err => panic!("{:?}", err),
                }
                assert_eq!(memory, vec![0u8; 5]);
            } else {
                result.unwrap();
                assert_eq!(&memory, &output);
            }

            // ---- Test ReadVolatile for File ----

            let mut temp_file = TempFile::new().unwrap().into_file();
            temp_file.write_all(input.as_ref()).unwrap();
            temp_file.rewind().unwrap();

            // Test read_volatile for File works
            let mut memory = vec![0u8; 5];

            assert_eq!(
                temp_file
                    .read_volatile(&mut VolatileSlice::from(&mut memory[..4]))
                    .unwrap(),
                input.len().min(4)
            );
            assert_eq!(&memory, &output);

            temp_file.rewind().unwrap();

            // Test read_exact_volatile for File works
            let mut memory = vec![0u8; 5];

            let read_exact_result =
                temp_file.read_exact_volatile(&mut VolatileSlice::from(&mut memory[..4]));

            if input.len() < 4 {
                read_exact_result.unwrap_err();
            } else {
                read_exact_result.unwrap();
            }
            assert_eq!(&memory, &output);
        }
    }

    #[test]
    fn test_write_volatile() {
        let test_cases = [
            (vec![1u8, 2], [1u8, 2, 0, 0, 0]),
            (vec![1, 2, 3, 4], [1, 2, 3, 4, 0]),
            // ensure we don't have a buffer overrun
            (vec![5, 6, 7, 8, 9], [5, 6, 7, 8, 0]),
        ];

        for (mut input, output) in test_cases {
            // ---- Test WriteVolatile for &mut [u8] ----
            //
            // Test write_volatile for &mut [u8] works
            let mut memory = vec![0u8; 5];

            assert_eq!(
                (&mut memory[..4])
                    .write_volatile(&VolatileSlice::from(input.as_mut_slice()))
                    .unwrap(),
                input.len().min(4)
            );
            assert_eq!(&memory, &output);

            // Test write_all_volatile for &mut [u8] works
            let mut memory = vec![0u8; 5];

            let result =
                (&mut memory[..4]).write_all_volatile(&VolatileSlice::from(input.as_mut_slice()));

            if input.len() > 4 {
                match result.unwrap_err() {
                    VolatileMemoryError::IOError(ioe) => {
                        assert_eq!(ioe.kind(), ErrorKind::WriteZero)
                    }
                    err => panic!("{:?}", err),
                }
                // This quirky behavior of writing to the slice even in the case of failure is also
                // exhibited by the stdlib
                assert_eq!(&memory, &output);
            } else {
                result.unwrap();
                assert_eq!(&memory, &output);
            }

            // ---- Test ẂriteVolatile for File works
            // Test write_volatile for File works
            let mut temp_file = TempFile::new().unwrap().into_file();

            temp_file
                .write_volatile(&VolatileSlice::from(input.as_mut_slice()))
                .unwrap();
            temp_file.rewind().unwrap();

            let mut written = vec![0u8; input.len()];
            temp_file.read_exact(written.as_mut_slice()).unwrap();

            assert_eq!(input, written);
            // check no excess bytes were written to the file
            assert_eq!(temp_file.read(&mut [0u8]).unwrap(), 0);

            // Test write_all_volatile for File works
            let mut temp_file = TempFile::new().unwrap().into_file();

            temp_file
                .write_all_volatile(&VolatileSlice::from(input.as_mut_slice()))
                .unwrap();
            temp_file.rewind().unwrap();

            let mut written = vec![0u8; input.len()];
            temp_file.read_exact(written.as_mut_slice()).unwrap();

            assert_eq!(input, written);
            // check no excess bytes were written to the file
            assert_eq!(temp_file.read(&mut [0u8]).unwrap(), 0);
        }
    }
}
