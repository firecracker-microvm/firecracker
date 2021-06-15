// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

pub use vm_memory_upstream::{
    address, bitmap::Bitmap, mmap::MmapRegionBuilder, mmap::MmapRegionError, Address, ByteValued,
    Bytes, Error, FileOffset, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryRegion,
    GuestUsize, MemoryRegionAddress,
};

use std::io::Error as IoError;
use std::os::unix::io::AsRawFd;

use vm_memory_upstream::bitmap::AtomicBitmap;
use vm_memory_upstream::mmap::{check_file_offset, NewBitmap};
use vm_memory_upstream::{
    GuestMemoryMmap as UpstreamGuestMemoryMmap, GuestRegionMmap as UpstreamGuestRegionMmap,
    MmapRegion as UpstreamMmapRegion,
};

pub type GuestMemoryMmap = UpstreamGuestMemoryMmap<Option<AtomicBitmap>>;
pub type GuestRegionMmap = UpstreamGuestRegionMmap<Option<AtomicBitmap>>;
pub type MmapRegion = UpstreamMmapRegion<Option<AtomicBitmap>>;

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
) -> Result<MmapRegion, MmapRegionError> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    // Create the guarded range size (received size + X pages),
    // where X is defined as a constant GUARD_PAGE_COUNT.
    let guarded_size = size + GUARD_PAGE_COUNT * 2 * page_size;

    // Map the guarded range to PROT_NONE
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

    unsafe {
        MmapRegionBuilder::new_with_bitmap(size, bitmap)
            .with_raw_mmap_pointer(region_addr as *mut u8)
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
            Some(_) => libc::MAP_NORESERVE | libc::MAP_PRIVATE,
        };

        let mmap_region =
            build_guarded_region(region.0.clone(), region.2, prot, flags, track_dirty_pages)
                .map_err(Error::MmapRegion)?;

        mmap_regions.push(GuestRegionMmap::new(mmap_region, region.1)?);
    }

    GuestMemoryMmap::from_regions(mmap_regions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::tempfile::TempFile;

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

    fn validate_guard_region(region: &MmapRegion) {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

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

    fn loop_guard_region_to_sigsegv(region: &MmapRegion) {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
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
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
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
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

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
                validate_guard_region(&region);
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
}
