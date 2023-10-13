// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fs::File;
use std::io::{Error as IoError, SeekFrom};
use std::os::unix::io::AsRawFd;

use utils::{errno, get_page_size, u64_to_usize};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
pub use vm_memory::bitmap::{AtomicBitmap, Bitmap, BitmapSlice, BS};
pub use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::mmap::{check_file_offset, MmapRegionError, NewBitmap};
pub use vm_memory::{
    address, Address, ByteValued, Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryRegion,
    GuestUsize, MemoryRegionAddress, MmapRegion,
};
use vm_memory::{Error as VmMemoryError, GuestMemoryError, WriteVolatile};

use crate::DirtyBitmap;

/// Type of GuestMemoryMmap.
pub type GuestMemoryMmap = vm_memory::GuestMemoryMmap<Option<AtomicBitmap>>;
/// Type of GuestRegionMmap.
pub type GuestRegionMmap = vm_memory::GuestRegionMmap<Option<AtomicBitmap>>;
/// Type of GuestMmapRegion.
pub type GuestMmapRegion = vm_memory::MmapRegion<Option<AtomicBitmap>>;

const GUARD_PAGE_COUNT: usize = 1;

/// Errors associated with dumping guest memory to file.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MemoryError {
    /// Cannot access file: {0:?}
    FileError(std::io::Error),
    /// Cannot create memory: {0:?}
    CreateMemory(VmMemoryError),
    /// Cannot create memory region: {0:?}
    CreateRegion(MmapRegionError),
    /// Cannot fetch system's page size: {0:?}
    PageSize(errno::Error),
    /// Cannot dump memory: {0:?}
    WriteMemory(GuestMemoryError),
    /// Cannot create mmap region: {0}
    MmapRegionError(MmapRegionError),
    /// Cannot create guest memory: {0}
    VmMemoryError(VmMemoryError),
    /// Cannot create memfd: {0:?}
    Memfd(memfd::Error),
    /// Cannot resize memfd file: {0:?}
    MemfdSetLen(std::io::Error),
}

/// Defines the interface for snapshotting memory.
pub trait GuestMemoryExtension
where
    Self: Sized,
{
    /// Creates a GuestMemoryMmap with `size` in MiB and guard pages backed by file.
    fn with_file(file: &File, track_dirty_pages: bool) -> Result<Self, MemoryError>;

    /// Creates a GuestMemoryMmap with `size` in MiB and guard pages.
    fn with_size(size: usize, track_dirty_pages: bool) -> Result<Self, MemoryError>;

    /// Creates a GuestMemoryMmap from raw regions with guard pages.
    fn from_raw_regions(
        regions: &[(GuestAddress, usize)],
        track_dirty_pages: bool,
    ) -> Result<Self, MemoryError>;

    /// Creates a GuestMemoryMmap from raw regions with no guard pages.
    fn from_raw_regions_unguarded(
        regions: &[(GuestAddress, usize)],
        track_dirty_pages: bool,
    ) -> Result<Self, MemoryError>;

    /// Creates a GuestMemoryMmap from raw regions with guard pages.
    fn from_raw_regions_file(
        regions: Vec<(FileOffset, GuestAddress, usize)>,
        track_dirty_pages: bool,
        shared: bool,
    ) -> Result<Self, MemoryError>;

    /// Creates a GuestMemoryMmap given a `file` containing the data
    /// and a `state` containing mapping information.
    fn from_state(
        file: Option<&File>,
        state: &GuestMemoryState,
        track_dirty_pages: bool,
    ) -> Result<Self, MemoryError>;

    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState;

    /// Mark memory range as dirty
    fn mark_dirty(&self, addr: GuestAddress, len: usize);

    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: WriteVolatile>(&self, writer: &mut T) -> Result<(), MemoryError>;

    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> Result<(), MemoryError>;
}

/// State of a guest memory region saved to file/buffer.
#[derive(Debug, PartialEq, Eq, Versionize)]
// NOTICE: Any changes to this structure require a snapshot version bump.
pub struct GuestMemoryRegionState {
    // This should have been named `base_guest_addr` since it's _guest_ addr, but for
    // backward compatibility we have to keep this name. At least this comment should help.
    /// Base GuestAddress.
    pub base_address: u64,
    /// Region size.
    pub size: usize,
    /// Offset in file/buffer where the region is saved.
    pub offset: u64,
}

/// Describes guest memory regions and their snapshot file mappings.
#[derive(Debug, Default, PartialEq, Eq, Versionize)]
// NOTICE: Any changes to this structure require a snapshot version bump.
pub struct GuestMemoryState {
    /// List of regions.
    pub regions: Vec<GuestMemoryRegionState>,
}

impl GuestMemoryExtension for GuestMemoryMmap {
    /// Creates a GuestMemoryMmap with `size` in MiB and guard pages backed by file.
    fn with_file(file: &File, track_dirty_pages: bool) -> Result<Self, MemoryError> {
        let metadata = file.metadata().map_err(MemoryError::FileError)?;
        let mem_size = u64_to_usize(metadata.len());

        let mut offset: u64 = 0;
        let regions = crate::arch::arch_memory_regions(mem_size)
            .iter()
            .map(|(guest_address, region_size)| {
                let file_clone = file.try_clone().map_err(MemoryError::FileError)?;
                let file_offset = FileOffset::new(file_clone, offset);
                offset += *region_size as u64;
                Ok((file_offset, *guest_address, *region_size))
            })
            .collect::<Result<Vec<_>, MemoryError>>()?;

        Self::from_raw_regions_file(regions, track_dirty_pages, true)
    }

    /// Creates a GuestMemoryMmap with `size` in MiB and guard pages backed by anonymous memory.
    fn with_size(size: usize, track_dirty_pages: bool) -> Result<Self, MemoryError> {
        let mem_size = size << 20;
        let regions = crate::arch::arch_memory_regions(mem_size);

        Self::from_raw_regions(&regions, track_dirty_pages)
    }

    /// Creates a GuestMemoryMmap from raw regions with guard pages backed by anonymous memory.
    fn from_raw_regions(
        regions: &[(GuestAddress, usize)],
        track_dirty_pages: bool,
    ) -> Result<Self, MemoryError> {
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

        let regions = regions
            .iter()
            .map(|(guest_address, region_size)| {
                let region =
                    build_guarded_region(None, *region_size, prot, flags, track_dirty_pages)?;
                GuestRegionMmap::new(region, *guest_address).map_err(MemoryError::VmMemoryError)
            })
            .collect::<Result<Vec<_>, MemoryError>>()?;

        GuestMemoryMmap::from_regions(regions).map_err(MemoryError::VmMemoryError)
    }

    /// Creates a GuestMemoryMmap from raw regions with no guard pages backed by anonymous memory.
    fn from_raw_regions_unguarded(
        regions: &[(GuestAddress, usize)],
        track_dirty_pages: bool,
    ) -> Result<Self, MemoryError> {
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

        let regions = regions
            .iter()
            .map(|(guest_address, region_size)| {
                let bitmap = match track_dirty_pages {
                    true => Some(AtomicBitmap::with_len(*region_size)),
                    false => None,
                };
                let region = MmapRegionBuilder::new_with_bitmap(*region_size, bitmap)
                    .with_mmap_prot(prot)
                    .with_mmap_flags(flags)
                    .build()
                    .map_err(MemoryError::MmapRegionError)?;
                GuestRegionMmap::new(region, *guest_address).map_err(MemoryError::VmMemoryError)
            })
            .collect::<Result<Vec<_>, MemoryError>>()?;

        GuestMemoryMmap::from_regions(regions).map_err(MemoryError::VmMemoryError)
    }

    /// Creates a GuestMemoryMmap from raw regions with guard pages backed by file.
    fn from_raw_regions_file(
        regions: Vec<(FileOffset, GuestAddress, usize)>,
        track_dirty_pages: bool,
        shared: bool,
    ) -> Result<Self, MemoryError> {
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = if shared {
            libc::MAP_NORESERVE | libc::MAP_SHARED
        } else {
            libc::MAP_NORESERVE | libc::MAP_PRIVATE
        };
        let regions = regions
            .into_iter()
            .map(|(file_offset, guest_address, region_size)| {
                let region = build_guarded_region(
                    Some(file_offset),
                    region_size,
                    prot,
                    flags,
                    track_dirty_pages,
                )?;
                GuestRegionMmap::new(region, guest_address).map_err(MemoryError::VmMemoryError)
            })
            .collect::<Result<Vec<_>, MemoryError>>()?;

        GuestMemoryMmap::from_regions(regions).map_err(MemoryError::VmMemoryError)
    }

    /// Creates a GuestMemoryMmap backed by a `file` if present, otherwise backed
    /// by anonymous memory. Memory layout and ranges are described in `state` param.
    fn from_state(
        file: Option<&File>,
        state: &GuestMemoryState,
        track_dirty_pages: bool,
    ) -> Result<Self, MemoryError> {
        match file {
            Some(f) => {
                let regions = state
                    .regions
                    .iter()
                    .map(|r| {
                        f.try_clone().map(|file_clone| {
                            let offset = FileOffset::new(file_clone, r.offset);
                            (offset, GuestAddress(r.base_address), r.size)
                        })
                    })
                    .collect::<Result<Vec<_>, std::io::Error>>()
                    .map_err(MemoryError::FileError)?;

                Self::from_raw_regions_file(regions, track_dirty_pages, false)
            }
            None => {
                let regions = state
                    .regions
                    .iter()
                    .map(|r| (GuestAddress(r.base_address), r.size))
                    .collect::<Vec<_>>();
                Self::from_raw_regions(&regions, track_dirty_pages)
            }
        }
    }

    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState {
        let mut guest_memory_state = GuestMemoryState::default();
        let mut offset = 0;
        self.iter().for_each(|region| {
            guest_memory_state.regions.push(GuestMemoryRegionState {
                base_address: region.start_addr().0,
                size: u64_to_usize(region.len()),
                offset,
            });

            offset += region.len();
        });
        guest_memory_state
    }

    /// Mark memory range as dirty
    fn mark_dirty(&self, addr: GuestAddress, len: usize) {
        let _ = self.try_access(len, addr, |_total, count, caddr, region| {
            if let Some(bitmap) = region.bitmap() {
                bitmap.mark_dirty(u64_to_usize(caddr.0), count);
            }
            Ok(count)
        });
    }

    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: WriteVolatile>(&self, writer: &mut T) -> Result<(), MemoryError> {
        self.iter()
            .try_for_each(|region| Ok(writer.write_all_volatile(&region.as_volatile_slice()?)?))
            .map_err(MemoryError::WriteMemory)
    }

    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> Result<(), MemoryError> {
        let mut writer_offset = 0;
        let page_size = get_page_size().map_err(MemoryError::PageSize)?;

        self.iter()
            .enumerate()
            .try_for_each(|(slot, region)| {
                let kvm_bitmap = dirty_bitmap.get(&slot).unwrap();
                let firecracker_bitmap = region.bitmap();
                let mut write_size = 0;
                let mut dirty_batch_start: u64 = 0;

                for (i, v) in kvm_bitmap.iter().enumerate() {
                    for j in 0..64 {
                        let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;
                        let page_offset = ((i * 64) + j) * page_size;
                        let is_firecracker_page_dirty = firecracker_bitmap.dirty_at(page_offset);
                        if is_kvm_page_dirty || is_firecracker_page_dirty {
                            // We are at the start of a new batch of dirty pages.
                            if write_size == 0 {
                                // Seek forward over the unmodified pages.
                                writer
                                    .seek(SeekFrom::Start(writer_offset + page_offset as u64))
                                    .unwrap();
                                dirty_batch_start = page_offset as u64;
                            }
                            write_size += page_size;
                        } else if write_size > 0 {
                            // We are at the end of a batch of dirty pages.
                            writer.write_all_volatile(
                                &region.get_slice(
                                    MemoryRegionAddress(dirty_batch_start),
                                    write_size,
                                )?,
                            )?;

                            write_size = 0;
                        }
                    }
                }

                if write_size > 0 {
                    writer.write_all_volatile(
                        &region.get_slice(MemoryRegionAddress(dirty_batch_start), write_size)?,
                    )?;
                }
                writer_offset += region.len();
                if let Some(bitmap) = firecracker_bitmap {
                    bitmap.reset();
                }

                Ok(())
            })
            .map_err(MemoryError::WriteMemory)
    }
}

/// Creates a memfd file with the `size` in MiB.
pub fn create_memfd(size: usize) -> Result<memfd::Memfd, MemoryError> {
    let mem_size = size << 20;
    // Create a memfd.
    let opts = memfd::MemfdOptions::default().allow_sealing(true);
    let mem_file = opts.create("guest_mem").map_err(MemoryError::Memfd)?;

    // Resize to guest mem size.
    mem_file
        .as_file()
        .set_len(mem_size as u64)
        .map_err(MemoryError::MemfdSetLen)?;

    // Add seals to prevent further resizing.
    let mut seals = memfd::SealsHashSet::new();
    seals.insert(memfd::FileSeal::SealShrink);
    seals.insert(memfd::FileSeal::SealGrow);
    mem_file.add_seals(&seals).map_err(MemoryError::Memfd)?;

    // Prevent further sealing changes.
    mem_file
        .add_seal(memfd::FileSeal::SealSeal)
        .map_err(MemoryError::Memfd)?;

    Ok(mem_file)
}

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
    file_offset: Option<FileOffset>,
    size: usize,
    prot: i32,
    flags: i32,
    track_dirty_pages: bool,
) -> Result<GuestMmapRegion, MemoryError> {
    let page_size = utils::get_page_size().expect("Cannot retrieve page size.");
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
        return Err(MemoryError::MmapRegionError(MmapRegionError::Mmap(
            IoError::last_os_error(),
        )));
    }

    let (fd, offset) = match file_offset {
        Some(ref file_offset) => {
            check_file_offset(file_offset, size).map_err(MemoryError::MmapRegionError)?;
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
            libc::off_t::try_from(offset).unwrap(),
        )
    };

    if region_addr == libc::MAP_FAILED {
        return Err(MemoryError::MmapRegionError(MmapRegionError::Mmap(
            IoError::last_os_error(),
        )));
    }

    let bitmap = match track_dirty_pages {
        true => Some(AtomicBitmap::with_len(size)),
        false => None,
    };

    // SAFETY: Safe because the parameters are valid.
    let builder = unsafe {
        MmapRegionBuilder::new_with_bitmap(size, bitmap)
            .with_raw_mmap_pointer(region_addr.cast::<u8>())
            .with_mmap_prot(prot)
            .with_mmap_flags(flags)
    };

    match file_offset {
        Some(offset) => builder.with_file_offset(offset),
        None => builder,
    }
    .build()
    .map_err(MemoryError::MmapRegionError)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::collections::HashMap;
    use std::io::{Read, Seek};

    use utils::get_page_size;
    use utils::tempfile::TempFile;

    use super::*;

    // This method only works on gnu targets
    #[cfg(target_env = "gnu")]
    fn validate_guard_region(region: &GuestMmapRegion) {
        let read_mem = |addr| unsafe { std::ptr::read_volatile::<u8>(addr) };
        let write_mem = |addr, val| unsafe {
            std::ptr::write(addr, val);
        };

        // We utilize ability to catch panic from threads
        // to verify the caught signal.
        unsafe extern "C" fn handler(signum: libc::c_int) {
            panic!("{}", signum == libc::SIGSEGV);
        }

        let read_threaded = |addr: *mut u8| {
            let addr_usize = addr as usize;
            std::thread::spawn(move || unsafe { std::ptr::read::<u8>(addr_usize as *mut u8) })
                .join()
                .err()
                .unwrap()
                .downcast::<String>()
                .unwrap()
        };

        let write_threaded = |addr: *mut u8, val: u8| {
            let addr_usize = addr as usize;
            std::thread::spawn(move || unsafe {
                std::ptr::write(addr_usize as *mut u8, val);
            })
            .join()
            .err()
            .unwrap()
            .downcast::<String>()
            .unwrap()
        };

        // Setting a signal handler for threads to panic
        // with specific messages.
        let previous_signal_handler = unsafe {
            libc::signal(
                libc::SIGSEGV,
                handler as *const fn(libc::c_int) as libc::size_t,
            )
        };

        let page_size = get_page_size().unwrap();

        // Check that the created range allows us to write inside it
        let region_first_byte = region.as_ptr();
        let region_last_byte = unsafe { region_first_byte.add(region.size() - 1) };

        // Write and read from the start of the region
        write_mem(region_first_byte, 0x69);
        assert_eq!(read_mem(region_first_byte), 0x69);

        // Write and read from the end of the region
        write_mem(region_last_byte, 0x69);
        assert_eq!(read_mem(region_last_byte), 0x69);

        // Try a read/write operation against the left guard border of the range
        let left_border_first_byte = unsafe { region_first_byte.sub(page_size) };
        assert_eq!(read_threaded(left_border_first_byte).as_str(), "true");
        assert_eq!(
            write_threaded(left_border_first_byte, 0x69).as_str(),
            "true"
        );

        // Try a read/write operation against the right guard border of the range
        let right_border_first_byte = unsafe { region_last_byte.add(1) };
        assert_eq!(read_threaded(right_border_first_byte).as_str(), "true");
        assert_eq!(
            write_threaded(right_border_first_byte, 0x69).as_str(),
            "true"
        );

        // Restoring previous signal handler.
        unsafe { libc::signal(libc::SIGSEGV, previous_signal_handler) };
    }

    #[test]
    #[cfg(target_env = "gnu")]
    fn test_build_guarded_region() {
        let page_size = get_page_size().unwrap();
        let region_size = page_size * 10;

        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_PRIVATE;

        let region = build_guarded_region(None, region_size, prot, flags, false).unwrap();

        // Verify that the region was built correctly
        assert_eq!(region.size(), region_size);
        assert!(region.file_offset().is_none());
        assert_eq!(region.prot(), prot);
        assert_eq!(region.flags(), flags);

        validate_guard_region(&region);
    }

    #[test]
    #[cfg(target_env = "gnu")]
    fn test_build_guarded_region_file() {
        let page_size = get_page_size().unwrap();
        let region_size = page_size * 10;

        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_NORESERVE | libc::MAP_PRIVATE;

        let file = TempFile::new().unwrap().into_file();
        file.set_len(region_size as u64).unwrap();
        let file_offset = FileOffset::new(file, 0);

        let region =
            build_guarded_region(Some(file_offset), region_size, prot, flags, false).unwrap();

        // Verify that the region was built correctly
        assert_eq!(region.size(), region_size);
        assert!(region.file_offset().is_some());
        assert_eq!(region.prot(), prot);
        assert_eq!(region.flags(), flags);

        validate_guard_region(&region);
    }

    #[test]
    #[cfg(target_env = "gnu")]
    fn test_from_raw_regions() {
        // Test that all regions are guarded.
        {
            let region_size = 0x10000;
            let regions = vec![
                (GuestAddress(0x0), region_size),
                (GuestAddress(0x10000), region_size),
                (GuestAddress(0x20000), region_size),
                (GuestAddress(0x30000), region_size),
            ];

            let guest_memory = GuestMemoryMmap::from_raw_regions(&regions, false).unwrap();
            guest_memory.iter().for_each(|region| {
                validate_guard_region(region);
            });
        }

        // Check dirty page tracking is off.
        {
            let region_size = 0x10000;
            let regions = vec![
                (GuestAddress(0x0), region_size),
                (GuestAddress(0x10000), region_size),
                (GuestAddress(0x20000), region_size),
                (GuestAddress(0x30000), region_size),
            ];

            let guest_memory = GuestMemoryMmap::from_raw_regions(&regions, false).unwrap();
            guest_memory.iter().for_each(|region| {
                assert!(region.bitmap().is_none());
            });
        }

        // Check dirty page tracking is on.
        {
            let region_size = 0x10000;
            let regions = vec![
                (GuestAddress(0x0), region_size),
                (GuestAddress(0x10000), region_size),
                (GuestAddress(0x20000), region_size),
                (GuestAddress(0x30000), region_size),
            ];

            let guest_memory = GuestMemoryMmap::from_raw_regions(&regions, true).unwrap();
            guest_memory.iter().for_each(|region| {
                assert!(region.bitmap().is_some());
            });
        }
    }

    #[test]
    fn test_from_raw_regions_unguarded() {
        // Check dirty page tracking is off.
        {
            let region_size = 0x10000;
            let regions = vec![
                (GuestAddress(0x0), region_size),
                (GuestAddress(0x10000), region_size),
                (GuestAddress(0x20000), region_size),
                (GuestAddress(0x30000), region_size),
            ];

            let guest_memory =
                GuestMemoryMmap::from_raw_regions_unguarded(&regions, false).unwrap();
            guest_memory.iter().for_each(|region| {
                assert!(region.bitmap().is_none());
            });
        }

        // Check dirty page tracking is on.
        {
            let region_size = 0x10000;
            let regions = vec![
                (GuestAddress(0x0), region_size),
                (GuestAddress(0x10000), region_size),
                (GuestAddress(0x20000), region_size),
                (GuestAddress(0x30000), region_size),
            ];

            let guest_memory = GuestMemoryMmap::from_raw_regions_unguarded(&regions, true).unwrap();
            guest_memory.iter().for_each(|region| {
                assert!(region.bitmap().is_some());
            });
        }
    }

    #[test]
    #[cfg(target_env = "gnu")]
    fn test_from_raw_regions_file() {
        let region_size = 0x10000;

        let file = TempFile::new().unwrap().into_file();
        let file_size = 4 * region_size;
        file.set_len(file_size as u64).unwrap();

        let regions = vec![
            (
                FileOffset::new(file.try_clone().unwrap(), 0x0),
                GuestAddress(0x0),
                region_size,
            ),
            (
                FileOffset::new(file.try_clone().unwrap(), 0x10000),
                GuestAddress(0x10000),
                region_size,
            ),
            (
                FileOffset::new(file.try_clone().unwrap(), 0x20000),
                GuestAddress(0x20000),
                region_size,
            ),
            (
                FileOffset::new(file.try_clone().unwrap(), 0x30000),
                GuestAddress(0x30000),
                region_size,
            ),
        ];

        // Test that all regions are guarded.
        {
            let guest_memory =
                GuestMemoryMmap::from_raw_regions_file(regions.clone(), false, false).unwrap();
            guest_memory.iter().for_each(|region| {
                assert_eq!(region.size(), region_size);
                assert!(region.file_offset().is_some());
                assert!(region.bitmap().is_none());
                validate_guard_region(region);
            });
        }

        // Check dirty page tracking is off.
        {
            let guest_memory =
                GuestMemoryMmap::from_raw_regions_file(regions.clone(), false, false).unwrap();
            guest_memory.iter().for_each(|region| {
                assert!(region.bitmap().is_none());
            });
        }

        // Check dirty page tracking is on.
        {
            let guest_memory =
                GuestMemoryMmap::from_raw_regions_file(regions, true, false).unwrap();
            guest_memory.iter().for_each(|region| {
                assert!(region.bitmap().is_some());
            });
        }
    }

    #[test]
    fn test_mark_dirty() {
        let page_size = get_page_size().unwrap();
        let region_size = page_size * 3;

        let regions = vec![
            (GuestAddress(0), region_size),                      // pages 0-2
            (GuestAddress(region_size as u64), region_size),     // pages 3-5
            (GuestAddress(region_size as u64 * 2), region_size), // pages 6-8
        ];
        let guest_memory = GuestMemoryMmap::from_raw_regions(&regions, true).unwrap();

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
                guest_memory.mark_dirty(GuestAddress(*addr as u64), *len);
            }
        }

        // Check that the dirty memory was set correctly
        for (addr, len, dirty) in &dirty_map {
            guest_memory
                .try_access(
                    *len,
                    GuestAddress(*addr as u64),
                    |_total, count, caddr, region| {
                        let offset = usize::try_from(caddr.0).unwrap();
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
    fn test_describe() {
        let page_size: usize = get_page_size().unwrap();

        // Two regions of one page each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size),
            (GuestAddress(page_size as u64 * 2), page_size),
        ];
        let guest_memory = GuestMemoryMmap::from_raw_regions(&mem_regions[..], true).unwrap();

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size,
                    offset: 0,
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 2,
                    size: page_size,
                    offset: page_size as u64,
                },
            ],
        };

        let actual_memory_state = guest_memory.describe();
        assert_eq!(expected_memory_state, actual_memory_state);

        // Two regions of three pages each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size * 3),
            (GuestAddress(page_size as u64 * 4), page_size * 3),
        ];
        let guest_memory = GuestMemoryMmap::from_raw_regions(&mem_regions[..], true).unwrap();

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size * 3,
                    offset: 0,
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 4,
                    size: page_size * 3,
                    offset: page_size as u64 * 3,
                },
            ],
        };

        let actual_memory_state = guest_memory.describe();
        assert_eq!(expected_memory_state, actual_memory_state);
    }

    #[test]
    fn test_dump() {
        let page_size = get_page_size().unwrap();

        // Two regions of two pages each, with a one page gap between them.
        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(page_size as u64 * 3);
        let region_size = page_size * 2;
        let mem_regions = [
            (region_1_address, region_size),
            (region_2_address, region_size),
        ];
        let guest_memory = GuestMemoryMmap::from_raw_regions(&mem_regions, true).unwrap();
        // Check that Firecracker bitmap is clean.
        guest_memory.iter().for_each(|r| {
            assert!(!r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(1));
        });

        // Fill the first region with 1s and the second with 2s.
        let first_region = vec![1u8; region_size];
        guest_memory.write(&first_region, region_1_address).unwrap();

        let second_region = vec![2u8; region_size];
        guest_memory
            .write(&second_region, region_2_address)
            .unwrap();

        let memory_state = guest_memory.describe();

        // dump the full memory.
        let mut memory_file = TempFile::new().unwrap().into_file();
        guest_memory.dump(&mut memory_file).unwrap();

        let restored_guest_memory =
            GuestMemoryMmap::from_state(Some(&memory_file), &memory_state, false).unwrap();

        // Check that the region contents are the same.
        let mut restored_region = vec![0u8; page_size * 2];
        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_1_address)
            .unwrap();
        assert_eq!(first_region, restored_region);

        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_2_address)
            .unwrap();
        assert_eq!(second_region, restored_region);
    }

    #[test]
    fn test_dump_dirty() {
        let page_size = get_page_size().unwrap();

        // Two regions of two pages each, with a one page gap between them.
        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(page_size as u64 * 3);
        let region_size = page_size * 2;
        let mem_regions = [
            (region_1_address, region_size),
            (region_2_address, region_size),
        ];
        let guest_memory = GuestMemoryMmap::from_raw_regions(&mem_regions, true).unwrap();
        // Check that Firecracker bitmap is clean.
        guest_memory.iter().for_each(|r| {
            assert!(!r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(1));
        });

        // Fill the first region with 1s and the second with 2s.
        let first_region = vec![1u8; region_size];
        guest_memory.write(&first_region, region_1_address).unwrap();

        let second_region = vec![2u8; region_size];
        guest_memory
            .write(&second_region, region_2_address)
            .unwrap();

        let memory_state = guest_memory.describe();

        // Dump only the dirty pages.
        // First region pages: [dirty, clean]
        // Second region pages: [clean, dirty]
        let mut dirty_bitmap: DirtyBitmap = HashMap::new();
        dirty_bitmap.insert(0, vec![0b01]);
        dirty_bitmap.insert(1, vec![0b10]);

        let mut file = TempFile::new().unwrap().into_file();
        guest_memory.dump_dirty(&mut file, &dirty_bitmap).unwrap();

        // We can restore from this because this is the first dirty dump.
        let restored_guest_memory =
            GuestMemoryMmap::from_state(Some(&file), &memory_state, false).unwrap();

        // Check that the region contents are the same.
        let mut restored_region = vec![0u8; region_size];
        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_1_address)
            .unwrap();
        assert_eq!(first_region, restored_region);

        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_2_address)
            .unwrap();
        assert_eq!(second_region, restored_region);

        // Dirty the memory and dump again
        let file = TempFile::new().unwrap();
        let mut reader = file.into_file();
        let zeros = vec![0u8; page_size];
        let ones = vec![1u8; page_size];
        let twos = vec![2u8; page_size];

        // Firecracker Bitmap
        // First region pages: [dirty, clean]
        // Second region pages: [clean, clean]
        guest_memory
            .write(&twos, GuestAddress(page_size as u64))
            .unwrap();

        guest_memory.dump_dirty(&mut reader, &dirty_bitmap).unwrap();

        // Check that only the dirty regions are dumped.
        let mut diff_file_content = Vec::new();
        let expected_first_region = [
            ones.as_slice(),
            twos.as_slice(),
            zeros.as_slice(),
            twos.as_slice(),
        ]
        .concat();
        reader.seek(SeekFrom::Start(0)).unwrap();
        reader.read_to_end(&mut diff_file_content).unwrap();
        assert_eq!(expected_first_region, diff_file_content);
    }

    #[test]
    fn test_create_memfd() {
        let size = 1;
        let size_mb = 1 << 20;

        let memfd = create_memfd(size).unwrap();

        assert_eq!(memfd.as_file().metadata().unwrap().len(), size_mb);
        assert!(memfd.as_file().set_len(0x69).is_err());

        let mut seals = memfd::SealsHashSet::new();
        seals.insert(memfd::FileSeal::SealGrow);
        assert!(memfd.add_seals(&seals).is_err());
    }
}
