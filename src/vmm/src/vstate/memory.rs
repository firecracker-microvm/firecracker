// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fs::File;
use std::io::SeekFrom;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
pub use vm_memory::bitmap::{AtomicBitmap, BS, Bitmap, BitmapSlice};
pub use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::mmap::{MmapRegionError, NewBitmap};
pub use vm_memory::{
    Address, ByteValued, Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryRegion,
    GuestUsize, MemoryRegionAddress, MmapRegion, address,
};
use vm_memory::{Error as VmMemoryError, GuestMemoryError, WriteVolatile};
use vmm_sys_util::errno;

use crate::DirtyBitmap;
use crate::utils::{get_page_size, u64_to_usize};
use crate::vmm_config::machine_config::HugePageConfig;

/// Type of GuestMemoryMmap.
pub type GuestMemoryMmap = vm_memory::GuestMemoryMmap<Option<AtomicBitmap>>;
/// Type of GuestRegionMmap.
pub type GuestRegionMmap = vm_memory::GuestRegionMmap<Option<AtomicBitmap>>;
/// Type of GuestMmapRegion.
pub type GuestMmapRegion = vm_memory::MmapRegion<Option<AtomicBitmap>>;

/// Errors associated with dumping guest memory to file.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MemoryError {
    /// Cannot fetch system's page size: {0}
    PageSize(errno::Error),
    /// Cannot dump memory: {0}
    WriteMemory(GuestMemoryError),
    /// Cannot create mmap region: {0}
    MmapRegionError(MmapRegionError),
    /// Cannot create guest memory: {0}
    VmMemoryError(VmMemoryError),
    /// Cannot create memfd: {0}
    Memfd(memfd::Error),
    /// Cannot resize memfd file: {0}
    MemfdSetLen(std::io::Error),
    /// Total sum of memory regions exceeds largest possible file offset
    OffsetTooLarge,
}

/// Creates a `Vec` of `GuestRegionMmap` with the given configuration
pub fn create(
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    mmap_flags: libc::c_int,
    file: Option<File>,
    track_dirty_pages: bool,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    let mut offset = 0;
    let file = file.map(Arc::new);
    regions
        .map(|(start, size)| {
            let mut builder = MmapRegionBuilder::new_with_bitmap(
                size,
                track_dirty_pages.then(|| AtomicBitmap::with_len(size)),
            )
            .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
            .with_mmap_flags(libc::MAP_NORESERVE | mmap_flags);

            if let Some(ref file) = file {
                let file_offset = FileOffset::from_arc(Arc::clone(file), offset);

                builder = builder.with_file_offset(file_offset);
            }

            offset = match offset.checked_add(size as u64) {
                None => return Err(MemoryError::OffsetTooLarge),
                Some(new_off) if new_off >= i64::MAX as u64 => {
                    return Err(MemoryError::OffsetTooLarge);
                }
                Some(new_off) => new_off,
            };

            GuestRegionMmap::new(
                builder.build().map_err(MemoryError::MmapRegionError)?,
                start,
            )
            .map_err(MemoryError::VmMemoryError)
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Creates a GuestMemoryMmap with `size` in MiB backed by a memfd.
pub fn memfd_backed(
    regions: &[(GuestAddress, usize)],
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    let size = regions.iter().map(|&(_, size)| size as u64).sum();
    let memfd_file = create_memfd(size, huge_pages.into())?.into_file();

    create(
        regions.iter().copied(),
        libc::MAP_SHARED | huge_pages.mmap_flags(),
        Some(memfd_file),
        track_dirty_pages,
    )
}

/// Creates a GuestMemoryMmap from raw regions.
pub fn anonymous(
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    create(
        regions,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | huge_pages.mmap_flags(),
        None,
        track_dirty_pages,
    )
}

/// Creates a GuestMemoryMmap given a `file` containing the data
/// and a `state` containing mapping information.
pub fn snapshot_file(
    file: File,
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    create(regions, libc::MAP_PRIVATE, Some(file), track_dirty_pages)
}

/// Defines the interface for snapshotting memory.
pub trait GuestMemoryExtension
where
    Self: Sized,
{
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

    /// Resets all the memory region bitmaps
    fn reset_dirty(&self);

    /// Store the dirty bitmap in internal store
    fn store_dirty_bitmap(&self, dirty_bitmap: &DirtyBitmap, page_size: usize);
}

/// State of a guest memory region saved to file/buffer.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryRegionState {
    // This should have been named `base_guest_addr` since it's _guest_ addr, but for
    // backward compatibility we have to keep this name. At least this comment should help.
    /// Base GuestAddress.
    pub base_address: u64,
    /// Region size.
    pub size: usize,
}

/// Describes guest memory regions and their snapshot file mappings.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryState {
    /// List of regions.
    pub regions: Vec<GuestMemoryRegionState>,
}

impl GuestMemoryState {
    /// Turns this [`GuestMemoryState`] into a description of guest memory regions as understood
    /// by the creation functions of [`GuestMemoryExtensions`]
    pub fn regions(&self) -> impl Iterator<Item = (GuestAddress, usize)> + '_ {
        self.regions
            .iter()
            .map(|region| (GuestAddress(region.base_address), region.size))
    }
}

impl GuestMemoryExtension for GuestMemoryMmap {
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState {
        let mut guest_memory_state = GuestMemoryState::default();
        self.iter().for_each(|region| {
            guest_memory_state.regions.push(GuestMemoryRegionState {
                base_address: region.start_addr().0,
                size: u64_to_usize(region.len()),
            });
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

        let write_result = self.iter().zip(0..).try_for_each(|(region, slot)| {
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
                            &region
                                .get_slice(MemoryRegionAddress(dirty_batch_start), write_size)?,
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

            Ok(())
        });

        if write_result.is_err() {
            self.store_dirty_bitmap(dirty_bitmap, page_size);
        } else {
            self.reset_dirty();
        }

        write_result.map_err(MemoryError::WriteMemory)
    }

    /// Resets all the memory region bitmaps
    fn reset_dirty(&self) {
        self.iter().for_each(|region| {
            if let Some(bitmap) = region.bitmap() {
                bitmap.reset();
            }
        })
    }

    /// Stores the dirty bitmap inside into the internal bitmap
    fn store_dirty_bitmap(&self, dirty_bitmap: &DirtyBitmap, page_size: usize) {
        self.iter().zip(0..).for_each(|(region, slot)| {
            let kvm_bitmap = dirty_bitmap.get(&slot).unwrap();
            let firecracker_bitmap = region.bitmap();

            for (i, v) in kvm_bitmap.iter().enumerate() {
                for j in 0..64 {
                    let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;

                    if is_kvm_page_dirty {
                        let page_offset = ((i * 64) + j) * page_size;

                        firecracker_bitmap.mark_dirty(page_offset, 1)
                    }
                }
            }
        });
    }
}

fn create_memfd(
    mem_size: u64,
    hugetlb_size: Option<memfd::HugetlbSize>,
) -> Result<memfd::Memfd, MemoryError> {
    // Create a memfd.
    let opts = memfd::MemfdOptions::default()
        .hugetlb(hugetlb_size)
        .allow_sealing(true);
    let mem_file = opts.create("guest_mem").map_err(MemoryError::Memfd)?;

    // Resize to guest mem size.
    mem_file
        .as_file()
        .set_len(mem_size)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::collections::HashMap;
    use std::io::{Read, Seek};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::snapshot::Snapshot;
    use crate::utils::{get_page_size, mib_to_bytes};

    #[test]
    fn test_anonymous() {
        for dirty_page_tracking in [true, false] {
            let region_size = 0x10000;
            let regions = vec![
                (GuestAddress(0x0), region_size),
                (GuestAddress(0x10000), region_size),
                (GuestAddress(0x20000), region_size),
                (GuestAddress(0x30000), region_size),
            ];

            let guest_memory = anonymous(
                regions.into_iter(),
                dirty_page_tracking,
                HugePageConfig::None,
            )
            .unwrap();
            guest_memory.iter().for_each(|region| {
                assert_eq!(region.bitmap().is_some(), dirty_page_tracking);
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
        let guest_memory = GuestMemoryMmap::from_regions(
            anonymous(regions.into_iter(), true, HugePageConfig::None).unwrap(),
        )
        .unwrap();

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

    fn check_serde(guest_memory: &GuestMemoryMmap) {
        let mut snapshot_data = vec![0u8; 10000];
        let original_state = guest_memory.describe();
        Snapshot::serialize(&mut snapshot_data.as_mut_slice(), &original_state).unwrap();
        let restored_state = Snapshot::deserialize(&mut snapshot_data.as_slice()).unwrap();
        assert_eq!(original_state, restored_state);
    }

    #[test]
    fn test_serde() {
        let page_size = get_page_size().unwrap();
        let region_size = page_size * 3;

        // Test with a single region
        let guest_memory = GuestMemoryMmap::from_regions(
            anonymous(
                [(GuestAddress(0), region_size)].into_iter(),
                false,
                HugePageConfig::None,
            )
            .unwrap(),
        )
        .unwrap();
        check_serde(&guest_memory);

        // Test with some regions
        let regions = vec![
            (GuestAddress(0), region_size),                      // pages 0-2
            (GuestAddress(region_size as u64), region_size),     // pages 3-5
            (GuestAddress(region_size as u64 * 2), region_size), // pages 6-8
        ];
        let guest_memory = GuestMemoryMmap::from_regions(
            anonymous(regions.into_iter(), true, HugePageConfig::None).unwrap(),
        )
        .unwrap();
        check_serde(&guest_memory);
    }

    #[test]
    fn test_describe() {
        let page_size: usize = get_page_size().unwrap();

        // Two regions of one page each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size),
            (GuestAddress(page_size as u64 * 2), page_size),
        ];
        let guest_memory = GuestMemoryMmap::from_regions(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        )
        .unwrap();

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size,
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 2,
                    size: page_size,
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
        let guest_memory = GuestMemoryMmap::from_regions(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        )
        .unwrap();

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size * 3,
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 4,
                    size: page_size * 3,
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
        let guest_memory = GuestMemoryMmap::from_regions(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        )
        .unwrap();
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

        let restored_guest_memory = GuestMemoryMmap::from_regions(
            snapshot_file(memory_file, memory_state.regions(), false).unwrap(),
        )
        .unwrap();

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
        let guest_memory = GuestMemoryMmap::from_regions(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        )
        .unwrap();
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
        let restored_guest_memory = GuestMemoryMmap::from_regions(
            snapshot_file(file, memory_state.regions(), false).unwrap(),
        )
        .unwrap();

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
    fn test_store_dirty_bitmap() {
        let page_size = get_page_size().unwrap();

        // Two regions of three pages each, with a one page gap between them.
        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(page_size as u64 * 4);
        let region_size = page_size * 3;
        let mem_regions = [
            (region_1_address, region_size),
            (region_2_address, region_size),
        ];
        let guest_memory = GuestMemoryMmap::from_regions(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        )
        .unwrap();

        // Check that Firecracker bitmap is clean.
        guest_memory.iter().for_each(|r| {
            assert!(!r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(page_size));
            assert!(!r.bitmap().dirty_at(page_size * 2));
        });

        let mut dirty_bitmap: DirtyBitmap = HashMap::new();
        dirty_bitmap.insert(0, vec![0b101]);
        dirty_bitmap.insert(1, vec![0b101]);

        guest_memory.store_dirty_bitmap(&dirty_bitmap, page_size);

        // Assert that the bitmap now reports as being dirty maching the dirty bitmap
        guest_memory.iter().for_each(|r| {
            assert!(r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(page_size));
            assert!(r.bitmap().dirty_at(page_size * 2));
        });
    }

    #[test]
    fn test_create_memfd() {
        let size_bytes = mib_to_bytes(1) as u64;

        let memfd = create_memfd(size_bytes, None).unwrap();

        assert_eq!(memfd.as_file().metadata().unwrap().len(), size_bytes);
        memfd.as_file().set_len(0x69).unwrap_err();

        let mut seals = memfd::SealsHashSet::new();
        seals.insert(memfd::FileSeal::SealGrow);
        memfd.add_seals(&seals).unwrap_err();
    }
}
