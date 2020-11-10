// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines functionality for creating guest memory snapshots.

// Currently only used on x86_64.
#![cfg(target_arch = "x86_64")]

use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::SeekFrom;

use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::{
    Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap,
    GuestMemoryRegion, GuestRegionMmap, MemoryRegionAddress, MmapRegion,
};

use crate::DirtyBitmap;

/// State of a guest memory region saved to file/buffer.
#[derive(Debug, PartialEq, Versionize)]
pub struct GuestMemoryRegionState {
    /// Base address.
    pub base_address: u64,
    /// Region size.
    pub size: usize,
    /// Offset in file/buffer where the region is saved.
    pub offset: u64,
}

/// Guest memory state.
#[derive(Debug, Default, PartialEq, Versionize)]
pub struct GuestMemoryState {
    /// List of regions.
    pub regions: Vec<GuestMemoryRegionState>,
}

/// Defines the interface for snapshotting memory.
pub trait SnapshotMemory
where
    Self: Sized,
{
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState;
    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: std::io::Write>(&self, writer: &mut T) -> std::result::Result<(), Error>;
    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> std::result::Result<(), Error>;
    /// Creates a GuestMemoryMmap given a `file` containing the data
    /// and a `state` containing mapping information.
    fn restore(
        file: &File,
        state: &GuestMemoryState,
        track_dirty_pages: bool,
    ) -> std::result::Result<Self, Error>;
}

/// Errors associated with dumping guest memory to file.
#[derive(Debug)]
pub enum Error {
    /// Cannot access file.
    FileHandle(std::io::Error),
    /// Cannot create memory.
    CreateMemory(vm_memory::Error),
    /// Cannot create region.
    CreateRegion(vm_memory::mmap::MmapRegionError),
    /// Cannot dump memory.
    WriteMemory(GuestMemoryError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;
        match self {
            FileHandle(err) => write!(f, "Cannot access file: {:?}", err),
            CreateMemory(err) => write!(f, "Cannot create memory: {:?}", err),
            CreateRegion(err) => write!(f, "Cannot create memory region: {:?}", err),
            WriteMemory(err) => write!(f, "Cannot dump memory: {:?}", err),
        }
    }
}

impl SnapshotMemory for GuestMemoryMmap {
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState {
        let mut guest_memory_state = GuestMemoryState::default();
        let mut offset = 0;
        let _: std::result::Result<(), ()> = self.with_regions_mut(|_, region| {
            guest_memory_state.regions.push(GuestMemoryRegionState {
                base_address: region.start_addr().0,
                size: region.len() as usize,
                offset,
            });

            offset += region.len();
            Ok(())
        });
        guest_memory_state
    }

    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: std::io::Write>(&self, writer: &mut T) -> std::result::Result<(), Error> {
        self.with_regions_mut(|_, region| {
            region.write_all_to(MemoryRegionAddress(0), writer, region.len() as usize)
        })
        .map_err(Error::WriteMemory)
    }

    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> std::result::Result<(), Error> {
        let page_size = sysconf::page::pagesize();
        let mut writer_offset = 0;

        self.with_regions_mut(|slot, region| {
            let kvm_bitmap = dirty_bitmap.get(&slot).unwrap();
            let firecracker_bitmap = region.dirty_bitmap().unwrap();
            let mut write_size = 0;
            let mut dirty_batch_start: u64 = 0;

            for (i, v) in kvm_bitmap.iter().enumerate() {
                for j in 0..64 {
                    let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;
                    let page_offset = ((i * 64) + j) * page_size;
                    let is_firecracker_page_dirty = firecracker_bitmap.is_addr_set(page_offset);
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
                        region.write_all_to(
                            MemoryRegionAddress(dirty_batch_start),
                            writer,
                            write_size,
                        )?;
                        write_size = 0;
                    }
                }
            }

            if write_size > 0 {
                region.write_all_to(MemoryRegionAddress(dirty_batch_start), writer, write_size)?;
            }

            writer_offset += region.len();
            firecracker_bitmap.reset();

            Ok(())
        })
        .map_err(Error::WriteMemory)
    }

    /// Creates a GuestMemoryMmap given a `file` containing the data
    /// and a `state` containing mapping information.
    fn restore(
        file: &File,
        state: &GuestMemoryState,
        track_dirty_pages: bool,
    ) -> std::result::Result<Self, Error> {
        let mut mmap_regions = Vec::new();
        for region in state.regions.iter() {
            let mmap_region = MmapRegion::build(
                Some(FileOffset::new(
                    file.try_clone().map_err(Error::FileHandle)?,
                    region.offset,
                )),
                region.size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_NORESERVE | libc::MAP_PRIVATE,
            )
            .map(|r| {
                let mut region = GuestRegionMmap::new(r, GuestAddress(region.base_address))?;
                if track_dirty_pages {
                    region.enable_dirty_page_tracking();
                }
                Ok(region)
            })
            .map_err(Error::CreateRegion)?
            .map_err(Error::CreateMemory)?;

            mmap_regions.push(mmap_region);
        }

        Ok(Self::from_regions(mmap_regions).map_err(Error::CreateMemory)?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use std::io::{Read, Seek};
    use utils::tempfile::TempFile;
    use vm_memory::GuestAddress;

    #[test]
    fn test_describe_state() {
        let page_size: usize = sysconf::page::pagesize();

        // Two regions of one page each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size),
            (GuestAddress(page_size as u64 * 2), page_size),
        ];
        let guest_memory = GuestMemoryMmap::from_ranges(&mem_regions[..]).unwrap();

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
        let guest_memory = GuestMemoryMmap::from_ranges(&mem_regions[..]).unwrap();

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
    fn test_restore_memory() {
        let page_size: usize = sysconf::page::pagesize();

        // Two regions of two pages each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size * 2),
            (GuestAddress(page_size as u64 * 3), page_size * 2),
        ];
        let guest_memory = GuestMemoryMmap::from_ranges_with_tracking(&mem_regions[..]).unwrap();
        // Check that Firecracker bitmap is clean.
        let _res: std::result::Result<(), Error> = guest_memory.with_regions(|_, r| {
            assert!(!r.dirty_bitmap().unwrap().is_bit_set(0));
            assert!(!r.dirty_bitmap().unwrap().is_bit_set(1));
            Ok(())
        });

        // Fill the first region with 1s and the second with 2s.
        let first_region = vec![1u8; page_size * 2];
        guest_memory
            .write(&first_region[..], GuestAddress(0))
            .unwrap();

        let second_region = vec![2u8; page_size * 2];
        guest_memory
            .write(&second_region[..], GuestAddress(page_size as u64 * 3))
            .unwrap();

        let memory_state = guest_memory.describe();

        // Case 1: dump the full memory.
        {
            let memory_file = TempFile::new().unwrap();
            guest_memory.dump(&mut memory_file.as_file()).unwrap();

            let restored_guest_memory =
                GuestMemoryMmap::restore(&memory_file.as_file(), &memory_state, false).unwrap();

            // Check that the region contents are the same.
            let mut actual_region = vec![0u8; page_size * 2];
            restored_guest_memory
                .read(&mut actual_region.as_mut_slice(), GuestAddress(0))
                .unwrap();
            assert_eq!(first_region, actual_region);

            restored_guest_memory
                .read(
                    &mut actual_region.as_mut_slice(),
                    GuestAddress(page_size as u64 * 3),
                )
                .unwrap();
            assert_eq!(second_region, actual_region);
        }

        // Case 2: dump only the dirty pages.
        {
            // KVM Bitmap
            // First region pages: [dirty, clean]
            // Second region pages: [clean, dirty]
            let mut dirty_bitmap: DirtyBitmap = HashMap::new();
            dirty_bitmap.insert(0, vec![0b01; 1]);
            dirty_bitmap.insert(1, vec![0b10; 1]);

            let file = TempFile::new().unwrap();
            guest_memory
                .dump_dirty(&mut file.as_file(), &dirty_bitmap)
                .unwrap();

            // We can restore from this because this is the first dirty dump.
            let restored_guest_memory =
                GuestMemoryMmap::restore(&file.as_file(), &memory_state, false).unwrap();

            // Check that the region contents are the same.
            let mut actual_region = vec![0u8; page_size * 2];
            restored_guest_memory
                .read(&mut actual_region.as_mut_slice(), GuestAddress(0))
                .unwrap();
            assert_eq!(first_region, actual_region);

            restored_guest_memory
                .read(
                    &mut actual_region.as_mut_slice(),
                    GuestAddress(page_size as u64 * 3),
                )
                .unwrap();
            assert_eq!(second_region, actual_region);

            // Dirty the memory and dump again
            let file = TempFile::new().unwrap();
            let mut reader = file.as_file();
            let zeros = vec![0u8; page_size];
            let ones = vec![1u8; page_size];
            let twos = vec![2u8; page_size];

            // Firecracker Bitmap
            // First region pages: [dirty, clean]
            // Second region pages: [clean, clean]
            guest_memory
                .write(&twos[..], GuestAddress(page_size as u64))
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
    }
}
