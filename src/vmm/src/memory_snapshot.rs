// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines functionality for creating guest memory snapshots.

use std::fs::File;
use std::io::SeekFrom;
use std::time::Instant;

use libc::{MAP_SHARED, PROT_WRITE};
use utils::vm_memory::{
    Bitmap, FileOffset, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap,
    GuestMemoryRegion, MemoryRegionAddress, WriteVolatile,
};
use utils::{errno, get_page_size};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

use crate::DirtyBitmap;

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

/// Defines the interface for snapshotting memory.
pub trait SnapshotMemory
where
    Self: Sized,
{
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState;
    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: WriteVolatile>(&self, writer: &mut T) -> std::result::Result<(), Error>;
    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> std::result::Result<(), Error>;
    /// Creates a GuestMemoryMmap given a `file` containing the data
    /// and a `state` containing mapping information.
    fn restore(
        file: Option<&File>,
        state: &GuestMemoryState,
        track_dirty_pages: bool,
    ) -> std::result::Result<Self, Error>;
}

/// Errors associated with dumping guest memory to file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Cannot access file.
    #[error("Cannot access file: {0:?}")]
    FileHandle(#[from] std::io::Error),
    /// Cannot create memory.
    #[error("Cannot create memory: {0:?}")]
    CreateMemory(#[from] utils::vm_memory::Error),
    /// Cannot create region.
    #[error("Cannot create memory region: {0:?}")]
    CreateRegion(#[from] utils::vm_memory::MmapRegionError),
    /// Cannot fetch system's page size.
    #[error("Cannot fetch system's page size: {0:?}")]
    PageSize(#[from] errno::Error),
    /// Cannot dump memory.
    #[error("Cannot dump memory: {0:?}")]
    WriteMemory(#[from] GuestMemoryError),
}

impl SnapshotMemory for GuestMemoryMmap {
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState {
        let mut guest_memory_state = GuestMemoryState::default();
        let mut offset = 0;
        self.iter().for_each(|region| {
            guest_memory_state.regions.push(GuestMemoryRegionState {
                base_address: region.start_addr().0,
                size: region.len() as usize,
                offset,
            });

            offset += region.len();
        });
        guest_memory_state
    }

    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: WriteVolatile>(&self, writer: &mut T) -> std::result::Result<(), Error> {
        self.iter()
            .try_for_each(|region| Ok(writer.write_all_volatile(&region.as_volatile_slice()?)?))
            .map_err(Error::WriteMemory)
    }

    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> std::result::Result<(), Error> {
        let mut writer_offset = 0;
        let page_size = get_page_size()?;

        let start = Instant::now();
        let mut total_written = 0;

        let res = self
            .iter()
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
                            let start = Instant::now();
                            // We are at the end of a batch of dirty pages.
                            writer.write_all_volatile(
                                &region.get_slice(
                                    MemoryRegionAddress(dirty_batch_start),
                                    write_size,
                                )?,
                            )?;
                            eprintln!(
                                "writing {}B took {}ms",
                                write_size,
                                start.elapsed().as_millis()
                            );
                            total_written += write_size;

                            write_size = 0;
                        }
                    }
                }

                if write_size > 0 {
                    writer.write_all_volatile(
                        &region.get_slice(MemoryRegionAddress(dirty_batch_start), write_size)?,
                    )?;
                    total_written += write_size;
                    eprintln!(
                        "writing {}B took {}ms",
                        write_size,
                        start.elapsed().as_millis()
                    );
                }
                writer_offset += region.len();
                if let Some(bitmap) = firecracker_bitmap {
                    bitmap.reset();
                }

                Ok(())
            })
            .map_err(Error::WriteMemory);

        eprintln!(
            "total write time: {}ms, total written: {}B",
            start.elapsed().as_millis(),
            total_written
        );

        res
    }

    /// Creates a GuestMemoryMmap backed by a `file` if present, otherwise backed
    /// by anonymous memory. Memory layout and ranges are described in `state` param.
    fn restore(
        file: Option<&File>,
        state: &GuestMemoryState,
        track_dirty_pages: bool,
    ) -> std::result::Result<Self, Error> {
        let mut regions = vec![];
        for region in state.regions.iter() {
            let f = match file {
                Some(f) => Some(FileOffset::new(f.try_clone()?, region.offset)),
                None => None,
            };

            regions.push((f, GuestAddress(region.base_address), region.size));
        }

        utils::vm_memory::create_guest_memory(&regions, track_dirty_pages)
            .map_err(Error::CreateMemory)
    }
}

/// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
pub fn mem_dump_dirty(
    mem_map: &GuestMemoryMmap,
    fd: i32,
    len: usize,
    dirty_bitmap: &DirtyBitmap,
) -> std::result::Result<(), Error> {
    let mut writer_offset = 0_u64;
    let page_size = get_page_size()?;

    let start = Instant::now();
    let mut total_written = 0;

    let source_map =
        unsafe { libc::mmap(std::ptr::null_mut(), len, PROT_WRITE, MAP_SHARED, fd, 0) };

    let res = mem_map
        .iter()
        .enumerate()
        .try_for_each(|(slot, region)| {
            let kvm_bitmap = dirty_bitmap.get(&slot).unwrap();
            let firecracker_bitmap = region.bitmap();
            let mut write_size = 0;
            let mut dirty_batch_start: u64 = 0;

            let mmap_base = region.get_host_address(MemoryRegionAddress(0)).unwrap();
            for (i, v) in kvm_bitmap.iter().enumerate() {
                for j in 0..64 {
                    let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;
                    let page_offset = ((i * 64) + j) * page_size;
                    let is_firecracker_page_dirty = firecracker_bitmap.dirty_at(page_offset);
                    if is_kvm_page_dirty || is_firecracker_page_dirty {
                        // We are at the start of a new batch of dirty pages.
                        if write_size == 0 {
                            // Seek forward over the unmodified pages.
                            dirty_batch_start = page_offset as u64;
                        }
                        write_size += page_size;
                    } else if write_size > 0 {
                        let start = Instant::now();

                        eprintln!(
                            "starting write of {}B  (source {}, dest {})",
                            write_size,
                            dirty_batch_start,
                            writer_offset + dirty_batch_start
                        );
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                mmap_base.offset((dirty_batch_start) as isize),
                                source_map.offset((writer_offset + dirty_batch_start) as isize)
                                    as *mut u8,
                                write_size,
                            );
                        }

                        eprintln!(
                            "writing {}B took {}ms",
                            write_size,
                            start.elapsed().as_millis()
                        );
                        total_written += write_size;
                        write_size = 0;
                    }
                }
            }

            if write_size > 0 {
                let start = Instant::now();

                eprintln!(
                    "starting final write of {}B (source {}, dest {}) (total_size: {})",
                    write_size,
                    dirty_batch_start,
                    writer_offset + dirty_batch_start,
                    len
                );
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        mmap_base.offset((dirty_batch_start) as isize),
                        source_map.offset((writer_offset + dirty_batch_start) as isize) as *mut u8,
                        write_size,
                    );
                }
                total_written += write_size;
                eprintln!(
                    "writing {}B took {}ms",
                    write_size,
                    start.elapsed().as_millis()
                );
            }
            writer_offset += region.len();
            if let Some(bitmap) = firecracker_bitmap {
                bitmap.reset();
            }

            Ok(())
        })
        .map_err(Error::WriteMemory);

    eprintln!(
        "total write time: {}ms, total written: {}B",
        start.elapsed().as_millis(),
        total_written
    );

    eprintln!("memfd {}, len {}", fd, len);

    res
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{Read, Seek};

    use utils::get_page_size;
    use utils::tempfile::TempFile;
    use utils::vm_memory::{Bytes, GuestAddress};

    use super::*;

    #[test]
    fn test_describe_state() {
        let page_size: usize = get_page_size().unwrap();

        // Two regions of one page each, with a one page gap between them.
        let mem_regions = [
            (None, GuestAddress(0), page_size),
            (None, GuestAddress(page_size as u64 * 2), page_size),
        ];
        let guest_memory = utils::vm_memory::create_guest_memory(&mem_regions[..], true).unwrap();

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
            (None, GuestAddress(0), page_size * 3),
            (None, GuestAddress(page_size as u64 * 4), page_size * 3),
        ];
        let guest_memory = utils::vm_memory::create_guest_memory(&mem_regions[..], true).unwrap();

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
        let page_size: usize = get_page_size().unwrap();

        // Two regions of two pages each, with a one page gap between them.
        let mem_regions = [
            (None, GuestAddress(0), page_size * 2),
            (None, GuestAddress(page_size as u64 * 3), page_size * 2),
        ];
        let guest_memory = utils::vm_memory::create_guest_memory(&mem_regions[..], true).unwrap();
        // Check that Firecracker bitmap is clean.
        let _res: std::result::Result<(), Error> = guest_memory.iter().try_for_each(|r| {
            assert!(!r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(1));
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
            let mut memory_file = TempFile::new().unwrap().into_file();
            guest_memory.dump(&mut memory_file).unwrap();

            let restored_guest_memory =
                GuestMemoryMmap::restore(Some(&memory_file), &memory_state, false).unwrap();

            // Check that the region contents are the same.
            let mut actual_region = vec![0u8; page_size * 2];
            restored_guest_memory
                .read(actual_region.as_mut_slice(), GuestAddress(0))
                .unwrap();
            assert_eq!(first_region, actual_region);

            restored_guest_memory
                .read(
                    actual_region.as_mut_slice(),
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

            let mut file = TempFile::new().unwrap().into_file();
            guest_memory.dump_dirty(&mut file, &dirty_bitmap).unwrap();

            // We can restore from this because this is the first dirty dump.
            let restored_guest_memory =
                GuestMemoryMmap::restore(Some(&file), &memory_state, false).unwrap();

            // Check that the region contents are the same.
            let mut actual_region = vec![0u8; page_size * 2];
            restored_guest_memory
                .read(actual_region.as_mut_slice(), GuestAddress(0))
                .unwrap();
            assert_eq!(first_region, actual_region);

            restored_guest_memory
                .read(
                    actual_region.as_mut_slice(),
                    GuestAddress(page_size as u64 * 3),
                )
                .unwrap();
            assert_eq!(second_region, actual_region);

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
