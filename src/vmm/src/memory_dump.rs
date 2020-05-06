// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines functionality for creating guest memory snapshots.

use std::fmt::{Display, Formatter};
use std::io::SeekFrom;

use vm_memory::{
    Bytes, GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion, MemoryRegionAddress,
};

use crate::DirtyBitmap;

/// Defines the interface for dumping memory a file.
pub trait DumpMemory {
    fn dump<T: std::io::Write>(&self, writer: &mut T) -> std::result::Result<(), Error>;
    fn dump_dirty<T: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> std::result::Result<(), Error>;
}

/// Errors associated with dumping guest memory to file.
#[derive(Debug)]
pub enum Error {
    WriteMemory(GuestMemoryError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;
        match self {
            WriteMemory(err) => write!(f, "Unable to dump memory: {:?}", err),
        }
    }
}

impl DumpMemory for GuestMemoryMmap {
    fn dump<T: std::io::Write>(&self, writer: &mut T) -> std::result::Result<(), Error> {
        self.with_regions_mut(|_, region| {
            region
                .write_to(MemoryRegionAddress(0), writer, region.len() as usize)
                .map(|_| ())
        })
        .map_err(Error::WriteMemory)?;

        Ok(())
    }

    fn dump_dirty<T: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> std::result::Result<(), Error> {
        let page_size = sysconf::page::pagesize();
        let mut writer_offset = 0;

        self.with_regions_mut(|slot, region| {
            let bitmap = dirty_bitmap.get(&slot).unwrap();
            let mut write_size = 0;
            let mut dirty_batch_start = 0;

            for (i, v) in bitmap.iter().enumerate() {
                for j in 0..64 {
                    let is_dirty_page = ((v >> j) & 1u64) != 0u64;
                    if is_dirty_page {
                        let page_offset = ((i * 64) + j) * page_size;
                        // We are at the start of a new batch of dirty pages.
                        if write_size == 0 {
                            // Seek forward over the unmodified pages.
                            writer
                                .seek(SeekFrom::Start(writer_offset + page_offset as u64))
                                .unwrap();
                            dirty_batch_start = page_offset;
                        }
                        write_size += page_size;
                    } else if write_size > 0 {
                        // We are at the end of a batch of dirty pages.
                        region
                            .write_to(
                                MemoryRegionAddress(dirty_batch_start as u64),
                                writer,
                                write_size,
                            )
                            .map(|_| ())?;
                        write_size = 0;
                    }
                }
            }

            if write_size > 0 {
                region
                    .write_to(
                        MemoryRegionAddress(dirty_batch_start as u64),
                        writer,
                        write_size,
                    )
                    .map(|_| ())?;
            }

            writer_offset += region.len();
            Ok(())
        })
        .map_err(Error::WriteMemory)?;

        Ok(())
    }
}
