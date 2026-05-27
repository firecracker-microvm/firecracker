// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use vm_memory::{GuestMemoryError, ReadVolatile, WriteVolatile};

use crate::vstate::memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

use super::direct_io_eligible;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SyncIoError {
    /// Flush: {0}
    Flush(std::io::Error),
    /// Seek: {0}
    Seek(std::io::Error),
    /// SyncAll: {0}
    SyncAll(std::io::Error),
    /// Transfer: {0}
    Transfer(GuestMemoryError),
}

#[derive(Debug)]
pub struct SyncFileEngine {
    file: File,
    direct_file: Option<File>,
}

// SAFETY: `File` is send and ultimately a POD.
unsafe impl Send for SyncFileEngine {}

impl SyncFileEngine {
    pub fn from_file(file: File, direct_file: Option<File>) -> SyncFileEngine {
        SyncFileEngine { file, direct_file }
    }

    #[cfg(test)]
    pub fn file(&self) -> &File {
        &self.file
    }

    #[cfg(test)]
    pub fn direct_file(&self) -> Option<&File> {
        self.direct_file.as_ref()
    }

    /// Update the backing file of the engine
    pub fn update_file(&mut self, file: File, direct_file: Option<File>) {
        self.file = file;
        self.direct_file = direct_file;
    }

    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|mut slice| Ok(self.file.read_exact_volatile(&mut slice)?))
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(SyncIoError::Transfer)?;
        let buf = slice.ptr_guard().as_ptr() as usize;
        let file = match self.direct_file.as_mut() {
            Some(direct_file) if direct_io_eligible(buf, offset, count) => direct_file,
            _ => &mut self.file,
        };

        file.seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        file.write_all_volatile(&slice)
            .map_err(GuestMemoryError::from)
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    pub fn flush(&mut self) -> Result<(), SyncIoError> {
        // flush() first to force any cached data out of rust buffers.
        self.file.flush().map_err(SyncIoError::Flush)?;
        // Sync data out to physical media on host.
        self.file.sync_all().map_err(SyncIoError::SyncAll)
    }
}
