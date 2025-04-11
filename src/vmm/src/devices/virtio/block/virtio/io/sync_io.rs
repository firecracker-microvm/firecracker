// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use vm_memory::{GuestMemoryError, ReadVolatile, WriteVolatile};

use crate::vstate::memory::{GuestAddress, GuestMemory, GuestMemoryMmap, MaybeBounce};

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
    // 65536 is the largest buffer a linux guest will give us, empirically. Determined by
    // having `MaybeBounce` logging scenarios where the fixed size bounce buffer isn't sufficient.
    // Note that even if this assumption ever changes, the worse that'll happen is that we do
    // multiple roundtrips between guest memory and the bounce buffer, as MaybeBounce would
    // just chop larger reads/writes into chunks of 65k.
    file: MaybeBounce<File, { u16::MAX as usize + 1 }>,
}

// SAFETY: `File` is send and ultimately a POD.
unsafe impl Send for SyncFileEngine {}

impl SyncFileEngine {
    pub fn from_file(file: File) -> SyncFileEngine {
        SyncFileEngine {
            file: MaybeBounce::new_persistent(file, false),
        }
    }

    #[cfg(test)]
    pub fn file(&self) -> &File {
        &self.file.target
    }

    pub fn start_bouncing(&mut self) {
        self.file.activate()
    }

    pub fn is_bouncing(&self) -> bool {
        self.file.is_activated()
    }

    /// Update the backing file of the engine
    pub fn update_file(&mut self, file: File) {
        self.file.target = file
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
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|slice| Ok(self.file.write_all_volatile(&slice)?))
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    pub fn flush(&mut self) -> Result<(), SyncIoError> {
        // flush() first to force any cached data out of rust buffers.
        self.file.target.flush().map_err(SyncIoError::Flush)?;
        // Sync data out to physical media on host.
        self.file.target.sync_all().map_err(SyncIoError::SyncAll)
    }
}
