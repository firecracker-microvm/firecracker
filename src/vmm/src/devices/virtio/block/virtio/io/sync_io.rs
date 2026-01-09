// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;

use libc::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, c_int, off64_t};
use vm_memory::{GuestMemoryError, ReadVolatile, WriteVolatile};

use crate::vstate::memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

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
    /// Discard: {0}
    Discard(std::io::Error),
}

#[derive(Debug)]
pub struct SyncFileEngine {
    file: File,
}

// SAFETY: `File` is send and ultimately a POD.
unsafe impl Send for SyncFileEngine {}

impl SyncFileEngine {
    pub fn from_file(file: File) -> SyncFileEngine {
        SyncFileEngine { file }
    }

    #[cfg(test)]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Update the backing file of the engine
    pub fn update_file(&mut self, file: File) {
        self.file = file
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
        self.file.flush().map_err(SyncIoError::Flush)?;
        // Sync data out to physical media on host.
        self.file.sync_all().map_err(SyncIoError::SyncAll)
    }

    pub fn discard(&mut self, offset: u64, len: u32) -> Result<u32, SyncIoError> {
        // Do checked conversion to avoid possible wrap/cast issues on 64-bit systems.
        let off_i64 = i64::try_from(offset).map_err(|_| {
            SyncIoError::Discard(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "offset overflow",
            ))
        })?;

        let len_i64: i64 = len.into();

        // # Safety: calling libc::fallocate is safe here because:
        // - `self.file.as_raw_fd()` is a valid file descriptor owned by this struct,
        // - `off_i64` and `len_i64` are validated copies of the incoming unsigned values converted
        //   to the C `off64_t` type, and
        // - the syscall is properly checked for an error return value.
        unsafe {
            let ret = libc::fallocate(
                self.file.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                off_i64,
                len_i64,
            );
            if ret != 0 {
                error!(
                    "DISCARD fallocate failed (offset={}, len={}): {:?}",
                    offset,
                    len,
                    std::io::Error::last_os_error()
                );
                return Ok(len);
            }
        }
        Ok(len)
    }
}
