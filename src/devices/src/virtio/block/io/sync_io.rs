// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Seek, SeekFrom, Write};
use std::result::Result;

use std::fs::File;
use vm_memory::{Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

#[derive(Debug)]
pub enum Error {
    Flush(std::io::Error),
    Seek(std::io::Error),
    SyncAll(std::io::Error),
    Transfer(GuestMemoryError),
}

pub struct SyncFileEngine {
    file: File,
}

unsafe impl Send for SyncFileEngine {}

impl SyncFileEngine {
    pub fn from_file(file: File) -> SyncFileEngine {
        SyncFileEngine { file }
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, Error> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(Error::Seek)?;
        mem.read_from(addr, &mut self.file, count as usize)
            .map(|count| count as u32)
            .map_err(Error::Transfer)
    }

    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, Error> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(Error::Seek)?;
        mem.write_to(addr, &mut self.file, count as usize)
            .map(|count| count as u32)
            .map_err(Error::Transfer)
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        // flush() first to force any cached data out of rust buffers.
        self.file.flush().map_err(Error::Flush)?;
        // Sync data out to physical media on host.
        self.file.sync_all().map_err(Error::SyncAll)
    }
}
