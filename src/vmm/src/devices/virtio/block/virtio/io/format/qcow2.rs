// Copyright (c) 2026 Tencent. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use imago::file::File as ImagoFile;
use imago::format::access::FormatAccess;
use imago::qcow2::Qcow2;
use imago::{Storage, StorageOpenOptions};
use vm_memory::{GuestMemoryBackend, GuestMemoryError};

use crate::logger::log_dev_preview_warning;
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

/// Errors specific to the QCOW2 IO engine.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Qcow2IoError {
    /// Failed to open QCOW2 image: {0}
    Open(io::Error),
    /// Writable or Async QCOW2 images do not support multiple queues.
    MultiQueueNotSupported,
    /// QCOW2 images with multiple queues do not support disk replacement.
    MultiQueuePatchNotSupported,
    /// QCOW2 read error after {completed} bytes: {source}
    Read { source: io::Error, completed: u32 },
    /// QCOW2 write error: {0}
    Write(io::Error),
    /// QCOW2 discard error: {0}
    Discard(io::Error),
    /// The QCOW2 backend cannot be re-pointed at another file after being opened.
    UnsupportedOperation,
    /// Guest memory error: {0}
    GuestMemory(GuestMemoryError),
    /// QCOW2 metadata writeback error: {0}
    MetadataFlush(io::Error),
    /// QCOW2 sync error: {0}
    Flush(io::Error),
}

const IO_BUFFER_SIZE: usize = 64 * 1024;

/// Single-owner QCOW2 access with an image lock and bounded I/O buffer.
#[derive(Debug)]
pub struct Qcow2FileEngine {
    access: FormatAccess<ImagoFile>,
    io_buffer: Box<[u8]>,
    file_id: (u64, u64),
}

impl Qcow2FileEngine {
    /// Open a self-contained regular image, holding its lock until drop.
    /// Writable images must be flushed before releasing the engine.
    pub fn from_file(file: File, path: &Path, read_only: bool) -> Result<Self, Qcow2IoError> {
        let metadata = file.metadata().map_err(Qcow2IoError::Open)?;
        if !metadata.is_file() {
            return Err(Qcow2IoError::Open(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QCOW2 image must be a regular file",
            )));
        }
        if read_only {
            file.try_lock_shared()
        } else {
            file.try_lock()
        }
        .map_err(|err| Qcow2IoError::Open(err.into()))?;
        let storage = ImagoFile::from_open_file(
            file,
            StorageOpenOptions::new()
                .filename(path)
                .write(!read_only)
                .direct(false),
        )
        .map_err(Qcow2IoError::Open)?;
        let mut qcow2 =
            Qcow2::<ImagoFile>::open_image(storage, !read_only).map_err(Qcow2IoError::Open)?;
        if qcow2.implicit_backing_file().is_some() || qcow2.requires_external_data_file() {
            let message = if qcow2.requires_external_data_file() {
                "qcow2 external data files are not permitted"
            } else {
                "qcow2 backing files are not permitted"
            };
            return Err(Qcow2IoError::Open(io::Error::new(
                io::ErrorKind::InvalidData,
                message,
            )));
        }
        if !read_only {
            qcow2
                .validate_active_metadata()
                .map_err(Qcow2IoError::Open)?;
        }
        qcow2.set_discard_passthrough(true);

        log_dev_preview_warning("QCOW2 disk images", None);
        Ok(Self {
            access: FormatAccess::new(qcow2),
            io_buffer: vec![0; IO_BUFFER_SIZE].into_boxed_slice(),
            file_id: (metadata.dev(), metadata.ino()),
        })
    }

    /// Compare the opened image's device and inode with another file descriptor.
    pub fn same_file(&self, file: &File) -> io::Result<bool> {
        let metadata = file.metadata()?;
        Ok(self.file_id == (metadata.dev(), metadata.ino()))
    }

    /// Return the virtual disk capacity in bytes.
    pub fn disk_size(&self) -> u64 {
        self.access.size()
    }

    /// Read into guest memory and dirty only completed chunks.
    /// On I/O failure, [`Qcow2IoError::Read`] records the bytes already copied.
    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, Qcow2IoError> {
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(Qcow2IoError::GuestMemory)?;
        offset
            .checked_add(u64::from(count))
            .ok_or_else(|| Qcow2IoError::Read {
                source: io::Error::new(io::ErrorKind::InvalidInput, "QCOW2 read offset overflow"),
                completed: 0,
            })?;

        for completed in (0..count).step_by(IO_BUFFER_SIZE) {
            let start = completed as usize;
            let len = (slice.len() - start).min(IO_BUFFER_SIZE);
            self.access
                .read(&mut self.io_buffer[..len], offset + u64::from(completed))
                .map_err(|source| Qcow2IoError::Read { source, completed })?;
            slice
                .subslice(start, len)
                .map_err(|err| Qcow2IoError::GuestMemory(err.into()))?
                .copy_from(&self.io_buffer[..len]);
        }

        Ok(count)
    }

    /// Write guest bytes; an error may follow partially completed writes.
    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, Qcow2IoError> {
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(Qcow2IoError::GuestMemory)?;
        offset.checked_add(u64::from(count)).ok_or_else(|| {
            Qcow2IoError::Write(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QCOW2 write offset overflow",
            ))
        })?;

        for completed in (0..count).step_by(IO_BUFFER_SIZE) {
            let start = completed as usize;
            let len = (slice.len() - start).min(IO_BUFFER_SIZE);
            slice
                .subslice(start, len)
                .map_err(|err| Qcow2IoError::GuestMemory(err.into()))?
                .copy_to(&mut self.io_buffer[..len]);
            self.access
                .write(&self.io_buffer[..len], offset + u64::from(completed))
                .map_err(Qcow2IoError::Write)?;
        }

        Ok(count)
    }

    /// Zero the guest range and reclaim unreferenced data where storage permits.
    pub fn discard(&mut self, range: (u64, u32)) -> Result<u32, Qcow2IoError> {
        self.access
            .discard_to_zero(range.0, u64::from(range.1))
            .map_err(Qcow2IoError::Discard)?;
        Ok(range.1)
    }

    /// Publish writable mappings and sync storage; read-only engines do nothing.
    pub fn flush(&self) -> Result<(), Qcow2IoError> {
        if !self.access.inner().writable() {
            return Ok(());
        }
        self.access.flush().map_err(Qcow2IoError::MetadataFlush)?;
        self.access.sync().map_err(Qcow2IoError::Flush)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::block::virtio::test_utils::create_test_qcow2;
    use crate::test_utils::single_region_mem_dirty_tracking;
    use crate::vstate::memory::{Bitmap, Bytes, GuestMemoryExtension};

    #[test]
    fn test_qcow2_sync_dirty_tracking_and_eof_zero_fill() {
        let file = create_test_qcow2();
        let count = 2 * IO_BUFFER_SIZE + 512;
        let addr = GuestAddress(4096);
        let mem = single_region_mem_dirty_tracking(count + 8192);
        let data = vec![0xa7; count];
        mem.write_slice(&data, addr).unwrap();
        let mut engine = Qcow2FileEngine::from_file(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(file.as_path())
                .unwrap(),
            file.as_path(),
            false,
        )
        .unwrap();
        assert_eq!(
            engine
                .write(512, &mem, addr, u32::try_from(count).unwrap())
                .unwrap(),
            u32::try_from(count).unwrap()
        );
        engine.flush().unwrap();
        drop(engine);

        let mut engine =
            Qcow2FileEngine::from_file(File::open(file.as_path()).unwrap(), file.as_path(), true)
                .unwrap();
        mem.write_slice(&vec![0; count], addr).unwrap();
        mem.reset_dirty();
        assert_eq!(
            engine
                .read(512, &mem, addr, u32::try_from(count).unwrap())
                .unwrap(),
            u32::try_from(count).unwrap()
        );
        let mut actual = vec![0; count];
        mem.read_slice(&mut actual, addr).unwrap();
        assert_eq!(actual, data);
        let slice = mem.get_slice(GuestAddress(0), count + 8192).unwrap();
        assert!(!slice.bitmap().dirty_at(0));
        assert!(slice.bitmap().dirty_at(4096));
        assert!(slice.bitmap().dirty_at(4096 + count - 1));
        assert!(!slice.bitmap().dirty_at(count + 8192 - 1));
        assert!(matches!(
            engine.write(0, &mem, addr, 512),
            Err(Qcow2IoError::Write(_))
        ));

        let completed = 2 * IO_BUFFER_SIZE;
        let (mapping, _) = engine
            .access
            .get_mapping(512 + completed as u64, 512)
            .unwrap();
        let imago::Mapping::Raw { offset, .. } = mapping else {
            panic!("Expected allocated data");
        };
        file.as_file().set_len(offset + 511).unwrap();
        mem.write_slice(&vec![0x5d; count], addr).unwrap();
        mem.reset_dirty();
        assert_eq!(
            engine
                .read(512, &mem, addr, u32::try_from(count).unwrap())
                .unwrap(),
            u32::try_from(count).unwrap()
        );
        mem.read_slice(&mut actual, addr).unwrap();
        assert_eq!(&actual[..count - 1], &data[..count - 1]);
        assert_eq!(actual[count - 1], 0);
        let slice = mem.get_slice(addr, count).unwrap();
        assert!(slice.bitmap().dirty_at(count - 1));
        mem.reset_dirty();
        assert!(matches!(
            engine.read(u64::MAX, &mem, GuestAddress(0), 512),
            Err(Qcow2IoError::Read { completed: 0, .. })
        ));
        assert!(matches!(
            engine.read(0, &mem, GuestAddress(count as u64 + 8192), 512),
            Err(Qcow2IoError::GuestMemory(_))
        ));
        assert!(
            !mem.get_slice(GuestAddress(0), count + 8192)
                .unwrap()
                .bitmap()
                .dirty_at(0)
        );
    }
}
