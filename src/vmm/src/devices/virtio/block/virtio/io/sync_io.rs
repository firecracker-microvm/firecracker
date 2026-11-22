// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{ErrorKind, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;

use vm_memory::{
    GuestMemoryBackend, GuestMemoryError, ReadVolatile, VolatileMemoryError, VolatileSlice,
    WriteVolatile,
};

use super::DataSegment;
use super::direct::{DirectIo, retry_interrupted};
use super::vectored::{IoVecs, mark_read_dirty};
use crate::vstate::memory::{Bitmap, GuestAddress, GuestMemoryMmap};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SyncIoError {
    /// Discard: {0}
    Discard(std::io::Error),
    /// Direct I/O: {0}
    Direct(std::io::Error),
    /// Vectored I/O: {0}
    Vectored(std::io::Error),
    /// Flush: {0}
    Flush(std::io::Error),
    /// Seek: {0}
    Seek(std::io::Error),
    /// Sync backing: {0}
    SyncBacking(std::io::Error),
    /// Transfer: {0}
    Transfer(GuestMemoryError),
}

#[derive(Debug)]
pub struct SyncFileEngine {
    file: File,
    pub(super) direct: Option<DirectIo>,
}

const BLKDISCARD: libc::Ioctl = 0x1277;
const FALLOC_FL_KEEP_SIZE: libc::c_int = 0x01;
const FALLOC_FL_PUNCH_HOLE: libc::c_int = 0x02;

fn advance_iovecs(iovecs: &mut [libc::iovec], mut consumed: usize) -> &mut [libc::iovec] {
    let mut first = 0;
    for iovec in &mut *iovecs {
        if consumed < iovec.iov_len {
            iovec.iov_base = iovec.iov_base.wrapping_add(consumed);
            iovec.iov_len -= consumed;
            break;
        }
        consumed -= iovec.iov_len;
        first += 1;
    }
    &mut iovecs[first..]
}

pub(super) fn file_discard_range(file: &File, range: (u64, u32)) -> Result<u32, std::io::Error> {
    let file_type = file.metadata()?.file_type();
    let (offset, len) = range;

    if len == 0 {
        return Ok(0);
    }
    let discarded = len;
    let len = u64::from(len);

    if file_type.is_block_device() {
        let mut range = [offset, len];
        // SAFETY: file is a valid fd, BLKDISCARD expects a pointer to two u64 values
        // representing byte offset and byte length.
        let ret = unsafe { libc::ioctl(file.as_raw_fd(), BLKDISCARD, range.as_mut_ptr()) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    } else {
        let off = libc::off_t::try_from(offset).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "discard offset overflow")
        })?;
        let len = libc::off_t::try_from(len).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "discard length overflow")
        })?;
        // SAFETY: file is a valid fd and fallocate does not retain the passed values.
        let ret = unsafe {
            libc::fallocate(
                file.as_raw_fd(),
                FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
                off,
                len,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(discarded)
}

impl SyncFileEngine {
    pub(super) fn from_file(file: File, direct: Option<DirectIo>) -> SyncFileEngine {
        SyncFileEngine { file, direct }
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    // Validate the entire guest range before starting a chunked operation.
    fn bounce(
        &mut self,
        write: bool,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<Option<u32>, SyncIoError> {
        let Some(direct) = &mut self.direct else {
            return Ok(None);
        };
        direct
            .check_range(offset, count)
            .map_err(SyncIoError::Direct)?;
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(SyncIoError::Transfer)?;
        let ptr = slice.ptr_guard().as_ptr() as usize;
        if count == 0 || (direct.aligned_buffer(ptr) && direct.aligned_span(offset, count)) {
            return Ok(None);
        }
        direct
            .transfer(&mut self.file, write, offset, mem, addr, count)
            .map(Some)
            .map_err(SyncIoError::Direct)
    }

    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        if let Some(done) = self.bounce(false, offset, mem, addr, count)? {
            return Ok(done);
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(SyncIoError::Transfer)?;
        // SAFETY: `get_slice` checked that `count` bytes at this address are guest memory, which
        // the device keeps mapped. The copy carries no bitmap: vm-memory would mark the whole
        // remainder dirty if a read failed, so marking is done below for the bytes read.
        let mut unmarked =
            unsafe { VolatileSlice::new(slice.ptr_guard_mut().as_ptr(), count as usize) };

        // Account for completed reads. A failed direct read may also have touched the rest
        // of the destination, even when the kernel returns no byte count.
        let mut filled = 0;
        let result = loop {
            if unmarked.is_empty() {
                break Ok(());
            }
            // `unmarked` carries no bitmap, so vm-memory marks nothing; see above.
            #[expect(clippy::disallowed_methods)]
            match self.file.read_volatile(&mut unmarked) {
                Ok(0) => {
                    break Err(VolatileMemoryError::IOError(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    )));
                }
                Ok(read) => {
                    filled += read;
                    // `read` cannot exceed the slice's length.
                    unmarked = unmarked.offset(read).unwrap();
                }
                Err(VolatileMemoryError::IOError(err)) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) => {
                    // A failed direct read may have modified memory without reporting
                    // how far it got. Preserve every page offered to that read.
                    if self.direct.is_some() {
                        slice.bitmap().mark_dirty(filled, unmarked.len());
                    }
                    break Err(err);
                }
            }
        };
        slice.bitmap().mark_dirty(0, filled);
        if self.direct.is_some() && filled > 0 && result.is_err() {
            return Ok(u32::try_from(filled).expect("bounded by requested count"));
        }
        result.map_err(|err| SyncIoError::Transfer(err.into()))?;
        Ok(count)
    }

    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        if let Some(done) = self.bounce(true, offset, mem, addr, count)? {
            return Ok(done);
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        let mut slice = mem
            .get_slice(addr, count as usize)
            .map_err(SyncIoError::Transfer)?;
        if let Some(direct) = &self.direct {
            let mut done = 0;
            while !slice.is_empty() {
                match self.file.write_volatile(&slice) {
                    Ok(0) => break,
                    Ok(written) => {
                        done += u32::try_from(written).expect("bounded by requested count");
                        slice = slice.offset(written).unwrap();
                    }
                    Err(VolatileMemoryError::IOError(err))
                        if err.kind() == ErrorKind::Interrupted => {}
                    Err(_) if done != 0 => break,
                    Err(err) => return Err(SyncIoError::Transfer(err.into())),
                }
            }
            return direct
                .finish_write(&self.file, done)
                .map_err(SyncIoError::SyncBacking);
        }
        self.file
            .write_all_volatile(&slice)
            .map_err(|err| SyncIoError::Transfer(err.into()))?;
        Ok(count)
    }

    pub(super) fn transfer_vectored(
        &mut self,
        write: bool,
        offset: u64,
        mem: &GuestMemoryMmap,
        segments: &[DataSegment],
        count: u32,
    ) -> Result<u32, SyncIoError> {
        let mut iovecs = IoVecs::new(mem, segments).map_err(SyncIoError::Transfer)?;
        if let Some(direct) = &mut self.direct {
            direct
                .check_range(offset, count)
                .map_err(SyncIoError::Direct)?;
            if iovecs.needs_bounce(direct, offset) {
                return direct
                    .transfer_segments(&mut self.file, write, offset, mem, segments, count)
                    .map_err(SyncIoError::Direct);
            }
        }
        let mut offset = libc::off_t::try_from(offset).map_err(|_| {
            SyncIoError::Vectored(std::io::Error::new(
                ErrorKind::InvalidInput,
                "offset overflow",
            ))
        })?;
        let ret = (|| {
            let mut iovecs = iovecs.as_mut_slice();
            let mut completed = 0;
            while completed < count {
                let iovcnt = i32::try_from(iovecs.len()).expect("bounded by seg_max");
                let moved = retry_interrupted(|| {
                    // SAFETY: The iovecs still point into the same validated guest memory.
                    let moved = unsafe {
                        if write {
                            libc::pwritev(self.file.as_raw_fd(), iovecs.as_ptr(), iovcnt, offset)
                        } else {
                            libc::preadv(self.file.as_raw_fd(), iovecs.as_ptr(), iovcnt, offset)
                        }
                    };
                    if moved < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(u32::try_from(moved).expect("transfer cannot exceed requested count"))
                    }
                })?;
                completed += moved;
                // A direct short transfer may leave the remainder unaligned.
                if moved == 0 || completed == count || self.direct.is_some() {
                    break;
                }
                offset = offset
                    .checked_add(libc::off_t::from(moved))
                    .ok_or_else(|| std::io::Error::other("file offset overflow"))?;
                iovecs = advance_iovecs(iovecs, moved as usize);
            }
            Ok(completed)
        })();
        if !write {
            // A failed direct read may have modified the buffer without returning a count.
            mark_read_dirty(mem, segments, ret.as_ref().copied().unwrap_or(count));
        }
        let completed = ret.map_err(SyncIoError::Vectored)?;
        if write && let Some(direct) = &self.direct {
            return direct
                .finish_write(&self.file, completed)
                .map_err(SyncIoError::SyncBacking);
        }
        Ok(completed)
    }

    pub fn flush(&mut self) -> Result<(), SyncIoError> {
        // flush() first to force any cached data out of rust buffers.
        self.file.flush().map_err(SyncIoError::Flush)?;
        // Sync data out to physical media on host.
        self.file.sync_all().map_err(SyncIoError::SyncBacking)
    }

    pub fn discard(&mut self, range: (u64, u32)) -> Result<u32, SyncIoError> {
        let discarded = file_discard_range(&self.file, range).map_err(SyncIoError::Discard)?;
        if let Some(direct) = &self.direct {
            return direct
                .finish_write(&self.file, discarded)
                .map_err(SyncIoError::SyncBacking);
        }
        Ok(discarded)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::{advance_iovecs, file_discard_range};

    #[test]
    fn test_advance_iovecs_after_short_transfer() {
        let mut data = [0u8; 8];
        let first = data.as_mut_ptr();
        let second = first.wrapping_add(3);
        let mut iovecs = [
            libc::iovec {
                iov_base: first.cast(),
                iov_len: 3,
            },
            libc::iovec {
                iov_base: second.cast(),
                iov_len: 5,
            },
        ];
        let rest = advance_iovecs(&mut iovecs, 5);
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].iov_base, second.wrapping_add(2).cast());
        assert_eq!(rest[0].iov_len, 3);
        assert!(advance_iovecs(rest, 3).is_empty());
    }

    #[test]
    fn test_discard_regular_file() {
        let mut file = TempFile::new().unwrap().into_file();
        file.write_all(&vec![0x5a; 4096]).unwrap();

        match file_discard_range(&file, (1024, 2048)) {
            Ok(discarded) => assert_eq!(discarded, 2048),
            // Some filesystems do not support hole punching; that is a host/filesystem
            // capability limitation, not a test failure for the regular discard path.
            Err(err)
                if matches!(
                    err.raw_os_error(),
                    Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS)
                ) =>
            {
                return;
            }
            Err(err) => panic!("discard failed: {err}"),
        }

        file.seek(SeekFrom::Start(0)).unwrap();
        let mut data = vec![0u8; 4096];
        file.read_exact(&mut data).unwrap();

        assert_eq!(&data[..1024], vec![0x5a; 1024].as_slice());
        assert_eq!(&data[1024..3072], vec![0; 2048].as_slice());
        assert_eq!(&data[3072..], vec![0x5a; 1024].as_slice());
    }
}
