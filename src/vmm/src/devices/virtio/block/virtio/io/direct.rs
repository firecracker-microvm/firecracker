// Copyright 2026 VPSnet. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host alignment and bounded staging for a single-queue raw O_DIRECT drive.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;

use rustix::fs::{AtFlags, StatxFlags, statx};
use vm_memory::Bytes;

use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

pub(super) const BUFFER_SIZE: usize = 64 * 1024;

/// One reusable staging area per direct drive, independent of guest request size.
#[repr(align(4096))]
pub(super) struct Buffer(pub [u8; BUFFER_SIZE]);

// Debug output for a drive must not include guest disk data.
impl std::fmt::Debug for Buffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Buffer").field("len", &BUFFER_SIZE).finish()
    }
}

#[derive(Debug)]
pub(super) struct DirectIo {
    mem_align: usize,
    offset_align: usize,
    size: u64,
    pub(super) write_through: bool,
    buffer: Option<Box<Buffer>>,
}

impl DirectIo {
    pub(super) fn probe(file: &File, size: u64) -> io::Result<Self> {
        let ty = file.metadata()?.file_type();
        if !ty.is_block_device() && !ty.is_file() {
            return Err(io::Error::other(
                "direct I/O requires a regular file or block device",
            ));
        }
        match statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::DIOALIGN) {
            Ok(info) if info.stx_mask & StatxFlags::DIOALIGN.bits() != 0 => {
                return Self::new(
                    info.stx_dio_mem_align as usize,
                    info.stx_dio_offset_align as usize,
                    size,
                );
            }
            Ok(_) => {}
            Err(
                rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP,
            ) if ty.is_block_device() => {}
            Err(err) => return Err(err.into()),
        }
        if !ty.is_block_device() {
            return Err(io::Error::other(
                "filesystem did not report direct I/O alignment",
            ));
        }
        // Older kernels do not report the device's DMA alignment. Use a whole
        // host page for buffers, independently of the logical sector length.
        let mut sector = 0i32;
        // SAFETY: BLKSSZGET writes one integer into the supplied pointer.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::BLKSSZGET, &mut sector) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if sector < 512 {
            return Err(io::Error::other("invalid logical sector size"));
        }
        Self::new(
            crate::arch::host_page_size(),
            usize::try_from(sector).unwrap(),
            size,
        )
    }

    pub(super) fn new(mem_align: usize, offset_align: usize, size: u64) -> io::Result<Self> {
        if ![mem_align, offset_align]
            .into_iter()
            .all(|n| n.is_power_of_two() && n <= align_of::<Buffer>())
        {
            return Err(io::Error::other("unsupported direct I/O alignment"));
        }
        let offset_align = offset_align.max(512);
        if !size.is_multiple_of(offset_align as u64) {
            return Err(io::Error::other(
                "disk size is not a multiple of the transfer alignment",
            ));
        }
        Ok(Self {
            mem_align,
            offset_align,
            size,
            write_through: false,
            buffer: None,
        })
    }

    pub(super) fn check_range(&self, offset: u64, count: u32) -> io::Result<()> {
        if offset
            .checked_add(u64::from(count))
            .is_none_or(|end| end > self.size)
        {
            return Err(io::Error::other("direct I/O exceeds backing size"));
        }
        Ok(())
    }

    pub(super) fn aligned_span(&self, offset: u64, count: u32) -> bool {
        offset.is_multiple_of(self.offset_align as u64)
            && (count as usize).is_multiple_of(self.offset_align)
    }

    pub(super) fn aligned_buffer(&self, ptr: usize) -> bool {
        ptr.is_multiple_of(self.mem_align)
    }

    pub(super) fn buffer(&mut self) -> &mut Buffer {
        self.buffer
            .get_or_insert_with(|| Box::new(Buffer([0; BUFFER_SIZE])))
    }

    pub(super) fn finish_write(&self, file: &File, count: u32) -> io::Result<u32> {
        if self.write_through && count != 0 {
            file.sync_all()?;
        }
        Ok(count)
    }

    /// Stage an unaligned request in whole host blocks. Only the start and end of the
    /// request can require a read-modify-write. The caller excludes concurrent writes.
    pub(super) fn transfer(
        &mut self,
        file: &mut File,
        write: bool,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> io::Result<u32> {
        let block = self.offset_align;
        let buf = &mut self.buffer().0;
        let mut done = 0;
        while done < count {
            let cursor = offset + u64::from(done);
            let head =
                usize::try_from(cursor % block as u64).expect("remainder is smaller than a block");
            let start = cursor - head as u64;
            let n = ((count - done) as usize).min(BUFFER_SIZE - head);
            let span = (head + n).next_multiple_of(block);
            let guest = GuestAddress(addr.0 + u64::from(done));

            let step = (|| -> io::Result<usize> {
                if write {
                    if head != 0 || n != span {
                        file.seek(SeekFrom::Start(start))?;
                        file.read_exact(&mut buf[..span])?;
                    }
                    mem.read_slice(&mut buf[head..head + n], guest)
                        .map_err(io::Error::other)?;
                    file.seek(SeekFrom::Start(start))?;
                    let written = retry_interrupted(|| file.write(&buf[..span]))?;
                    Ok(written.saturating_sub(head).min(n))
                } else {
                    file.seek(SeekFrom::Start(start))?;
                    let read = retry_interrupted(|| file.read(&mut buf[..span]))?;
                    let available = read.saturating_sub(head).min(n);
                    mem.write_slice(&buf[head..head + available], guest)
                        .map_err(io::Error::other)?;
                    Ok(available)
                }
            })();

            match step {
                Ok(bytes) => {
                    done += u32::try_from(bytes).expect("bounded by buffer size");
                    if bytes != n {
                        break;
                    }
                }
                // A short count makes the virtio request fail and accounts for the
                // prefix already delivered to guest memory.
                Err(_) if done > 0 => break,
                Err(err) => return Err(err),
            }
        }
        if write {
            self.finish_write(file, done)
        } else {
            Ok(done)
        }
    }
}

fn retry_interrupted<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match f() {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_through_reports_sync_error() {
        let mut direct = DirectIo::new(4096, 4096, 4096).unwrap();
        let disk = File::options().write(true).open("/dev/null").unwrap();
        assert_eq!(direct.finish_write(&disk, 512).unwrap(), 512);
        direct.write_through = true;
        assert_eq!(direct.finish_write(&disk, 0).unwrap(), 0);
        assert_eq!(
            direct.finish_write(&disk, 512).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
    }
}
