// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CStr;
use std::fmt::Debug;
use std::fs::File;
use std::os::fd::RawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;

use vm_memory::GuestMemoryError;
use vmm_sys_util::eventfd::EventFd;

use crate::devices::virtio::block::virtio::io::RequestError;
use crate::devices::virtio::block::virtio::{IO_URING_NUM_ENTRIES, PendingRequest};
use crate::io_uring::operation::{Cqe, OpCode, Operation};
use crate::io_uring::restriction::Restriction;
use crate::io_uring::{IoUring, IoUringError};
use crate::logger::log_dev_preview_warning;
use crate::vstate::memory::{GuestAddress, GuestMemory, GuestMemoryExtension, GuestMemoryMmap};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum AsyncIoError {
    /// Not implemented
    NotImplemented,
    /// Discard is not supported with this async backend on the host kernel.
    DiscardUnsupported,
    /// IO: {0}
    IO(std::io::Error),
    /// IoUring: {0}
    IoUring(IoUringError),
    /// Submit: {0}
    Submit(std::io::Error),
    /// SyncAll: {0}
    SyncAll(std::io::Error),
    /// EventFd: {0}
    EventFd(std::io::Error),
    /// GuestMemory: {0}
    GuestMemory(GuestMemoryError),
}

#[derive(Debug)]
pub struct AsyncFileEngine {
    file: File,
    ring: IoUring<WrappedRequest>,
    completion_evt: EventFd,
    discard_op: Option<AsyncDiscardOp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AsyncDiscardOp {
    BlockUringCmd,
    Fallocate,
}

#[derive(Debug)]
pub struct WrappedRequest {
    addr: Option<GuestAddress>,
    req: PendingRequest,
}

impl WrappedRequest {
    fn new(req: PendingRequest) -> Self {
        WrappedRequest { addr: None, req }
    }

    fn new_with_dirty_tracking(addr: GuestAddress, req: PendingRequest) -> Self {
        WrappedRequest {
            addr: Some(addr),
            req,
        }
    }

    fn mark_dirty_mem_and_unwrap(self, mem: &GuestMemoryMmap, count: u32) -> PendingRequest {
        if let Some(addr) = self.addr {
            mem.mark_dirty(addr, count as usize)
        }

        self.req
    }
}

impl AsyncFileEngine {
    const BLOCK_URING_CMD_DISCARD: u32 = 0x1200;
    const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
    const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
    const MIN_BLOCK_URING_DISCARD_KERNEL: (u32, u32) = (6, 12);

    fn new_ring(
        file: &File,
        completion_fd: RawFd,
        discard_op: Option<AsyncDiscardOp>,
    ) -> Result<IoUring<WrappedRequest>, IoUringError> {
        let mut restrictions = vec![
            // Make sure we only allow operations on pre-registered fds.
            Restriction::RequireFixedFds,
            // Allowlist of opcodes.
            Restriction::AllowOpCode(OpCode::Read),
            Restriction::AllowOpCode(OpCode::Write),
            Restriction::AllowOpCode(OpCode::Fsync),
        ];
        let mut required_ops = vec![OpCode::Read, OpCode::Write];
        match discard_op {
            Some(AsyncDiscardOp::Fallocate) => {
                restrictions.push(Restriction::AllowOpCode(OpCode::Fallocate));
                required_ops.push(OpCode::Fallocate);
            }
            Some(AsyncDiscardOp::BlockUringCmd) => {
                restrictions.push(Restriction::AllowOpCode(OpCode::UringCmd));
                required_ops.push(OpCode::UringCmd);
            }
            None => {}
        }

        IoUring::new_with_required_ops(
            u32::from(IO_URING_NUM_ENTRIES),
            vec![file],
            restrictions,
            Some(completion_fd),
            &required_ops,
        )
    }

    pub fn from_file(file: File, discard: bool) -> Result<AsyncFileEngine, AsyncIoError> {
        log_dev_preview_warning("Async file IO", Option::None);

        let completion_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(AsyncIoError::EventFd)?;
        let discard_op = Self::discard_op(&file, discard)?;
        let ring = Self::new_ring(&file, completion_evt.as_raw_fd(), discard_op)
            .map_err(AsyncIoError::IoUring)?;

        Ok(AsyncFileEngine {
            file,
            ring,
            completion_evt,
            discard_op,
        })
    }

    pub fn update_file(&mut self, file: File) -> Result<(), AsyncIoError> {
        let discard_op = Self::discard_op(&file, self.discard_op.is_some())?;
        let ring = Self::new_ring(&file, self.completion_evt.as_raw_fd(), discard_op)
            .map_err(AsyncIoError::IoUring)?;

        self.ring = ring;
        self.file = file;
        self.discard_op = discard_op;
        Ok(())
    }

    fn discard_op(file: &File, discard: bool) -> Result<Option<AsyncDiscardOp>, AsyncIoError> {
        if !discard {
            return Ok(None);
        }

        if file
            .metadata()
            .map_err(AsyncIoError::IO)?
            .file_type()
            .is_block_device()
        {
            // BLOCK_URING_CMD_DISCARD is introduced for block devices in Linux 6.12.
            // IORING_OP_URING_CMD probing alone is not enough because older kernels can
            // support uring commands for other file operations.
            if !Self::host_kernel_at_least(Self::MIN_BLOCK_URING_DISCARD_KERNEL)
                .map_err(AsyncIoError::IO)?
            {
                return Err(AsyncIoError::DiscardUnsupported);
            }
            Ok(Some(AsyncDiscardOp::BlockUringCmd))
        } else {
            Ok(Some(AsyncDiscardOp::Fallocate))
        }
    }

    fn host_kernel_at_least((major, minor): (u32, u32)) -> Result<bool, std::io::Error> {
        // SAFETY: An all-zeroed value for `libc::utsname` is valid.
        let mut name: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: The passed arg is a valid mutable reference of `libc::utsname`.
        let ret = unsafe { libc::uname(&mut name) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: The fields of `libc::utsname` are terminated by a null byte.
        let release = unsafe { CStr::from_ptr(name.release.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        Self::kernel_release_at_least(&release, (major, minor)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid kernel release")
        })
    }

    fn parse_kernel_release(release: &str) -> Option<(u32, u32)> {
        let mut parts = release
            .split(|ch: char| !ch.is_ascii_digit() && ch != '.')
            .next()
            .unwrap_or("")
            .split('.');

        let host_major = parts.next()?.parse::<u32>().ok()?;
        let host_minor = parts.next()?.parse::<u32>().ok()?;

        Some((host_major, host_minor))
    }

    fn kernel_release_at_least(release: &str, (major, minor): (u32, u32)) -> Option<bool> {
        let (host_major, host_minor) = Self::parse_kernel_release(release)?;

        Some(host_major > major || (host_major == major && host_minor >= minor))
    }

    #[cfg(test)]
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn completion_evt(&self) -> &EventFd {
        &self.completion_evt
    }

    pub fn push_read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<AsyncIoError>> {
        let buf = match mem.get_slice(addr, count as usize) {
            Ok(slice) => slice.ptr_guard_mut().as_ptr(),
            Err(err) => {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::GuestMemory(err),
                });
            }
        };

        let wrapped_user_data = WrappedRequest::new_with_dirty_tracking(addr, req);

        self.ring
            .push(Operation::read(
                0,
                buf as usize,
                count,
                offset,
                wrapped_user_data,
            ))
            .map_err(|(io_uring_error, data)| RequestError {
                req: data.req,
                error: AsyncIoError::IoUring(io_uring_error),
            })
    }

    pub fn push_write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<AsyncIoError>> {
        let buf = match mem.get_slice(addr, count as usize) {
            Ok(slice) => slice.ptr_guard_mut().as_ptr(),
            Err(err) => {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::GuestMemory(err),
                });
            }
        };

        let wrapped_user_data = WrappedRequest::new(req);

        self.ring
            .push(Operation::write(
                0,
                buf as usize,
                count,
                offset,
                wrapped_user_data,
            ))
            .map_err(|(io_uring_error, data)| RequestError {
                req: data.req,
                error: AsyncIoError::IoUring(io_uring_error),
            })
    }

    pub fn push_flush(&mut self, req: PendingRequest) -> Result<(), RequestError<AsyncIoError>> {
        let wrapped_user_data = WrappedRequest::new(req);

        self.ring
            .push(Operation::fsync(0, wrapped_user_data))
            .map_err(|(io_uring_error, data)| RequestError {
                req: data.req,
                error: AsyncIoError::IoUring(io_uring_error),
            })
    }

    pub fn push_discard(
        &mut self,
        range: (u64, u64),
        req: PendingRequest,
    ) -> Result<(), RequestError<AsyncIoError>> {
        let wrapped_user_data = WrappedRequest::new(req);
        let (offset, len) = range;
        let operation = match self.discard_op {
            Some(AsyncDiscardOp::Fallocate) => Operation::fallocate(
                0,
                Self::FALLOC_FL_KEEP_SIZE | Self::FALLOC_FL_PUNCH_HOLE,
                offset,
                len,
                wrapped_user_data,
            ),
            Some(AsyncDiscardOp::BlockUringCmd) => Operation::block_discard(
                0,
                Self::BLOCK_URING_CMD_DISCARD,
                offset,
                len,
                wrapped_user_data,
            ),
            None => {
                return Err(RequestError {
                    req: wrapped_user_data.req,
                    error: AsyncIoError::NotImplemented,
                });
            }
        };

        self.ring
            .push(operation)
            .map_err(|(io_uring_error, data)| RequestError {
                req: data.req,
                error: AsyncIoError::IoUring(io_uring_error),
            })
    }

    pub fn kick_submission_queue(&mut self) -> Result<(), AsyncIoError> {
        self.ring
            .submit()
            .map(|_| ())
            .map_err(AsyncIoError::IoUring)
    }

    pub fn drain(&mut self, discard_cqes: bool) -> Result<(), AsyncIoError> {
        self.ring
            .submit_and_wait_all()
            .map(|_| ())
            .map_err(AsyncIoError::IoUring)?;

        if discard_cqes {
            // Drain the completion queue so that we may deallocate the user_data fields.
            while self.do_pop()?.is_some() {}
        }

        Ok(())
    }

    pub fn drain_and_flush(&mut self, discard_cqes: bool) -> Result<(), AsyncIoError> {
        self.drain(discard_cqes)?;

        // Sync data out to physical media on host.
        // We don't need to call flush first since all the ops are performed through io_uring
        // and Rust shouldn't manage any data in its internal buffers.
        self.file.sync_all().map_err(AsyncIoError::SyncAll)?;

        Ok(())
    }

    fn do_pop(&mut self) -> Result<Option<Cqe<WrappedRequest>>, AsyncIoError> {
        self.ring.pop().map_err(AsyncIoError::IoUring)
    }

    pub fn pop(
        &mut self,
        mem: &GuestMemoryMmap,
    ) -> Result<Option<Cqe<PendingRequest>>, AsyncIoError> {
        let cqe = self.do_pop()?.map(|cqe| {
            let count = cqe.count();
            cqe.map_user_data(|wrapped_user_data| {
                wrapped_user_data.mark_dirty_mem_and_unwrap(mem, count)
            })
        });

        Ok(cqe)
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_kernel_release_at_least() {
        assert_eq!(
            AsyncFileEngine::kernel_release_at_least("6.11.0-1018-aws", (6, 12)),
            Some(false)
        );
        assert_eq!(
            AsyncFileEngine::kernel_release_at_least("6.12.0-1020-aws", (6, 12)),
            Some(true)
        );
        assert_eq!(
            AsyncFileEngine::kernel_release_at_least("6.17.0-29-generic", (6, 12)),
            Some(true)
        );
        assert_eq!(
            AsyncFileEngine::kernel_release_at_least("7.0.2-6-pve", (6, 12)),
            Some(true)
        );
        assert_eq!(
            AsyncFileEngine::kernel_release_at_least("not-a-kernel", (6, 12)),
            None
        );
    }

    #[test]
    fn test_discard_regular_file_uses_fallocate() {
        let file = TempFile::new().unwrap().into_file();
        let engine = AsyncFileEngine::from_file(file, true).unwrap();

        assert_eq!(engine.discard_op, Some(AsyncDiscardOp::Fallocate));
    }
}
