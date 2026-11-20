// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::os::fd::RawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;

use vm_memory::{GuestMemoryBackend, GuestMemoryError};
use vmm_sys_util::eventfd::EventFd;

use crate::arch::host_kernel_version;
use crate::devices::virtio::block::virtio::io::RequestError;
use crate::devices::virtio::block::virtio::{IO_URING_NUM_ENTRIES, PendingRequest};
use crate::io_uring::operation::{Cqe, OpCode, Operation};
use crate::io_uring::restriction::Restriction;
use crate::io_uring::{IoUring, IoUringError};
use crate::logger::log_dev_preview_warning;
use crate::utils::Version;
use crate::vstate::memory::{GuestAddress, GuestMemoryExtension, GuestMemoryMmap};

/// `BLOCK_URING_CMD_DISCARD` was added in Linux 6.12. Probing `IORING_OP_URING_CMD` is not
/// enough, because older kernels support the opcode without implementing it for block devices.
const BLOCK_URING_DISCARD_MIN_KERNEL: Version = Version::new(6, 12, 0);
const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum AsyncIoError {
    /// Not implemented
    NotImplemented,
    /// Discard on a block device with the Async engine requires host kernel 6.12 or newer
    BlockDiscardUnsupported,
    /// Could not read the metadata of the backing file: {0}
    Metadata(std::io::Error),
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
    discard: bool,
    discard_op: Option<DiscardOp>,
}

/// How discard is executed for the backing file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscardOp {
    /// `IORING_OP_FALLOCATE` punching a hole in a regular file.
    Fallocate,
    /// `BLOCK_URING_CMD_DISCARD` through `IORING_OP_URING_CMD` on a block device.
    BlockDiscard,
}

impl DiscardOp {
    fn select(is_block_device: bool, host_kernel: Version) -> Result<Self, AsyncIoError> {
        if !is_block_device {
            Ok(DiscardOp::Fallocate)
        } else if host_kernel >= BLOCK_URING_DISCARD_MIN_KERNEL {
            Ok(DiscardOp::BlockDiscard)
        } else {
            Err(AsyncIoError::BlockDiscardUnsupported)
        }
    }

    fn for_file(file: &File) -> Result<Self, AsyncIoError> {
        let is_block_device = file
            .metadata()
            .map_err(AsyncIoError::Metadata)?
            .file_type()
            .is_block_device();
        // The host kernel version only matters for block devices.
        let host_kernel = if is_block_device {
            host_kernel_version()
        } else {
            Version::default()
        };
        Self::select(is_block_device, host_kernel)
    }
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
    fn new_ring(
        file: &File,
        completion_fd: RawFd,
        discard_op: Option<DiscardOp>,
    ) -> Result<IoUring<WrappedRequest>, IoUringError> {
        let mut restrictions = vec![
            // Make sure we only allow operations on pre-registered fds.
            Restriction::RequireFixedFds,
            // Allowlist of opcodes.
            Restriction::AllowOpCode(OpCode::Read),
            Restriction::AllowOpCode(OpCode::Write),
            Restriction::AllowOpCode(OpCode::Fsync),
        ];
        let mut extra_ops = Vec::new();
        match discard_op {
            Some(DiscardOp::Fallocate) => {
                restrictions.push(Restriction::AllowOpCode(OpCode::Fallocate));
                extra_ops.push(OpCode::Fallocate);
            }
            Some(DiscardOp::BlockDiscard) => {
                restrictions.push(Restriction::AllowOpCode(OpCode::UringCmd));
                // The block discard command is forced into io-wq.
                restrictions.push(Restriction::AllowAsync);
                extra_ops.push(OpCode::UringCmd);
            }
            None => (),
        }

        IoUring::new_with_required_ops(
            u32::from(IO_URING_NUM_ENTRIES),
            vec![file],
            restrictions,
            Some(completion_fd),
            &extra_ops,
        )
    }

    pub fn from_file(file: File, discard: bool) -> Result<AsyncFileEngine, AsyncIoError> {
        log_dev_preview_warning("Async file IO", Option::None);

        let completion_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(AsyncIoError::EventFd)?;
        let discard_op = discard.then(|| DiscardOp::for_file(&file)).transpose()?;
        let ring = Self::new_ring(&file, completion_evt.as_raw_fd(), discard_op)
            .map_err(AsyncIoError::IoUring)?;

        Ok(AsyncFileEngine {
            file,
            ring,
            completion_evt,
            discard,
            discard_op,
        })
    }

    pub fn update_file(&mut self, file: File) -> Result<(), AsyncIoError> {
        // The new backing file may be of a different type than the old one.
        let discard_op = self
            .discard
            .then(|| DiscardOp::for_file(&file))
            .transpose()?;
        let ring = Self::new_ring(&file, self.completion_evt.as_raw_fd(), discard_op)
            .map_err(AsyncIoError::IoUring)?;

        self.file = file;
        self.ring = ring;
        self.discard_op = discard_op;
        Ok(())
    }

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
        (offset, len): (u64, u32),
        req: PendingRequest,
    ) -> Result<(), RequestError<AsyncIoError>> {
        let wrapped_user_data = WrappedRequest::new(req);
        let len = u64::from(len);
        let operation = match self.discard_op {
            Some(DiscardOp::Fallocate) => Operation::fallocate(
                0,
                FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
                offset,
                len,
                wrapped_user_data,
            ),
            Some(DiscardOp::BlockDiscard) => {
                Operation::block_discard(0, offset, len, wrapped_user_data)
            }
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
    fn test_discard_op_select() {
        assert_eq!(
            DiscardOp::select(false, Version::new(5, 10, 0)).unwrap(),
            DiscardOp::Fallocate
        );
        assert_eq!(
            DiscardOp::select(true, Version::new(6, 12, 0)).unwrap(),
            DiscardOp::BlockDiscard
        );
        assert_eq!(
            DiscardOp::select(true, Version::new(6, 18, 0)).unwrap(),
            DiscardOp::BlockDiscard
        );
        for kernel in [
            Version::new(5, 10, 0),
            Version::new(6, 1, 0),
            Version::new(6, 11, 255),
            // An unreadable host kernel version is reported as 0.0.0.
            Version::default(),
        ] {
            assert!(matches!(
                DiscardOp::select(true, kernel),
                Err(AsyncIoError::BlockDiscardUnsupported)
            ));
        }
    }

    #[test]
    fn test_discard_op_for_regular_file() {
        let file = TempFile::new().unwrap().into_file();
        let engine = AsyncFileEngine::from_file(file, true).unwrap();
        assert_eq!(engine.discard_op, Some(DiscardOp::Fallocate));

        let file = TempFile::new().unwrap().into_file();
        let mut engine = AsyncFileEngine::from_file(file, false).unwrap();
        assert_eq!(engine.discard_op, None);
        // Without discard, nothing is selected for a new backing file either.
        engine
            .update_file(TempFile::new().unwrap().into_file())
            .unwrap();
        assert_eq!(engine.discard_op, None);
    }
}
