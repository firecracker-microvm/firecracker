// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Module exposing data structures for working with io_uring operations.

mod cqe;
mod sqe;

use std::convert::From;
use std::fmt::{self, Debug};

pub use cqe::Cqe;
pub(crate) use sqe::Sqe;

use crate::io_uring::generated::{io_uring_op, io_uring_sqe, io_uring_sqe_flags_bit};

/// The index of a registered fd.
pub type FixedFd = u32;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
// These constants are generated as u32, but we use u8; const try_from() is unstable
#[allow(clippy::cast_possible_truncation)]
/// Supported operation types.
pub enum OpCode {
    /// Read operation.
    Read = io_uring_op::IORING_OP_READ as u8,
    /// Write operation.
    Write = io_uring_op::IORING_OP_WRITE as u8,
    /// Vectored read operation.
    Readv = io_uring_op::IORING_OP_READV as u8,
    /// Vectored write operation.
    Writev = io_uring_op::IORING_OP_WRITEV as u8,
    /// Fsync operation.
    Fsync = io_uring_op::IORING_OP_FSYNC as u8,
}

// Useful for outputting errors.
impl From<OpCode> for &'static str {
    fn from(opcode: OpCode) -> Self {
        match opcode {
            OpCode::Read => "read",
            OpCode::Write => "write",
            OpCode::Readv => "readv",
            OpCode::Writev => "writev",
            OpCode::Fsync => "fsync",
        }
    }
}

/// Operation type for populating the submission queue, parametrised with the `user_data` type `T`.
/// The `user_data` is used for identifying the operation once completed.
pub struct Operation<T> {
    fd: FixedFd,
    pub(crate) opcode: OpCode,
    pub(crate) addr: Option<usize>,
    pub(crate) len: Option<u32>,
    flags: u8,
    rw_flags: i32,
    pub(crate) offset: Option<u64>,
    pub(crate) user_data: T,
}

// Needed for proptesting.
impl<T> fmt::Debug for Operation<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "
            Operation {{
                opcode: {:?},
                addr: {:?},
                len: {:?},
                offset: {:?},
            }}
        ",
            self.opcode, self.addr, self.len, self.offset
        )
    }
}

#[allow(clippy::len_without_is_empty)]
impl<T: Debug> Operation<T> {
    /// Construct a read operation.
    pub fn read(fd: FixedFd, addr: usize, len: u32, offset: u64, user_data: T) -> Self {
        Self {
            fd,
            opcode: OpCode::Read,
            addr: Some(addr),
            len: Some(len),
            flags: 0,
            rw_flags: 0,
            offset: Some(offset),
            user_data,
        }
    }

    /// Construct a write operation.
    pub fn write(fd: FixedFd, addr: usize, len: u32, offset: u64, user_data: T) -> Self {
        Self {
            fd,
            opcode: OpCode::Write,
            addr: Some(addr),
            len: Some(len),
            flags: 0,
            rw_flags: 0,
            offset: Some(offset),
            user_data,
        }
    }

    /// Require data and the metadata needed to retrieve it to reach stable storage.
    pub fn write_through(fd: FixedFd, addr: usize, len: u32, offset: u64, user_data: T) -> Self {
        Self::write(fd, addr, len, offset, user_data).with_dsync()
    }

    /// Construct a vectored read operation. The caller keeps the vector alive until completion.
    pub(crate) fn readv(fd: FixedFd, addr: usize, len: u32, offset: u64, user_data: T) -> Self {
        let mut op = Self::read(fd, addr, len, offset, user_data);
        op.opcode = OpCode::Readv;
        op
    }

    /// Construct a vectored write operation. The caller keeps the vector alive until completion.
    pub(crate) fn writev(fd: FixedFd, addr: usize, len: u32, offset: u64, user_data: T) -> Self {
        let mut op = Self::write(fd, addr, len, offset, user_data);
        op.opcode = OpCode::Writev;
        op
    }

    pub(crate) fn with_dsync(mut self) -> Self {
        self.rw_flags = libc::RWF_DSYNC;
        self
    }

    /// Construct a fsync operation.
    pub fn fsync(fd: FixedFd, user_data: T) -> Self {
        Self {
            fd,
            opcode: OpCode::Fsync,
            addr: None,
            len: None,
            flags: 0,
            rw_flags: 0,
            offset: None,
            user_data,
        }
    }

    /// Delay this operation until all earlier operations in the ring have completed.
    pub fn drain_before(mut self) -> Self {
        self.flags |= 1 << io_uring_sqe_flags_bit::IOSQE_IO_DRAIN_BIT;
        self
    }

    pub(crate) fn fd(&self) -> FixedFd {
        self.fd
    }

    // Needed for proptesting.
    #[cfg(test)]
    pub(crate) fn set_linked(&mut self) {
        self.flags |= 1 << io_uring_sqe_flags_bit::IOSQE_IO_LINK_BIT;
    }

    /// Transform the operation into an `Sqe`.
    /// Note: remember remove user_data from slab or it will leak.
    pub(crate) fn into_sqe(self, slab: &mut slab::Slab<T>) -> Sqe {
        // SAFETY:
        // Safe because all-zero value is valid. The sqe is made up of integers and raw pointers.
        let mut inner: io_uring_sqe = unsafe { std::mem::zeroed() };

        inner.opcode = self.opcode as u8;
        inner.__bindgen_anon_3.rw_flags = self.rw_flags;
        inner.fd = i32::try_from(self.fd).unwrap();
        // Simplifying assumption that we only used pre-registered FDs.
        inner.flags = self.flags | (1 << io_uring_sqe_flags_bit::IOSQE_FIXED_FILE_BIT);

        if let Some(addr) = self.addr {
            inner.__bindgen_anon_2.addr = addr as u64;
        }

        if let Some(len) = self.len {
            inner.len = len;
        }

        if let Some(offset) = self.offset {
            inner.__bindgen_anon_1.off = offset;
        }
        inner.user_data = slab.insert(self.user_data) as u64;

        Sqe::new(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_through_sets_the_per_write_sync_flag() {
        let mut slab = slab::Slab::new();
        for (op, flags) in [
            (Operation::write(0, 4096, 4096, 8192, ()), 0),
            (
                Operation::write_through(0, 4096, 4096, 8192, ()),
                libc::RWF_DSYNC,
            ),
        ] {
            let sqe = op.into_sqe(&mut slab);
            assert_eq!(sqe.0.opcode, OpCode::Write as u8);
            // SAFETY: writes use the rw_flags member of this union.
            assert_eq!(unsafe { sqe.0.__bindgen_anon_3.rw_flags }, flags);
        }
    }
}
