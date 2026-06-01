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
    /// Fsync operation.
    Fsync = io_uring_op::IORING_OP_FSYNC as u8,
    /// Fallocate operation.
    Fallocate = io_uring_op::IORING_OP_FALLOCATE as u8,
    /// Uring command operation.
    UringCmd = io_uring_op::IORING_OP_URING_CMD as u8,
}

// Useful for outputting errors.
impl From<OpCode> for &'static str {
    fn from(opcode: OpCode) -> Self {
        match opcode {
            OpCode::Read => "read",
            OpCode::Write => "write",
            OpCode::Fsync => "fsync",
            OpCode::Fallocate => "fallocate",
            OpCode::UringCmd => "uring_cmd",
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
    pub(crate) cmd_op: Option<u32>,
    flags: u8,
    pub(crate) offset: Option<u64>,
    pub(crate) addr3: Option<u64>,
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
                cmd_op: {:?},
                offset: {:?},
                addr3: {:?},
            }}
        ",
            self.opcode, self.addr, self.len, self.cmd_op, self.offset, self.addr3
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
            cmd_op: None,
            flags: 0,
            offset: Some(offset),
            addr3: None,
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
            cmd_op: None,
            flags: 0,
            offset: Some(offset),
            addr3: None,
            user_data,
        }
    }

    /// Construct a fsync operation.
    pub fn fsync(fd: FixedFd, user_data: T) -> Self {
        Self {
            fd,
            opcode: OpCode::Fsync,
            addr: None,
            len: None,
            cmd_op: None,
            flags: 0,
            offset: None,
            addr3: None,
            user_data,
        }
    }

    /// Construct a fallocate operation.
    pub fn fallocate(fd: FixedFd, mode: u32, offset: u64, len: u64, user_data: T) -> Self {
        Self {
            fd,
            opcode: OpCode::Fallocate,
            addr: Some(usize::try_from(len).unwrap()),
            len: Some(mode),
            cmd_op: None,
            flags: 0,
            offset: Some(offset),
            addr3: None,
            user_data,
        }
    }

    /// Construct a block uring command operation.
    pub fn block_discard(fd: FixedFd, cmd_op: u32, offset: u64, len: u64, user_data: T) -> Self {
        Self {
            fd,
            opcode: OpCode::UringCmd,
            addr: Some(usize::try_from(offset).unwrap()),
            len: None,
            cmd_op: Some(cmd_op),
            flags: 0,
            offset: None,
            addr3: Some(len),
            user_data,
        }
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
        inner.fd = i32::try_from(self.fd).unwrap();
        // Simplifying assumption that we only used pre-registered FDs.
        inner.flags = self.flags | (1 << io_uring_sqe_flags_bit::IOSQE_FIXED_FILE_BIT);

        if let Some(addr) = self.addr {
            inner.__bindgen_anon_2.addr = addr as u64;
        }

        if let Some(len) = self.len {
            inner.len = len;
        }

        if let Some(cmd_op) = self.cmd_op {
            inner.__bindgen_anon_1.__bindgen_anon_1.cmd_op = cmd_op;
        }

        if let Some(offset) = self.offset {
            inner.__bindgen_anon_1.off = offset;
        }

        if let Some(addr3) = self.addr3 {
            // SAFETY: `__bindgen_anon_1` is the `addr3` view of this SQE union and
            // we are only writing plain integer fields before the SQE is submitted.
            unsafe {
                inner.__bindgen_anon_6.__bindgen_anon_1.as_mut().addr3 = addr3;
            }
        }
        inner.user_data = slab.insert(self.user_data) as u64;

        Sqe::new(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io_uring::generated::io_uring_op;

    #[test]
    fn test_fallocate_sqe_layout() {
        let mut slab = slab::Slab::new();
        let sqe = Operation::fallocate(0, 3, 4096, 8192, 7u8)
            .into_sqe(&mut slab)
            .0;

        assert_eq!(
            sqe.opcode,
            u8::try_from(io_uring_op::IORING_OP_FALLOCATE).unwrap()
        );
        assert_eq!(sqe.fd, 0);
        assert_eq!(sqe.len, 3);
        // SAFETY: These are the SQE union fields populated by fallocate().
        let offset = unsafe { sqe.__bindgen_anon_1.off };
        // SAFETY: This is the SQE union field populated by fallocate().
        let len = unsafe { sqe.__bindgen_anon_2.addr };
        assert_eq!(offset, 4096);
        assert_eq!(len, 8192);
    }

    #[test]
    fn test_block_discard_sqe_layout() {
        const BLOCK_URING_CMD_DISCARD: u32 = 0x1200;

        let mut slab = slab::Slab::new();
        let sqe = Operation::block_discard(0, BLOCK_URING_CMD_DISCARD, 4096, 8192, 7u8)
            .into_sqe(&mut slab)
            .0;

        assert_eq!(
            sqe.opcode,
            u8::try_from(io_uring_op::IORING_OP_URING_CMD).unwrap()
        );
        assert_eq!(sqe.fd, 0);
        assert_eq!(sqe.len, 0);
        // SAFETY: These are the SQE union fields populated by block_discard().
        let cmd_op = unsafe { sqe.__bindgen_anon_1.__bindgen_anon_1.cmd_op };
        // SAFETY: This is the SQE union field populated by block_discard().
        let offset = unsafe { sqe.__bindgen_anon_2.addr };
        // SAFETY: `__bindgen_anon_1` is the `addr3` view populated by block_discard().
        let len = unsafe { sqe.__bindgen_anon_6.__bindgen_anon_1.as_ref().addr3 };
        assert_eq!(cmd_op, BLOCK_URING_CMD_DISCARD);
        assert_eq!(offset, 4096);
        assert_eq!(len, 8192);
    }
}
