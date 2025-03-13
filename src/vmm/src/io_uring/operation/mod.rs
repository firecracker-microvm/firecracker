// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Module exposing data structures for working with io_uring operations.

mod cqe;
mod sqe;

use std::convert::From;
use std::fmt::{self, Debug};

pub use cqe::Cqe;
pub(crate) use sqe::Sqe;

use crate::io_uring::generated::{self, IOSQE_FIXED_FILE_BIT, io_uring_sqe};

/// The index of a registered fd.
pub type FixedFd = u32;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
// These constants are generated as u32, but we use u8; const try_from() is unstable
#[allow(clippy::cast_possible_truncation)]
/// Supported operation types.
pub enum OpCode {
    /// Read operation.
    Read = generated::IORING_OP_READ as u8,
    /// Write operation.
    Write = generated::IORING_OP_WRITE as u8,
    /// Fsync operation.
    Fsync = generated::IORING_OP_FSYNC as u8,
}

// Useful for outputting errors.
impl From<OpCode> for &'static str {
    fn from(opcode: OpCode) -> Self {
        match opcode {
            OpCode::Read => "read",
            OpCode::Write => "write",
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
            offset: Some(offset),
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
            flags: 0,
            offset: None,
            user_data,
        }
    }

    pub(crate) fn fd(&self) -> FixedFd {
        self.fd
    }

    // Needed for proptesting.
    #[cfg(test)]
    pub(crate) fn set_linked(&mut self) {
        self.flags |= 1 << generated::IOSQE_IO_LINK_BIT;
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
        inner.flags = self.flags | (1 << IOSQE_FIXED_FILE_BIT);

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
