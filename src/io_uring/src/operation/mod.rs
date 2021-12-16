// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod cqe;
mod sqe;

pub use cqe::Cqe;
pub(crate) use sqe::Sqe;

#[cfg(test)]
use core::fmt::{self, Debug, Formatter};
use std::convert::From;

use crate::bindings::{self, io_uring_sqe, IOSQE_FIXED_FILE_BIT};

pub type FixedFd = u32;

#[repr(u8)]
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum OpCode {
    Read = bindings::IORING_OP_READ as u8,
    Write = bindings::IORING_OP_WRITE as u8,
    Fsync = bindings::IORING_OP_FSYNC as u8,
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

pub struct Operation<T> {
    fd: FixedFd,
    pub(crate) opcode: OpCode,
    pub(crate) addr: Option<usize>,
    pub(crate) len: Option<u32>,
    flags: u8,
    pub(crate) offset: Option<u64>,
    user_data: Box<T>,
}

// Needed for proptesting.
#[cfg(test)]
impl<T> Debug for Operation<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
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
impl<T> Operation<T> {
    pub fn read(fd: FixedFd, addr: usize, len: u32, offset: u64, user_data: T) -> Self {
        Self {
            fd,
            opcode: OpCode::Read,
            addr: Some(addr),
            len: Some(len),
            flags: 0,
            offset: Some(offset),
            user_data: Box::new(user_data),
        }
    }

    pub fn write(fd: FixedFd, addr: usize, len: u32, offset: u64, user_data: T) -> Self {
        Self {
            fd,
            opcode: OpCode::Write,
            addr: Some(addr),
            len: Some(len),
            flags: 0,
            offset: Some(offset),
            user_data: Box::new(user_data),
        }
    }

    pub fn fsync(fd: FixedFd, user_data: T) -> Self {
        Self {
            fd,
            opcode: OpCode::Fsync,
            addr: None,
            len: None,
            flags: 0,
            offset: None,
            user_data: Box::new(user_data),
        }
    }

    pub(crate) fn fd(&self) -> FixedFd {
        self.fd
    }

    pub fn user_data(self) -> T {
        *self.user_data
    }

    // Needed for proptesting.
    #[cfg(test)]
    pub(crate) fn set_linked(&mut self) {
        self.flags |= 1 << bindings::IOSQE_IO_LINK_BIT;
    }

    /// # Safety
    /// Unsafe because we turn the Boxed user_data into a raw pointer contained in the sqe.
    /// It's up to the caller to make sure that this value is freed (not leaked).
    pub(crate) unsafe fn into_sqe(self) -> Sqe {
        // Safe because all-zero value is valid. The sqe is made up of integers and raw pointers.
        let mut inner: io_uring_sqe = std::mem::zeroed();

        inner.opcode = self.opcode as u8;
        inner.fd = self.fd as i32;
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
        inner.user_data = Box::into_raw(self.user_data) as u64;

        Sqe::new(inner)
    }
}
