// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod cqe;
mod sqe;

pub use cqe::Cqe;
pub use sqe::Sqe;

use crate::bindings::{self, io_uring_sqe, IOSQE_FIXED_FILE_BIT};

pub type FixedFd = u32;

#[repr(u8)]
pub enum OpCode {
    Read = bindings::IORING_OP_READ as u8,
    Write = bindings::IORING_OP_WRITE as u8,
    Fsync = bindings::IORING_OP_FSYNC as u8,
}

pub struct Operation<T> {
    fd: FixedFd,
    opcode: OpCode,
    addr: Option<usize>,
    len: Option<u32>,
    offset: Option<u64>,
    user_data: Box<T>,
}

#[allow(clippy::len_without_is_empty)]
impl<T> Operation<T> {
    pub fn read(fd: FixedFd, addr: usize, len: u32, offset: u64, user_data: T) -> Self {
        Self {
            fd,
            opcode: OpCode::Read,
            addr: Some(addr),
            len: Some(len),
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
            offset: None,
            user_data: Box::new(user_data),
        }
    }

    pub fn fd(&self) -> FixedFd {
        self.fd
    }

    pub fn user_data(self) -> T {
        *self.user_data
    }

    pub fn addr(&self) -> Option<usize> {
        self.addr
    }

    pub fn len(&self) -> Option<u32> {
        self.len
    }

    /// # Safety
    /// Unsafe because we turn the Boxed user_data into a raw pointer contained in the sqe.
    /// It's up to the caller to make sure that this value is freed (not leaked).
    pub unsafe fn into_sqe(self) -> Sqe {
        // Safe because all-zero value is valid. The sqe is made up of integers and raw pointers.
        let mut inner: io_uring_sqe = std::mem::zeroed();

        inner.opcode = self.opcode as u8;
        inner.fd = self.fd as i32;
        // Simplifying assumption that we only used pre-registered FDs.
        inner.flags = (1 << IOSQE_FIXED_FILE_BIT) as u8;

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
