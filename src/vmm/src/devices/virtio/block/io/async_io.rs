// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::marker::PhantomData;
use std::os::unix::io::AsRawFd;

use utils::eventfd::EventFd;
use utils::vm_memory::{mark_dirty_mem, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::devices::virtio::block::io::UserDataError;
use crate::devices::virtio::block::IO_URING_NUM_ENTRIES;
use crate::io_uring::operation::{Cqe, OpCode, Operation};
use crate::io_uring::restriction::Restriction;
use crate::io_uring::{IoUring, IoUringError};
use crate::logger::log_dev_preview_warning;

#[derive(Debug)]
pub enum AsyncIoError {
    IO(std::io::Error),
    IoUring(IoUringError),
    Submit(std::io::Error),
    SyncAll(std::io::Error),
    EventFd(std::io::Error),
    GuestMemory(utils::vm_memory::GuestMemoryError),
}

#[derive(Debug)]
pub struct AsyncFileEngine<T> {
    file: File,
    ring: IoUring,
    completion_evt: EventFd,
    phantom: PhantomData<T>,
}

#[derive(Debug)]
pub struct WrappedUserData<T> {
    addr: Option<GuestAddress>,
    user_data: T,
}

impl<T: Debug> WrappedUserData<T> {
    fn new(user_data: T) -> Self {
        WrappedUserData {
            addr: None,
            user_data,
        }
    }

    fn new_with_dirty_tracking(addr: GuestAddress, user_data: T) -> Self {
        WrappedUserData {
            addr: Some(addr),
            user_data,
        }
    }

    fn mark_dirty_mem_and_unwrap(self, mem: &GuestMemoryMmap, count: u32) -> T {
        if let Some(addr) = self.addr {
            mark_dirty_mem(mem, addr, count as usize)
        }

        self.user_data
    }
}

impl<T: Debug> AsyncFileEngine<T> {
    pub fn from_file(file: File) -> Result<AsyncFileEngine<T>, AsyncIoError> {
        log_dev_preview_warning("Async file IO", Option::None);

        let completion_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(AsyncIoError::EventFd)?;
        let ring = IoUring::new(
            u32::from(IO_URING_NUM_ENTRIES),
            vec![&file],
            vec![
                // Make sure we only allow operations on pre-registered fds.
                Restriction::RequireFixedFds,
                // Allowlist of opcodes.
                Restriction::AllowOpCode(OpCode::Read),
                Restriction::AllowOpCode(OpCode::Write),
                Restriction::AllowOpCode(OpCode::Fsync),
            ],
            Some(completion_evt.as_raw_fd()),
        )
        .map_err(AsyncIoError::IoUring)?;

        Ok(AsyncFileEngine {
            file,
            ring,
            completion_evt,
            phantom: PhantomData,
        })
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
        user_data: T,
    ) -> Result<(), UserDataError<T, AsyncIoError>> {
        let buf = match mem.get_slice(addr, count as usize) {
            Ok(slice) => slice.ptr_guard_mut().as_ptr(),
            Err(err) => {
                return Err(UserDataError {
                    user_data,
                    error: AsyncIoError::GuestMemory(err),
                });
            }
        };

        let wrapped_user_data = WrappedUserData::new_with_dirty_tracking(addr, user_data);

        // SAFETY: Safe because we trust that the host kernel will pass us back a completed entry
        // with this same `user_data`, so that the value will not be leaked.
        unsafe {
            self.ring.push(Operation::read(
                0,
                buf as usize,
                count,
                offset,
                wrapped_user_data,
            ))
        }
        .map_err(|err_tuple| UserDataError {
            user_data: err_tuple.1.user_data,
            error: AsyncIoError::IoUring(err_tuple.0),
        })
    }

    pub fn push_write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        user_data: T,
    ) -> Result<(), UserDataError<T, AsyncIoError>> {
        let buf = match mem.get_slice(addr, count as usize) {
            Ok(slice) => slice.ptr_guard_mut().as_ptr(),
            Err(err) => {
                return Err(UserDataError {
                    user_data,
                    error: AsyncIoError::GuestMemory(err),
                });
            }
        };

        let wrapped_user_data = WrappedUserData::new(user_data);

        // SAFETY: Safe because we trust that the host kernel will pass us back a completed entry
        // with this same `user_data`, so that the value will not be leaked.
        unsafe {
            self.ring.push(Operation::write(
                0,
                buf as usize,
                count,
                offset,
                wrapped_user_data,
            ))
        }
        .map_err(|err_tuple| UserDataError {
            user_data: err_tuple.1.user_data,
            error: AsyncIoError::IoUring(err_tuple.0),
        })
    }

    pub fn push_flush(&mut self, user_data: T) -> Result<(), UserDataError<T, AsyncIoError>> {
        let wrapped_user_data = WrappedUserData::new(user_data);

        // SAFETY: Safe because we trust that the host kernel will pass us back a completed entry
        // with this same `user_data`, so that the value will not be leaked.
        unsafe { self.ring.push(Operation::fsync(0, wrapped_user_data)) }.map_err(|err_tuple| {
            UserDataError {
                user_data: err_tuple.1.user_data,
                error: AsyncIoError::IoUring(err_tuple.0),
            }
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

    fn do_pop(&mut self) -> Result<Option<Cqe<WrappedUserData<T>>>, AsyncIoError> {
        // SAFETY: We trust that the host kernel did not touch the operation's `user_data` field.
        // The `T` type is the same one used for `push`ing and since the kernel made this entry
        // available in the completion queue, we now have full ownership of it.

        unsafe { self.ring.pop::<WrappedUserData<T>>() }.map_err(AsyncIoError::IoUring)
    }

    pub fn pop(&mut self, mem: &GuestMemoryMmap) -> Result<Option<Cqe<T>>, AsyncIoError> {
        let cqe = self.do_pop()?.map(|cqe| {
            let count = cqe.count();
            cqe.map_user_data(|wrapped_user_data| {
                wrapped_user_data.mark_dirty_mem_and_unwrap(mem, count)
            })
        });

        Ok(cqe)
    }
}
