// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::marker::PhantomData;
use std::os::unix::io::AsRawFd;

use io_uring::{
    operation::{Cqe, Operation},
    Error as IoUringError, IoUring,
};

use utils::eventfd::EventFd;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::virtio::block::io::UserDataError;
use crate::virtio::block::QUEUE_SIZE;

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    IoUring(IoUringError),
    Submit(std::io::Error),
    SyncAll(std::io::Error),
    EventFd(std::io::Error),
    GuestMemory(vm_memory::GuestMemoryError),
}

pub struct AsyncFileEngine<T> {
    file: File,
    ring: IoUring,
    completion_evt: EventFd,
    phantom: PhantomData<T>,
}

impl<T> AsyncFileEngine<T> {
    #[allow(unused)]
    pub fn from_file(file: File) -> Result<AsyncFileEngine<T>, Error> {
        let completion_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let mut ring = IoUring::new(QUEUE_SIZE as u32).map_err(Error::IoUring)?;
        ring.register_eventfd(completion_evt.as_raw_fd())
            .map_err(Error::IoUring)?;

        ring.register_file(&file).map_err(Error::IoUring)?;

        Ok(AsyncFileEngine {
            file,
            ring,
            completion_evt,
            phantom: PhantomData,
        })
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
        user_data: T,
    ) -> Result<(), UserDataError<T, Error>> {
        let buf = match mem.get_slice(addr, count as usize) {
            Ok(slice) => slice.as_ptr(),
            Err(e) => {
                return Err(UserDataError {
                    user_data,
                    error: Error::GuestMemory(e),
                });
            }
        };

        self.ring
            .push(Operation::read(0, buf as usize, count, offset, user_data))
            .map_err(|err_tuple| UserDataError {
                user_data: err_tuple.1,
                error: Error::IoUring(err_tuple.0),
            })
    }

    pub fn push_write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        user_data: T,
    ) -> Result<(), UserDataError<T, Error>> {
        let buf = match mem.get_slice(addr, count as usize) {
            Ok(slice) => slice.as_ptr(),
            Err(e) => {
                return Err(UserDataError {
                    user_data,
                    error: Error::GuestMemory(e),
                });
            }
        };

        self.ring
            .push(Operation::write(0, buf as usize, count, offset, user_data))
            .map_err(|err_tuple| UserDataError {
                user_data: err_tuple.1,
                error: Error::IoUring(err_tuple.0),
            })
    }

    pub fn push_flush(&mut self, user_data: T) -> Result<(), UserDataError<T, Error>> {
        self.ring
            .push(Operation::fsync(0, user_data))
            .map_err(|err_tuple| UserDataError {
                user_data: err_tuple.1,
                error: Error::IoUring(err_tuple.0),
            })
    }

    pub fn kick_submission_queue(&mut self) -> Result<(), Error> {
        self.ring.submit().map(|_| ()).map_err(Error::IoUring)
    }

    #[cfg(test)]
    // Useful when testing, to skip the eventfd polling and waiting.
    pub fn kick_submission_queue_and_wait(&mut self, min_complete: u32) -> Result<(), Error> {
        self.ring
            .submit_and_wait(min_complete)
            .map(|_| ())
            .map_err(Error::IoUring)
    }

    pub fn drain(&mut self, flush: bool) -> Result<(), Error> {
        self.drain_submission_queue()?;

        // Drain the completion queue so that we may deallocate the user_data fields.
        while self.pop()?.is_some() {}

        if flush {
            // Sync data out to physical media on host.
            // We don't need to call flush first since all the ops are performed through io_uring
            // and Rust shouldn't manage any data in its internal buffers.
            self.file.sync_all().map_err(Error::SyncAll)
        } else {
            Ok(())
        }
    }

    fn drain_submission_queue(&mut self) -> Result<(), Error> {
        // Drain the submission queue.
        loop {
            // In order for this loop to ever end, we must guarantee that there isn't another thread
            // submitting ops on the io_uring fd.
            let sq_len = self.ring.pending_sqes().map_err(Error::IoUring)?;
            if sq_len == 0 {
                break;
            }

            self.ring.submit_and_wait(sq_len).map_err(Error::IoUring)?;
        }

        Ok(())
    }

    pub fn pop(&mut self) -> Result<Option<Cqe<T>>, Error> {
        self.ring.pop().map_err(Error::IoUring)
    }
}
