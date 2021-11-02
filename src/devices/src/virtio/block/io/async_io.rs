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
use vm_memory::{mark_dirty_mem, GuestAddress, GuestMemory, GuestMemoryMmap};

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

pub struct WrappedUserData<T> {
    addr: Option<GuestAddress>,
    user_data: T,
}

impl<T> WrappedUserData<T> {
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

        let wrapped_user_data = WrappedUserData::new_with_dirty_tracking(addr, user_data);

        self.ring
            .push(Operation::read(
                0,
                buf as usize,
                count,
                offset,
                wrapped_user_data,
            ))
            .map_err(|err_tuple| UserDataError {
                user_data: err_tuple.1.user_data,
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

        let wrapped_user_data = WrappedUserData::new(user_data);

        self.ring
            .push(Operation::write(
                0,
                buf as usize,
                count,
                offset,
                wrapped_user_data,
            ))
            .map_err(|err_tuple| UserDataError {
                user_data: err_tuple.1.user_data,
                error: Error::IoUring(err_tuple.0),
            })
    }

    pub fn push_flush(&mut self, user_data: T) -> Result<(), UserDataError<T, Error>> {
        let wrapped_user_data = WrappedUserData::new(user_data);

        self.ring
            .push(Operation::fsync(0, wrapped_user_data))
            .map_err(|err_tuple| UserDataError {
                user_data: err_tuple.1.user_data,
                error: Error::IoUring(err_tuple.0),
            })
    }

    pub fn kick_submission_queue(&mut self) -> Result<(), Error> {
        self.ring.submit().map(|_| ()).map_err(Error::IoUring)
    }

    pub fn drain(&mut self, flush: bool) -> Result<(), Error> {
        self.drain_submission_queue()?;

        // Drain the completion queue so that we may deallocate the user_data fields.
        while self.do_pop()?.is_some() {}

        if flush {
            // Sync data out to physical media on host.
            // We don't need to call flush first since all the ops are performed through io_uring
            // and Rust shouldn't manage any data in its internal buffers.
            self.file.sync_all().map_err(Error::SyncAll)
        } else {
            Ok(())
        }
    }

    pub fn drain_submission_queue(&mut self) -> Result<(), Error> {
        self.ring
            .submit_and_wait_all()
            .map(|_| ())
            .map_err(Error::IoUring)
    }

    fn do_pop(&mut self) -> Result<Option<Cqe<WrappedUserData<T>>>, Error> {
        self.ring
            .pop::<WrappedUserData<T>>()
            .map_err(Error::IoUring)
    }

    pub fn pop(&mut self, mem: &GuestMemoryMmap) -> Result<Option<Cqe<T>>, Error> {
        let cqe = self.do_pop()?.map(|cqe| {
            let count = cqe.count();
            cqe.map_user_data(|wrapped_user_data| {
                wrapped_user_data.mark_dirty_mem_and_unwrap(mem, count)
            })
        });

        Ok(cqe)
    }
}
