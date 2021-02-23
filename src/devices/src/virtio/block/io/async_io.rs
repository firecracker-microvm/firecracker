// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::virtio::block::io::{UserDataError, UserDataOk};
use std::fs::File;
use std::marker::PhantomData;
use utils::eventfd::EventFd;
use vm_memory::{GuestAddress, GuestMemoryMmap};

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    OpNotImplemented,
    SyncAll(std::io::Error),
}

pub struct AsyncFileEngine<T> {
    file: File,
    #[allow(unused)]
    completion_evt: EventFd,
    phantom: PhantomData<T>,
}

impl<T> AsyncFileEngine<T> {
    #[allow(unused)]
    pub fn from_file(file: File) -> std::io::Result<AsyncFileEngine<T>> {
        let completion_evt = EventFd::new(libc::EFD_NONBLOCK)?;

        Ok(AsyncFileEngine {
            file,
            completion_evt,
            phantom: PhantomData,
        })
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    #[allow(unused)]
    pub fn completion_evt(&self) -> &EventFd {
        &self.completion_evt
    }

    pub fn push_read(
        &mut self,
        _offset: u64,
        _mem: &GuestMemoryMmap,
        _addr: GuestAddress,
        _count: u32,
        user_data: Box<T>,
    ) -> Result<(), UserDataError<T, Error>> {
        Err(UserDataError {
            user_data,
            error: Error::OpNotImplemented,
        })
    }

    pub fn push_write(
        &mut self,
        _offset: u64,
        _mem: &GuestMemoryMmap,
        _addr: GuestAddress,
        _count: u32,
        user_data: Box<T>,
    ) -> Result<(), UserDataError<T, Error>> {
        Err(UserDataError {
            user_data,
            error: Error::OpNotImplemented,
        })
    }

    pub fn push_flush(&mut self, user_data: Box<T>) -> Result<(), UserDataError<T, Error>> {
        Err(UserDataError {
            user_data,
            error: Error::OpNotImplemented,
        })
    }

    #[allow(unused)]
    pub fn kick_submission_queue(&self) -> Result<(), Error> {
        Err(Error::OpNotImplemented)
    }

    /// Wait until all the entries in the submission queue are processed, then flush if requested.
    pub fn drain(&mut self, _flush: bool) -> Result<(), Error> {
        Err(Error::OpNotImplemented)
    }

    #[allow(unused)]
    pub fn pop(&mut self) -> Option<Result<UserDataOk<T>, UserDataError<T, Error>>> {
        None
    }
}
