// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod bindings;
pub mod operation;
mod queue;

pub use queue::submission::Error as SQueueError;

use std::fs::File;
use std::io::Error as IOError;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use bindings::io_uring_params;
use operation::{Cqe, Operation};
use queue::completion::{CompletionQueue, Error as CQueueError};
use queue::submission::SubmissionQueue;
use utils::syscall::SyscallReturnCode;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    CQueue(CQueueError),
    RegisterEventfd(IOError),
    RegisterFile(IOError),
    Setup(IOError),
    SQueue(SQueueError),
    InvalidFixedFd(i32),
    NoRegisteredFds,
}

pub struct IoUring {
    fd: File,
    registered_fds_count: u32,
    squeue: SubmissionQueue,
    cqueue: CompletionQueue,
}

impl IoUring {
    pub fn new(num_entries: u32) -> Result<Self> {
        let mut params: io_uring_params = Default::default();
        // Safe because values are valid and we check the return value.
        let fd = SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                num_entries,
                &mut params as *mut io_uring_params,
            ) as libc::c_int
        })
        .into_result()
        .map_err(Error::Setup)? as i32;

        // Safe because the fd is valid and because this struct owns the fd.
        let file = unsafe { File::from_raw_fd(fd) };

        let squeue = SubmissionQueue::new(fd, &params).map_err(Error::SQueue)?;
        let cqueue = CompletionQueue::new(fd, &params).map_err(Error::CQueue)?;

        Ok(Self {
            fd: file,
            squeue,
            cqueue,
            registered_fds_count: 0,
        })
    }

    pub fn push<T>(&mut self, op: Operation<T>) -> std::result::Result<(), (Error, T)> {
        // validate that we actually did register fds
        let fd = op.fd() as i32;
        match self.registered_fds_count {
            0 => Err((Error::NoRegisteredFds, op.user_data())),
            len if fd < 0 || (len as i32 - 1) < fd => {
                Err((Error::InvalidFixedFd(fd), op.user_data()))
            }
            _ => self.squeue.push(unsafe { op.into_sqe() }).map_err(
                |err_tuple: (SQueueError, T)| -> (Error, T) {
                    (Error::SQueue(err_tuple.0), err_tuple.1)
                },
            ),
        }
    }

    pub fn pop<T>(&mut self) -> Result<Option<Cqe<T>>> {
        self.cqueue.pop().map_err(Error::CQueue)
    }

    pub fn submit(&mut self) -> Result<u64> {
        self.squeue.submit(0).map_err(Error::SQueue)
    }

    pub fn submit_and_wait(&mut self, min_complete: u32) -> Result<u64> {
        self.squeue.submit(min_complete).map_err(Error::SQueue)
    }

    pub fn pending_sqes(&self) -> Result<u32> {
        self.squeue.pending().map_err(Error::SQueue)
    }

    pub fn register_file(&mut self, file: &File) -> Result<()> {
        // Safe because values are valid and we check the return value.
        SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                bindings::IORING_REGISTER_FILES,
                (&[file.as_raw_fd()]).as_ptr() as *const _,
                1,
            ) as libc::c_int
        })
        .into_empty_result()
        .map_err(Error::RegisterFile)?;

        self.registered_fds_count += 1;
        Ok(())
    }

    pub fn register_eventfd(&self, fd: RawFd) -> Result<()> {
        // Safe because values are valid and we check the return value.
        SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                bindings::IORING_REGISTER_EVENTFD,
                (&fd) as *const _,
                1,
            ) as libc::c_int
        })
        .into_empty_result()
        .map_err(Error::RegisterEventfd)?;

        Ok(())
    }
}
