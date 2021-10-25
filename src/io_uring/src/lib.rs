// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod bindings;
pub mod operation;
mod probe;
mod queue;

pub use queue::submission::Error as SQueueError;

use std::collections::HashSet;
use std::fs::File;
use std::io::Error as IOError;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use bindings::io_uring_params;
use operation::{Cqe, OpCode, Operation};
use probe::{ProbeWrapper, PROBE_LEN};
use queue::completion::{CompletionQueue, Error as CQueueError};
use queue::submission::SubmissionQueue;
use utils::syscall::SyscallReturnCode;

// IO_uring operations that we require to be supported by the host kernel.
const REQUIRED_OPS: [OpCode; 2] = [OpCode::Read, OpCode::Write];

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
    Probe(IOError),
    /// A FamStructWrapper operation has failed.
    FamError(utils::fam::Error),
    UnsupportedFeature(&'static str),
    UnsupportedOperation(&'static str),
}

impl Error {
    pub fn is_full_sq(&self) -> bool {
        if let Error::SQueue(SQueueError::FullQueue) = self {
            return true;
        }
        false
    }
}

pub struct IoUring {
    fd: File,
    registered_fds_count: u32,
    squeue: SubmissionQueue,
    cqueue: CompletionQueue,

    // Number of ops yet to be pop-ed from the CQ. These ops either haven't been pop-ed yet,
    // or they haven't even been completed.
    to_pop: u32,
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

        Self::check_features(params)?;

        let squeue = SubmissionQueue::new(fd, &params).map_err(Error::SQueue)?;
        let cqueue = CompletionQueue::new(fd, &params).map_err(Error::CQueue)?;

        let instance = Self {
            fd: file,
            squeue,
            cqueue,
            registered_fds_count: 0,
            to_pop: 0,
        };

        instance.check_operations()?;

        Ok(instance)
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
        self.cqueue
            .pop()
            .map(|maybe_cqe| {
                maybe_cqe.map(|cqe| {
                    // This is safe since the pop-ed CQEs have been previously submitted. However
                    // we use a saturating_sub for extra safety.
                    self.to_pop = self.to_pop.saturating_sub(1);
                    cqe
                })
            })
            .map_err(Error::CQueue)
    }

    fn do_submit(&mut self, min_complete: u32) -> Result<u32> {
        self.squeue
            .submit(min_complete)
            .map(|submitted| {
                // This is safe since submitted < IORING_MAX_ENTRIES (32768)
                // and self.to_pop < IORING_MAX_CQ_ENTRIES (65536)
                self.to_pop += submitted;
                submitted
            })
            .map_err(Error::SQueue)
    }

    pub fn submit(&mut self) -> Result<u32> {
        self.do_submit(0)
    }

    pub fn submit_and_wait_all(&mut self) -> Result<u32> {
        // This is safe since to_submit < IORING_MAX_ENTRIES (32768)
        // and self.to_pop < IORING_MAX_CQ_ENTRIES (65536)
        let total_num_ops = self.squeue.to_submit() + self.to_pop;
        self.do_submit(total_num_ops)
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

    fn check_features(params: io_uring_params) -> Result<()> {
        // We require that the host kernel will never drop completed entries due to an (unlikely)
        // overflow in the completion queue.
        // This feature is supported for kernels greater than 5.7.
        // An alternative fix would be to keep an internal counter that tracks the number of
        // submitted entries that haven't been completed and makes sure it doesn't exceed
        // (2 * num_entries).
        if (params.features & bindings::IORING_FEAT_NODROP) == 0 {
            return Err(Error::UnsupportedFeature("IORING_FEAT_NODROP"));
        }

        Ok(())
    }

    fn check_operations(&self) -> Result<()> {
        let mut probes = ProbeWrapper::new(PROBE_LEN).map_err(Error::FamError)?;

        // Safe because values are valid and we check the return value.
        SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                bindings::IORING_REGISTER_PROBE,
                probes.as_mut_fam_struct_ptr(),
                PROBE_LEN,
            )
        } as libc::c_int)
        .into_empty_result()
        .map_err(Error::Probe)?;

        let supported_opcodes: HashSet<u8> = probes
            .as_slice()
            .iter()
            .filter(|op| ((op.flags as u32) & bindings::IO_URING_OP_SUPPORTED) != 0)
            .map(|op| op.op)
            .collect();

        for opcode in REQUIRED_OPS.iter() {
            if !supported_opcodes.contains(&(*opcode as u8)) {
                return Err(Error::UnsupportedOperation((*opcode).into()));
            }
        }

        Ok(())
    }
}
