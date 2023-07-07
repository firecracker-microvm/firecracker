// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::io::Error as IOError;
use std::mem;
use std::num::Wrapping;
use std::os::unix::io::RawFd;
use std::sync::atomic::Ordering;

use utils::syscall::SyscallReturnCode;
use utils::vm_memory::{Bytes, MmapRegion, VolatileMemory, VolatileMemoryError};

use super::mmap::{mmap, MmapError};
use crate::io_uring::bindings;
use crate::io_uring::operation::Sqe;

#[derive(Debug, derive_more::From)]
/// SQueue Error.
pub enum SQueueError {
    /// The queue is full.
    FullQueue,
    /// Error mapping the ring.
    Mmap(MmapError),
    /// Error reading/writing volatile memory.
    VolatileMemory(VolatileMemoryError),
    /// Error returned by `io_uring_enter`.
    Submit(IOError),
}

#[derive(Debug)]
pub(crate) struct SubmissionQueue {
    io_uring_fd: RawFd,

    // Offsets.
    head_off: usize,
    tail_off: usize,

    // Cached values.
    ring_mask: u32,
    count: u32,
    unmasked_tail: Wrapping<u32>,

    // Mmap-ed ring.
    ring: MmapRegion,
    // Mmap-ed sqes.
    sqes: MmapRegion,

    // Number of ops yet to be submitted.
    to_submit: u32,
}

impl SubmissionQueue {
    pub(crate) fn new(
        io_uring_fd: RawFd,
        params: &bindings::io_uring_params,
    ) -> Result<Self, SQueueError> {
        let (ring, sqes) = Self::mmap(io_uring_fd, params)?;
        let ring_slice = ring.as_volatile_slice();

        // since we don't need the extra layer of indirection, we can simply map the index array
        // to be array[i] = i;
        let sq_array = ring_slice.offset(params.sq_off.array as usize)?;
        for i in 0..params.sq_entries {
            sq_array.write_obj(i, mem::size_of::<u32>() * (i as usize))?;
        }

        let ring_mask = ring_slice.read_obj(params.sq_off.ring_mask as usize)?;

        Ok(Self {
            io_uring_fd,
            head_off: params.sq_off.head as usize,
            tail_off: params.sq_off.tail as usize,
            ring_mask,
            count: params.sq_entries,
            // We can init this to 0 and cache it because we are the only ones modifying it.
            unmasked_tail: Wrapping(0),
            ring,
            sqes,
            to_submit: 0,
        })
    }

    /// # Safety
    /// Unsafe because we pass a raw `user_data` pointer to the kernel.
    /// It's up to the caller to make sure that this value is ever freed (not leaked).
    pub(crate) unsafe fn push<T: Debug>(&mut self, sqe: Sqe) -> Result<(), (SQueueError, T)> {
        let ring_slice = self.ring.as_volatile_slice();

        // get the sqe tail
        let tail = self.unmasked_tail.0 & self.ring_mask;

        // get the pending sqes
        let pending = match self.pending() {
            Ok(n) => n,
            Err(err) => return Err((err, sqe.user_data())),
        };

        if pending >= self.count {
            return Err((SQueueError::FullQueue, sqe.user_data()));
        }

        // retrieve and populate the sqe
        if let Err(err) = self.sqes.as_volatile_slice().write_obj(
            sqe.0,
            (tail as usize) * mem::size_of::<bindings::io_uring_sqe>(),
        ) {
            return Err((SQueueError::VolatileMemory(err), sqe.user_data()));
        }

        // increment the sqe tail
        self.unmasked_tail += Wrapping(1u32);

        if let Err(err) = ring_slice.store(self.unmasked_tail.0, self.tail_off, Ordering::Release) {
            return Err((SQueueError::VolatileMemory(err), sqe.user_data()));
        }

        // This is safe since we already checked if there is enough space in the queue;
        self.to_submit += 1;

        Ok(())
    }

    pub(crate) fn submit(&mut self, min_complete: u32) -> Result<u32, SQueueError> {
        if self.to_submit == 0 && min_complete == 0 {
            // Nothing to submit and nothing to wait for.
            return Ok(0);
        }

        let mut flags = 0;

        if min_complete > 0 {
            flags |= bindings::IORING_ENTER_GETEVENTS;
        }
        // SAFETY: Safe because values are valid and we check the return value.
        let submitted = SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                self.io_uring_fd,
                self.to_submit,
                min_complete,
                flags,
                std::ptr::null::<libc::sigset_t>(),
            )
        } as libc::c_int)
        .into_result()?;
        // It's safe to convert to u32 since the syscall didn't return an error.
        let submitted = u32::try_from(submitted).unwrap();

        // This is safe since submitted <= self.to_submit. However we use a saturating_sub
        // for extra safety.
        self.to_submit = self.to_submit.saturating_sub(submitted);

        Ok(submitted)
    }

    fn mmap(
        io_uring_fd: RawFd,
        params: &bindings::io_uring_params,
    ) -> Result<(MmapRegion, MmapRegion), SQueueError> {
        // map the SQ_ring. The actual size of the ring is `num_entries * size_of(entry_type)`.
        // To this we add an offset as per the io_uring specifications.
        let sqe_ring_size =
            (params.sq_off.array as usize) + (params.sq_entries as usize) * mem::size_of::<u32>();

        let sqe_ring = mmap(
            sqe_ring_size,
            io_uring_fd,
            bindings::IORING_OFF_SQ_RING.into(),
        )?;

        // map the SQEs.
        let sqes_array_size =
            (params.sq_entries as usize) * mem::size_of::<bindings::io_uring_sqe>();

        let sqes = mmap(
            sqes_array_size,
            io_uring_fd,
            bindings::IORING_OFF_SQES.into(),
        )?;

        Ok((sqe_ring, sqes))
    }

    pub(crate) fn pending(&self) -> Result<u32, SQueueError> {
        let ring_slice = self.ring.as_volatile_slice();
        // get the sqe head
        let unmasked_head = ring_slice.load::<u32>(self.head_off, Ordering::Acquire)?;

        Ok((self.unmasked_tail - Wrapping(unmasked_head)).0)
    }
}

impl Drop for SubmissionQueue {
    fn drop(&mut self) {
        // SAFETY: Safe because parameters are valid.
        unsafe { libc::munmap(self.ring.as_ptr().cast::<libc::c_void>(), self.ring.size()) };
        // SAFETY: Safe because parameters are valid.
        unsafe { libc::munmap(self.sqes.as_ptr().cast::<libc::c_void>(), self.sqes.size()) };
    }
}
