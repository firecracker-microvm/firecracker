// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Error as IOError;
use std::mem;
use std::num::Wrapping;
use std::os::unix::io::RawFd;
use std::result::Result;
use std::sync::atomic::Ordering;

use utils::syscall::SyscallReturnCode;
use vm_memory::{mmap::MmapRegionError, Bytes, MmapRegion, VolatileMemory, VolatileMemoryError};

use crate::bindings;
use crate::operation::Sqe;

#[derive(Debug)]
pub enum Error {
    EmptyQueue,
    FullQueue,
    Mmap(IOError),
    BuildMmapRegion(MmapRegionError),
    VolatileMemory(VolatileMemoryError),
    Submit(IOError),
    WaitTooLong,
}

pub struct SubmissionQueue {
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

    // Number of values yet to be submitted.
    to_submit: u64,
}

impl SubmissionQueue {
    pub fn new(io_uring_fd: RawFd, params: &bindings::io_uring_params) -> Result<Self, Error> {
        let (ring, sqes) = Self::mmap(io_uring_fd, params)?;
        let ring_slice = ring.as_volatile_slice();

        // since we don't need the extra layer of indirection, we can simply map the index array
        // to be array[i] = i;
        let sq_array = ring_slice
            .offset(params.sq_off.array as usize)
            .map_err(Error::VolatileMemory)?;
        for i in 0..params.sq_entries {
            sq_array
                .write_obj(i, mem::size_of::<u32>() * (i as usize))
                .map_err(Error::VolatileMemory)?;
        }

        let ring_mask = ring_slice
            .read_obj(params.sq_off.ring_mask as usize)
            .map_err(Error::VolatileMemory)?;

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

    pub fn push<T>(&mut self, sqe: Sqe) -> Result<(), (Error, T)> {
        let ring_slice = self.ring.as_volatile_slice();

        // get the sqe tail
        let tail = self.unmasked_tail.0 & self.ring_mask;

        // get the pending sqes
        let pending = match self.pending() {
            Ok(n) => n,
            Err(err) => return Err((err, unsafe { sqe.user_data() })),
        };

        if pending >= self.count {
            return Err((Error::FullQueue, unsafe { sqe.user_data() }));
        }

        // retrieve and populate the sqe
        if let Err(err) = self.sqes.as_volatile_slice().write_obj(
            sqe.0,
            (tail as usize) * mem::size_of::<bindings::io_uring_sqe>(),
        ) {
            return Err((Error::VolatileMemory(err), unsafe { sqe.user_data() }));
        }

        // increment the sqe tail
        self.unmasked_tail += Wrapping(1u32);

        if let Err(err) = ring_slice.store(self.unmasked_tail.0, self.tail_off, Ordering::Release) {
            return Err((Error::VolatileMemory(err), unsafe { sqe.user_data() }));
        }

        self.to_submit += 1;

        Ok(())
    }

    pub fn submit(&mut self, wait_for: u32) -> Result<u64, Error> {
        if wait_for > self.pending()? {
            return Err(Error::WaitTooLong);
        }
        if self.to_submit < 1 {
            // Nothing to submit.
            return Ok(0);
        }

        let mut flags = 0;

        if wait_for > 0 {
            flags |= bindings::IORING_ENTER_GETEVENTS;
        }
        // Safe because values are valid and we check the return value.
        SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                self.io_uring_fd,
                self.to_submit,
                wait_for,
                flags,
                std::ptr::null() as *const libc::sigset_t,
            )
        } as libc::c_int)
        .into_empty_result()
        .map_err(Error::Submit)?;

        let submitted = self.to_submit;
        self.to_submit = 0;

        Ok(submitted)
    }

    fn mmap(
        io_uring_fd: RawFd,
        params: &bindings::io_uring_params,
    ) -> Result<(MmapRegion, MmapRegion), Error> {
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_SHARED | libc::MAP_POPULATE;
        let sqe_ring_size =
            (params.sq_off.array as usize) + (params.sq_entries as usize) * mem::size_of::<u32>();
        let sqes_array_size =
            (params.sq_entries as usize) * mem::size_of::<bindings::io_uring_sqe>();

        // map the SQ_ring
        // Safe because values are valid and we check the return value.
        let ring_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                sqe_ring_size,
                prot,
                flags,
                io_uring_fd,
                bindings::IORING_OFF_SQ_RING.into(),
            )
        };

        if (ring_ptr as isize) < 0 {
            return Err(Error::Mmap(IOError::last_os_error()));
        }

        // Safe because values are valid and we check the return value.
        let sqe_ring = unsafe {
            MmapRegion::build_raw(ring_ptr as *mut u8, sqe_ring_size, prot, flags)
                .map_err(Error::BuildMmapRegion)?
        };

        // map the SQEs
        // Safe because values are valid and we check the return value.
        let sqes_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                sqes_array_size,
                prot,
                flags,
                // it's actually u32
                io_uring_fd,
                bindings::IORING_OFF_SQES.into(),
            )
        };

        if (sqes_ptr as isize) < 0 {
            return Err(Error::Mmap(IOError::last_os_error()));
        }
        // Safe because values are valid and we check the return value.
        let sqes = unsafe {
            MmapRegion::build_raw(sqes_ptr as *mut u8, sqes_array_size, prot, flags)
                .map_err(Error::BuildMmapRegion)?
        };

        Ok((sqe_ring, sqes))
    }

    pub fn pending(&self) -> Result<u32, Error> {
        let ring_slice = self.ring.as_volatile_slice();
        // get the sqe head
        let unmasked_head = ring_slice
            .load::<u32>(self.head_off, Ordering::Acquire)
            .map_err(Error::VolatileMemory)?;

        Ok((self.unmasked_tail - Wrapping(unmasked_head)).0)
    }
}

impl Drop for SubmissionQueue {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ring.as_ptr() as *mut libc::c_void, self.ring.size()) };
        unsafe { libc::munmap(self.sqes.as_ptr() as *mut libc::c_void, self.sqes.size()) };
    }
}
