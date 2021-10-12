// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Error as IOError;
use std::num::Wrapping;
use std::os::unix::io::RawFd;
use std::result::Result;
use std::sync::atomic::Ordering;
use vm_memory::{mmap::MmapRegionError, Bytes, MmapRegion, VolatileMemory, VolatileMemoryError};

use crate::bindings;
use crate::operation::Cqe;

#[derive(Debug)]
pub enum Error {
    EmptyQueue,
    Mmap(IOError),
    VolatileMemory(VolatileMemoryError),
    BuildMmapRegion(MmapRegionError),
}

pub struct CompletionQueue {
    // Offsets.
    head_off: usize,
    tail_off: usize,
    cqes_off: usize,

    // Cached values.
    unmasked_head: Wrapping<u32>,
    ring_mask: u32,

    // Mmap-ed cqes ring.
    cqes: MmapRegion,
}

impl CompletionQueue {
    pub fn new(io_uring_fd: RawFd, params: &bindings::io_uring_params) -> Result<Self, Error> {
        let offsets = params.cq_off;

        // Map the CQ_ring
        let cqes = Self::mmap(io_uring_fd, params)?;
        let ring = cqes.as_volatile_slice();
        let ring_mask = ring
            .read_obj(offsets.ring_mask as usize)
            .map_err(Error::VolatileMemory)?;

        Ok(Self {
            // safe because it's an u32 offset
            head_off: offsets.head as usize,
            // safe because it's an u32 offset
            tail_off: offsets.tail as usize,
            // safe because it's an u32 offset
            cqes_off: offsets.cqes as usize,
            // We can init this to 0 and cache it because we are the only ones modifying it.
            unmasked_head: Wrapping(0),
            ring_mask,
            cqes,
        })
    }

    pub fn pop<T>(&mut self) -> Result<Option<Cqe<T>>, Error> {
        let ring = self.cqes.as_volatile_slice();
        // get the head & tail
        let head = self.unmasked_head.0 & self.ring_mask;
        let tail = ring
            .load::<u32>(self.tail_off, Ordering::Acquire)
            .map_err(Error::VolatileMemory)?
            & self.ring_mask;

        // validate that we have smth to fetch
        if head != tail {
            let cqe: bindings::io_uring_cqe = ring
                .read_obj(
                    self.cqes_off + (head as usize) * std::mem::size_of::<bindings::io_uring_cqe>(),
                )
                .map_err(Error::VolatileMemory)?;

            // increase the head
            self.unmasked_head += Wrapping(1u32);
            ring.store(self.unmasked_head.0, self.head_off, Ordering::Release)
                .map_err(Error::VolatileMemory)?;

            Ok(Some(unsafe { Cqe::new(cqe) }))
        } else {
            Ok(None)
        }
    }

    fn mmap(io_uring_fd: RawFd, params: &bindings::io_uring_params) -> Result<MmapRegion, Error> {
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_SHARED | libc::MAP_POPULATE;
        let ring_size = (params.cq_off.cqes as usize)
            + (params.cq_entries as usize) * std::mem::size_of::<bindings::io_uring_cqe>();
        // Safe because values are valid and we check the return value.
        let ring_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                prot,
                flags,
                io_uring_fd,
                bindings::IORING_OFF_CQ_RING.into(),
            )
        };
        if (ring_ptr as isize) < 0 {
            return Err(Error::Mmap(IOError::last_os_error()));
        }
        // Safe because the mmap did not return error.
        unsafe {
            MmapRegion::build_raw(ring_ptr as *mut u8, ring_size, prot, flags)
                .map_err(Error::BuildMmapRegion)
        }
    }
}

impl Drop for CompletionQueue {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.cqes.as_ptr() as *mut libc::c_void, self.cqes.size()) };
    }
}
