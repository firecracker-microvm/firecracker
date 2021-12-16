// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::num::Wrapping;
use std::os::unix::io::RawFd;
use std::result::Result;
use std::sync::atomic::Ordering;
use vm_memory::{Bytes, MmapRegion, VolatileMemory, VolatileMemoryError};

use super::mmap::{mmap, Error as MmapError};
use crate::bindings;
use crate::operation::Cqe;

#[derive(Debug)]
pub enum Error {
    Mmap(MmapError),
    VolatileMemory(VolatileMemoryError),
}

pub(crate) struct CompletionQueue {
    // Offsets.
    head_off: usize,
    tail_off: usize,
    cqes_off: usize,

    // Cached values.
    unmasked_head: Wrapping<u32>,
    count: u32,
    ring_mask: u32,

    // Mmap-ed cqes ring.
    cqes: MmapRegion,
}

impl CompletionQueue {
    pub(crate) fn new(
        io_uring_fd: RawFd,
        params: &bindings::io_uring_params,
    ) -> Result<Self, Error> {
        let offsets = params.cq_off;

        // Map the CQ_ring. The actual size of the ring is `num_entries * size_of(entry_type)`.
        // To this we add an offset as per the io_uring specifications.
        let ring_size = (params.cq_off.cqes as usize)
            + (params.cq_entries as usize) * std::mem::size_of::<bindings::io_uring_cqe>();
        let cqes = mmap(ring_size, io_uring_fd, bindings::IORING_OFF_CQ_RING.into())
            .map_err(Error::Mmap)?;

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
            count: params.cq_entries,
            ring_mask,
            cqes,
        })
    }

    pub(crate) fn count(&self) -> u32 {
        self.count
    }

    pub(crate) fn pop<T>(&mut self) -> Result<Option<Cqe<T>>, Error> {
        let ring = self.cqes.as_volatile_slice();
        // get the head & tail
        let head = self.unmasked_head.0 & self.ring_mask;
        let unmasked_tail = ring
            .load::<u32>(self.tail_off, Ordering::Acquire)
            .map_err(Error::VolatileMemory)?;

        // validate that we have smth to fetch
        if Wrapping(unmasked_tail) - self.unmasked_head > Wrapping(0) {
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
}

impl Drop for CompletionQueue {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.cqes.as_ptr() as *mut libc::c_void, self.cqes.size()) };
    }
}
