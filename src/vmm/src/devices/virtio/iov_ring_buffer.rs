// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::AsRawFd;

use libc::{c_int, c_void, iovec, off_t, size_t};
use memfd::{self, FileSeal, Memfd, MemfdOptions};

use super::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::arch::PAGE_SIZE;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum IovRingBufferError {
    /// Error with memfd: {0}
    Memfd(#[from] memfd::Error),
    /// Error while resizing memfd: {0}
    MemfdResize(std::io::Error),
    /// Error calling mmap: {0}
    Mmap(std::io::Error),
}

/// ['IovRingBuffer'] is a ring buffer tailored for `struct iovec` objects.
///
/// From the point of view of API, [`IovRingBuffer`] is a typical ring buffer that allows us to push
/// `struct iovec` objects at the end of the buffer and pop them from its beginning.
///
/// It is tailored to store `struct iovec` objects that described memory that was passed to us from
/// the guest via a VirtIO queue. This allows us to assume the maximum size of a ring buffer (the
/// negotiated size of the queue).
// An important feature of the data structure is that it can give us a slice of all `struct iovec`
// objects in the queue, so that we can use this `&mut [iovec]` to perform operations such as
// `readv`. A typical implementation of a ring buffer allows for entries to wrap around the end of
// the underlying buffer. For example, a ring buffer with a capacity of 10 elements which
// currently holds 4 elements can look like this:
//
//                      tail                        head
//                       |                           |
//                       v                           v
//                 +---+---+---+---+---+---+---+---+---+---+
// ring buffer:    | C | D |   |   |   |   |   |   | A | B |
//                 +---+---+---+---+---+---+---+---+---+---+
//
// When getting a slice for this data we should get something like that: &[A, B, C, D], which
// would require copies in order to make the elements continuous in memory.
//
// In order to avoid that and make the operation of getting a slice more efficient, we implement
// the optimization described in the "Optimization" section of the "Circular buffer" wikipedia
// entry: https://en.wikipedia.org/wiki/Circular_buffer. The optimization consists of allocating
// double the size of the virtual memory required for the buffer and map both parts on the same
// physical address. Looking at the same example as before, we should get, this picture:
//
//                                    head   |    tail
//                                     |     |     |
//                                     v     |     v
//   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//   | C | D |   |   |   |   |   |   | A | B | C | D |   |   |   |   |   |   | A | B |
//   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//            First virtual page             |       Second virtual page
//                                           |
//                                           |
//
//                                     Virtual memory
// ---------------------------------------------------------------------------------------
//                                    Physical memory
//
//                      +---+---+---+---+---+---+---+---+---+---+
//                      | C | D |   |   |   |   |   |   | A | B |
//                      +---+---+---+---+---+---+---+---+---+---+
//
// Like that, the elements stored in the buffer are always laid out in contiguous virtual memory,
// so making a slice out of them does not require any copies.
#[derive(Debug)]
pub struct IovRingBuffer {
    iov_ptr: *mut iovec,
    start: usize,
    len: usize,
}

// SAFETY: This is `Send`. We hold sole ownership of the underlying buffer.
unsafe impl Send for IovRingBuffer {}

impl IovRingBuffer {
    /// Create a [`memfd`] object that represents a single physical page
    fn create_memfd() -> Result<Memfd, IovRingBufferError> {
        // Create a sealable memfd.
        let opts = MemfdOptions::default().allow_sealing(true);
        let mfd = opts.create("sized-1K")?;

        // Resize to system page size.
        mfd.as_file()
            .set_len(PAGE_SIZE.try_into().unwrap())
            .map_err(IovRingBufferError::MemfdResize)?;

        // Add seals to prevent further resizing.
        mfd.add_seals(&[FileSeal::SealShrink, FileSeal::SealGrow])?;

        // Prevent further sealing changes.
        mfd.add_seal(FileSeal::SealSeal)?;

        Ok(mfd)
    }

    /// Wrapper for libc's `mmap` system call
    unsafe fn mmap(
        addr: *mut c_void,
        len: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> Result<*mut c_void, IovRingBufferError> {
        // SAFETY: We are calling the system call with valid arguments and properly checking its
        // return value
        let ptr = unsafe { libc::mmap(addr, len, prot, flags, fd, offset) };
        if ptr == libc::MAP_FAILED {
            return Err(IovRingBufferError::Mmap(std::io::Error::last_os_error()));
        }

        Ok(ptr)
    }

    /// Allocate memory for our ring buffer
    ///
    /// This will allocate exactly two pages of virtual memory. In order to implement the
    /// optimization that allows us to always have elements in contiguous memory we need
    /// allocations at the granularity of `PAGE_SIZE`. Now, our queues are at maximum 256
    /// descriptors long and `struct iovec` looks like this:
    ///
    /// ```Rust
    /// pub struct iovec {
    ///    pub iov_base: *mut ::c_void,
    ///    pub iov_len: ::size_t,
    /// }
    /// ```
    ///
    /// so, it's 16 bytes long. As a result, we need a single page for holding the actual data of
    /// our buffer.
    fn allocate_ring_buffer_memory() -> Result<*mut c_void, IovRingBufferError> {
        // The fact that we allocate two pages is due to the size of `struct iovec` times our queue
        // size equals the page size. Add here a debug assertion to reflect that and ensure that we
        // will adapt our logic if the assumption changes in the future.
        debug_assert_eq!(
            std::mem::size_of::<iovec>() * usize::from(FIRECRACKER_MAX_QUEUE_SIZE),
            PAGE_SIZE
        );

        // SAFETY: We are calling this function with valid arguments
        unsafe {
            Self::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE * 2,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        }
    }

    /// Create a new [`IovRingBuffer`] that can hold memory described by a single VirtIO queue.
    pub fn new() -> Result<Self, IovRingBufferError> {
        let memfd = Self::create_memfd()?;
        let raw_memfd = memfd.as_file().as_raw_fd();
        let buffer = Self::allocate_ring_buffer_memory()?;

        // Map the first page of virtual memory to the physical page described by the memfd object
        // SAFETY: We are calling this function with valid arguments
        unsafe {
            let _ = Self::mmap(
                buffer,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                raw_memfd,
                0,
            )?;
        }

        // Map the second page of virtual memory to the physical page described by the memfd object
        // SAFETY: safe because `Self::allocate_ring_buffer_memory` allocates exactly two pages for
        // us
        let next_page = unsafe { buffer.add(PAGE_SIZE) };
        // SAFETY: We are calling this function with valid arguments
        unsafe {
            let _ = Self::mmap(
                next_page,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                raw_memfd,
                0,
            )?;
        }

        Ok(Self {
            iov_ptr: buffer.cast(),
            start: 0,
            len: 0,
            // head: 0,
            // tail: 0,
        })
    }

    /// Returns the number of `iovec` objects currently in the [`IovRingBuffer`]
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the [`IovRingBuffer`] is empty, `false` otherwise
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if the [`IovRingBuffer`] is full, `false` otherwise
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.len == usize::from(FIRECRACKER_MAX_QUEUE_SIZE)
    }

    /// Adds an `iovec` in the ring buffer.
    /// Panics if the queue is already full.
    pub fn push_back(&mut self, iov: iovec) {
        // This should NEVER happen, since our ring buffer is as big as the maximum queue size.
        // We also check for the sanity of the VirtIO queues, in queue.rs, which means that if we
        // ever try to add something in a full ring buffer, there is an internal bug in the device
        // emulation logic. Panic here because the device is hopelessly broken.
        if self.is_full() {
            panic!("The number of `iovec` objects is bigger than the available space");
        }

        // SAFETY: iov_ptr is valid and tail is within bounds
        unsafe {
            self.iov_ptr.add(self.start + self.len).write(iov);
        }
        self.len += 1;
    }

    /// Pop first `n` iovs from the back of the queue.
    /// Panics if `n` is greater than length of the queue.
    pub fn pop_back(&mut self, n: usize) {
        if self.len() < n {
            panic!("Attempt to pop more objects than are in the queue");
        }
        // We don't need to care about case where tail will underflow
        // because this can only occur if the ring overflow.
        self.len -= n;
    }

    /// Pop first `n` iovs from the front of the queue.
    /// Panics if `n` is greater than length of the queue.
    pub fn pop_front(&mut self, n: usize) {
        if self.len() < n {
            panic!("Attempt to pop more objects than are in the queue");
        }
        self.start += n;
        self.len -= n;
        if usize::from(FIRECRACKER_MAX_QUEUE_SIZE) <= self.start {
            self.start -= usize::from(FIRECRACKER_MAX_QUEUE_SIZE);
        }
    }

    /// Gets a slice of the `iovec` objects currently in the buffer.
    pub fn as_slice(&self) -> &[iovec] {
        // SAFETY: we create a slice which does not touch same memory twice.
        // slice_start and slice_len are valid values.
        unsafe {
            let slice_start = self.iov_ptr.add(self.start);
            let slice_len = self.len;
            std::slice::from_raw_parts(slice_start, slice_len)
        }
    }

    /// Gets a mutable slice of the `iovec` objects currently in the buffer.
    pub fn as_mut_slice(&mut self) -> &mut [iovec] {
        // SAFETY: we create a slice which does not touch same memory twice.
        // slice_start and slice_len are valid values.
        unsafe {
            let slice_start = self.iov_ptr.add(self.start);
            let slice_len = self.len;
            std::slice::from_raw_parts_mut(slice_start, slice_len)
        }
    }
}

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let ring_buffer = IovRingBuffer::new().unwrap();
        assert!(ring_buffer.is_empty());
    }

    fn make_iovec(id: usize, len: usize) -> iovec {
        iovec {
            iov_base: id as *mut libc::c_void,
            iov_len: len,
        }
    }

    #[test]
    #[should_panic]
    fn test_push_back() {
        let mut ring_buffer = IovRingBuffer::new().unwrap();
        assert!(ring_buffer.is_empty());

        for i in 0..256 {
            ring_buffer.push_back(make_iovec(i, i));
            assert_eq!(ring_buffer.len(), i + 1);
        }

        ring_buffer.push_back(make_iovec(0, 0));
    }

    #[test]
    #[should_panic]
    fn test_pop_back_empty() {
        let mut deque = IovRingBuffer::new().unwrap();
        assert!(deque.is_empty());
        assert!(!deque.is_full());

        deque.pop_back(1);
    }

    #[test]
    fn test_pop_back() {
        let mut ring_buffer = IovRingBuffer::new().unwrap();
        assert!(ring_buffer.is_empty());
        assert!(!ring_buffer.is_full());

        for i in 0..256 {
            ring_buffer.push_back(make_iovec(i, i));
            assert_eq!(ring_buffer.len(), i + 1);
        }

        assert!(ring_buffer.is_full());
        assert!(!ring_buffer.is_empty());

        ring_buffer.pop_back(256);
        assert!(ring_buffer.is_empty());
        assert!(!ring_buffer.is_full());
    }

    #[test]
    #[should_panic]
    fn test_pop_front_empty() {
        let mut ring_buffer = IovRingBuffer::new().unwrap();
        assert!(ring_buffer.is_empty());
        assert!(!ring_buffer.is_full());

        ring_buffer.pop_front(1);
    }

    #[test]
    fn test_pop_front() {
        let mut ring_buffer = IovRingBuffer::new().unwrap();
        assert!(ring_buffer.is_empty());
        assert!(!ring_buffer.is_full());

        for i in 0..256 {
            ring_buffer.push_back(make_iovec(i, i));
            assert_eq!(ring_buffer.len(), i + 1);
        }

        assert!(ring_buffer.is_full());
        assert!(!ring_buffer.is_empty());

        ring_buffer.pop_front(256);
        assert!(ring_buffer.is_empty());
        assert!(!ring_buffer.is_full());
    }

    #[test]
    fn test_as_slice() {
        let mut buffer = IovRingBuffer::new().unwrap();
        assert_eq!(buffer.as_mut_slice(), &mut []);

        for i in 0..256 {
            buffer.push_back(make_iovec(i, 100));
        }

        let buffer_len = buffer.len();
        let slice = buffer.as_slice();
        assert_eq!(slice.len(), buffer_len);
        for i in 0..256 {
            assert_eq!(slice[i], make_iovec(i, 100));
        }

        let slice = buffer.as_mut_slice();
        assert_eq!(slice.len(), buffer_len);
        for i in 0..256 {
            assert_eq!(slice[i], make_iovec(i, 100));
        }

        buffer.pop_front(256);
        assert!(buffer.is_empty());
        assert_eq!(buffer.as_slice(), &mut []);
        assert_eq!(buffer.as_mut_slice(), &mut []);
    }
}
