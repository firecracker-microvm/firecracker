// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::AsRawFd;

use libc::{c_int, c_void, iovec, off_t, size_t};
use memfd;

use crate::arch::host_page_size;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum IovDequeError {
    /// Error with memfd: {0}
    Memfd(#[from] memfd::Error),
    /// Error while resizing memfd: {0}
    MemfdResize(std::io::Error),
    /// Error calling mmap: {0}
    Mmap(std::io::Error),
}

/// ['IovDeque'] is a ring buffer tailored for `struct iovec` objects.
///
/// From the point of view of API, [`IovDeque`] is a typical ring buffer that allows us to push
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
//
// The `L` const generic determines the maximum number of `iovec` elements the queue should hold
// at any point in time. The actual capacity of the queue may differ and will depend on the host
// page size.
//
// ```Rust
// pub struct iovec {
//    pub iov_base: *mut ::c_void,
//    pub iov_len: ::size_t,
// }
// ```

#[derive(Debug)]
pub struct IovDeque<const L: u16> {
    pub iov: *mut libc::iovec,
    pub start: u16,
    pub len: u16,
    pub capacity: u16,
}

// SAFETY: This is `Send`. We hold sole ownership of the underlying buffer.
unsafe impl<const L: u16> Send for IovDeque<L> {}

impl<const L: u16> IovDeque<L> {
    /// Create a [`memfd`] object that represents a single physical page
    fn create_memfd(pages_bytes: usize) -> Result<memfd::Memfd, IovDequeError> {
        // Create a sealable memfd.
        let opts = memfd::MemfdOptions::default().allow_sealing(true);
        let mfd = opts.create("iov_deque")?;

        // Resize to system page size.
        mfd.as_file()
            .set_len(pages_bytes.try_into().unwrap())
            .map_err(IovDequeError::MemfdResize)?;

        // Add seals to prevent further resizing.
        mfd.add_seals(&[memfd::FileSeal::SealShrink, memfd::FileSeal::SealGrow])?;

        // Prevent further sealing changes.
        mfd.add_seal(memfd::FileSeal::SealSeal)?;

        Ok(mfd)
    }

    /// A safe wrapper on top of libc's `mmap` system call
    ///
    /// # Safety: Callers need to make sure that the arguments to `mmap` are valid
    unsafe fn mmap(
        addr: *mut c_void,
        len: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> Result<*mut c_void, IovDequeError> {
        // SAFETY: caller should ensure the parameters are valid
        let ptr = unsafe { libc::mmap(addr, len, prot, flags, fd, offset) };
        if ptr == libc::MAP_FAILED {
            return Err(IovDequeError::Mmap(std::io::Error::last_os_error()));
        }

        Ok(ptr)
    }

    /// Allocate memory for our ring buffer
    ///
    /// This will allocate 2 * `pages_bytes` bytes of virtual memory.
    fn allocate_ring_buffer_memory(pages_bytes: usize) -> Result<*mut c_void, IovDequeError> {
        // SAFETY: We are calling the system call with valid arguments
        unsafe {
            Self::mmap(
                std::ptr::null_mut(),
                pages_bytes * 2,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        }
    }

    /// Calculate a number of bytes in full pages required for
    /// the type to operate.
    fn pages_bytes() -> usize {
        let host_page_size = host_page_size();
        let bytes = L as usize * std::mem::size_of::<iovec>();
        let num_host_pages = bytes.div_ceil(host_page_size);
        num_host_pages * host_page_size
    }

    /// Create a new [`IovDeque`] that can hold memory described by a single VirtIO queue.
    pub fn new() -> Result<Self, IovDequeError> {
        let pages_bytes = Self::pages_bytes();
        let capacity = pages_bytes / std::mem::size_of::<iovec>();
        let capacity: u16 = capacity.try_into().unwrap();
        assert!(
            L <= capacity,
            "Actual capacity {} is smaller than requested capacity {}",
            capacity,
            L
        );

        let memfd = Self::create_memfd(pages_bytes)?;
        let raw_memfd = memfd.as_file().as_raw_fd();
        let buffer = Self::allocate_ring_buffer_memory(pages_bytes)?;

        // Map the first page of virtual memory to the physical page described by the memfd object
        // SAFETY: We are calling the system call with valid arguments
        let _ = unsafe {
            Self::mmap(
                buffer,
                pages_bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                raw_memfd,
                0,
            )
        }?;

        // Map the second page of virtual memory to the physical page described by the memfd object
        //
        // SAFETY: This is safe because:
        // * Both `buffer` and the result of `buffer.add(pages_bytes)` are within bounds of the
        //   allocation we got from `Self::allocate_ring_buffer_memory`.
        // * The resulting pointer is the beginning of the second page of our allocation, so it
        //   doesn't wrap around the address space.
        let next_page = unsafe { buffer.add(pages_bytes) };

        // SAFETY: We are calling the system call with valid arguments
        let _ = unsafe {
            Self::mmap(
                next_page,
                pages_bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                raw_memfd,
                0,
            )
        }?;

        Ok(Self {
            iov: buffer.cast(),
            start: 0,
            len: 0,
            capacity,
        })
    }

    /// Returns the number of `iovec` objects currently in the [`IovDeque`]
    #[inline(always)]
    pub fn len(&self) -> u16 {
        self.len
    }

    /// Returns `true` if the [`IovDeque`] is full, `false` otherwise
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.len() == L
    }

    /// Resets the queue, dropping all its elements.
    #[inline(always)]
    pub fn clear(&mut self) {
        self.start = 0;
        self.len = 0;
    }

    /// Adds an `iovec` in the ring buffer.
    ///
    /// Returns an `IovDequeError::Full` error if the buffer is full.
    pub fn push_back(&mut self, iov: iovec) {
        // This should NEVER happen, since our ring buffer is as big as the maximum queue size.
        // We also check for the sanity of the VirtIO queues, in queue.rs, which means that if we
        // ever try to add something in a full ring buffer, there is an internal bug in the device
        // emulation logic. Panic here because the device is hopelessly broken.
        assert!(
            !self.is_full(),
            "The number of `iovec` objects is bigger than the available space"
        );

        // SAFETY: self.iov is a valid pointer and `self.start + self.len` is within range (we
        // asserted before that the buffer is not full).
        unsafe {
            self.iov
                .add((self.start + self.len) as usize)
                .write_volatile(iov)
        };
        self.len += 1;
    }

    /// Pops the first `nr_iovecs` iovecs from the front of the buffer.
    ///
    /// This will panic if we are asked
    /// to pop more iovecs than what is currently available in the buffer.
    pub fn pop_front(&mut self, nr_iovecs: u16) {
        assert!(
            self.len() >= nr_iovecs,
            "Internal bug! Trying to drop more iovec objects than what is available"
        );

        self.start += nr_iovecs;
        self.len -= nr_iovecs;
        if self.capacity <= self.start {
            self.start -= self.capacity;
        }
    }

    /// Pops the first `nr_iovecs` iovecs from the back of the buffer.
    ///
    /// This will panic if we are asked
    /// to pop more iovecs than what is currently available in the buffer.
    pub fn pop_back(&mut self, nr_iovecs: u16) {
        assert!(
            self.len() >= nr_iovecs,
            "Internal bug! Trying to drop more iovec objects than what is available"
        );

        self.len -= nr_iovecs;
    }

    /// Get a slice of the iovec objects currently in the buffer.
    pub fn as_slice(&self) -> &[iovec] {
        // SAFETY: Here we create a slice out of the existing elements in the buffer (not the whole
        // allocated memory). That means that we can:
        // * We can read `self.len * mem::size_of::<iovec>()` bytes out of the memory range we are
        //   returning.
        // * `self.iov.add(self.start.into())` is a non-null pointer and aligned.
        // * The underlying memory comes from a single allocation.
        // * The returning pointer points to `self.len` consecutive initialized `iovec` objects.
        // * We are only accessing the underlying memory through the returned slice. Since we are
        //   returning a slice of only the existing pushed elements the slice does not contain any
        //   aliasing references.
        // * The slice can be up to 1 page long which is smaller than `isize::MAX`.
        unsafe {
            let slice_start = self.iov.add(self.start.into());
            std::slice::from_raw_parts(slice_start, self.len.into())
        }
    }

    /// Get a mutable slice of the iovec objects currently in the buffer.
    pub fn as_mut_slice(&mut self) -> &mut [iovec] {
        // SAFETY: Here we create a slice out of the existing elements in the buffer (not the whole
        // allocated memory). That means that we can:
        // * We can read/write `self.len * mem::size_of::<iovec>()` bytes out of the memory range we
        //   are returning.
        // * The underlying memory comes from a single allocation.
        // * `self.iov.add(self.start.into())` is a non-null pointer and aligned
        // * The returning pointer points to `self.len` consecutive initialized `iovec` objects.
        // * We are only accessing the underlying memory through the returned slice. Since we are
        //   returning a slice of only the existing pushed elements the slice does not contain any
        //   aliasing references.
        // * The slice can be up to 1 page long which is smaller than `isize::MAX`.
        unsafe {
            let slice_start = self.iov.add(self.start.into());
            std::slice::from_raw_parts_mut(slice_start, self.len.into())
        }
    }
}

impl<const L: u16> Drop for IovDeque<L> {
    fn drop(&mut self) {
        let pages_bytes = Self::pages_bytes();
        // SAFETY: We are passing an address that we got from a previous allocation of `2 *
        // pages_bytes` by calling mmap
        let _ = unsafe { libc::munmap(self.iov.cast(), 2 * pages_bytes) };
    }
}

#[cfg(test)]
mod tests {
    use libc::iovec;

    // Redefine `IovDeque` with specific length. Otherwise
    // Rust will not know what to do.
    type IovDeque = super::IovDeque<256>;

    #[test]
    fn test_new() {
        let deque = IovDeque::new().unwrap();
        assert_eq!(deque.len(), 0);
    }

    #[test]
    fn test_new_less_than_page() {
        let deque = super::IovDeque::<128>::new().unwrap();
        assert_eq!(deque.len(), 0);
    }

    #[test]
    fn test_new_more_than_page() {
        let deque = super::IovDeque::<512>::new().unwrap();
        assert_eq!(deque.len(), 0);
    }

    fn make_iovec(id: u16, len: u16) -> iovec {
        iovec {
            iov_base: id as *mut libc::c_void,
            iov_len: len as usize,
        }
    }

    #[test]
    #[should_panic]
    fn test_push_back_too_many() {
        let mut deque = IovDeque::new().unwrap();
        assert_eq!(deque.len(), 0);

        for i in 0u16..256 {
            deque.push_back(make_iovec(i, i));
            assert_eq!(deque.len(), i + 1);
        }

        deque.push_back(make_iovec(0, 0));
    }

    #[test]
    #[should_panic]
    fn test_pop_front_from_empty() {
        let mut deque = IovDeque::new().unwrap();
        deque.pop_front(1);
    }

    #[test]
    #[should_panic]
    fn test_pop_front_too_many() {
        let mut deque = IovDeque::new().unwrap();
        deque.push_back(make_iovec(42, 42));
        deque.pop_front(2);
    }

    #[test]
    fn test_pop_font() {
        let mut deque = IovDeque::new().unwrap();
        assert_eq!(deque.len(), 0);
        assert!(!deque.is_full());
        deque.pop_front(0);

        let iovs: Vec<_> = (0..4).map(|i| make_iovec(i, i)).collect();
        for iov in iovs.iter() {
            deque.push_back(*iov);
        }
        assert_eq!(deque.as_slice(), &iovs);
        assert_eq!(deque.as_mut_slice(), &iovs);

        deque.pop_front(1);
        assert_eq!(deque.as_slice(), &iovs[1..]);
        assert_eq!(deque.as_mut_slice(), &iovs[1..]);
        deque.pop_front(1);
        assert_eq!(deque.as_slice(), &iovs[2..]);
        assert_eq!(deque.as_mut_slice(), &iovs[2..]);
        deque.pop_front(1);
        assert_eq!(deque.as_slice(), &iovs[3..]);
        assert_eq!(deque.as_mut_slice(), &iovs[3..]);
        deque.pop_front(1);
        assert_eq!(deque.as_slice(), &iovs[4..]);
        assert_eq!(deque.as_mut_slice(), &iovs[4..]);

        for i in 0u16..256 {
            deque.push_back(make_iovec(i, i));
            assert_eq!(deque.len(), i + 1);
        }

        assert!(deque.is_full());
        assert!(deque.len() != 0);

        for i in 0u16..256 {
            deque.pop_front(1);
            assert_eq!(deque.len(), 256 - i - 1);
        }
    }

    #[test]
    fn test_pop_back() {
        let mut deque = IovDeque::new().unwrap();
        assert_eq!(deque.len(), 0);
        assert!(!deque.is_full());
        deque.pop_back(0);

        let iovs: Vec<_> = (0..4).map(|i| make_iovec(i, i)).collect();
        for iov in iovs.iter() {
            deque.push_back(*iov);
        }
        assert_eq!(deque.as_slice(), &iovs);
        assert_eq!(deque.as_mut_slice(), &iovs);

        deque.pop_back(1);
        assert_eq!(deque.as_slice(), &iovs[..iovs.len() - 1]);
        assert_eq!(deque.as_mut_slice(), &iovs[..iovs.len() - 1]);
        deque.pop_back(1);
        assert_eq!(deque.as_slice(), &iovs[..iovs.len() - 2]);
        assert_eq!(deque.as_mut_slice(), &iovs[..iovs.len() - 2]);
        deque.pop_back(1);
        assert_eq!(deque.as_slice(), &iovs[..iovs.len() - 3]);
        assert_eq!(deque.as_mut_slice(), &iovs[..iovs.len() - 3]);
        deque.pop_back(1);
        assert_eq!(deque.as_slice(), &iovs[..iovs.len() - 4]);
        assert_eq!(deque.as_mut_slice(), &iovs[..iovs.len() - 4]);

        for i in 0u16..256 {
            deque.push_back(make_iovec(i, i));
            assert_eq!(deque.len(), i + 1);
        }

        assert!(deque.is_full());
        assert!(deque.len() != 0);

        for i in 0u16..256 {
            deque.pop_back(1);
            assert_eq!(deque.len(), 256 - i - 1);
        }
    }

    #[test]
    fn test_pop_many() {
        let mut deque = IovDeque::new().unwrap();

        for i in 0u16..256 {
            deque.push_back(make_iovec(i, i));
        }

        deque.pop_front(1);
        assert_eq!(deque.len(), 255);
        deque.pop_front(2);
        assert_eq!(deque.len(), 253);
        deque.pop_front(4);
        assert_eq!(deque.len(), 249);
        deque.pop_front(8);
        assert_eq!(deque.len(), 241);
        deque.pop_front(16);
        assert_eq!(deque.len(), 225);
        deque.pop_front(32);
        assert_eq!(deque.len(), 193);
        deque.pop_front(64);
        assert_eq!(deque.len(), 129);
        deque.pop_front(128);
        assert_eq!(deque.len(), 1);
    }

    #[test]
    fn test_as_slice() {
        let mut deque = IovDeque::new().unwrap();
        assert!(deque.as_slice().is_empty());

        for i in 0..256 {
            deque.push_back(make_iovec(i, 100));
            assert_eq!(deque.as_slice().len(), (i + 1) as usize);
        }
        let copy: Vec<iovec> = deque.as_slice().to_vec();

        assert_eq!(copy.len(), deque.len() as usize);
        for (i, iov) in deque.as_slice().iter().enumerate() {
            assert_eq!(iov.iov_len, copy[i].iov_len);
        }
    }

    #[test]
    fn test_as_mut_slice() {
        let mut deque = IovDeque::new().unwrap();
        assert!(deque.as_mut_slice().is_empty());

        for i in 0..256 {
            deque.push_back(make_iovec(i, 100));
            assert_eq!(deque.as_mut_slice().len(), (i + 1) as usize);
        }

        let copy: Vec<iovec> = deque.as_mut_slice().to_vec();
        deque
            .as_mut_slice()
            .iter_mut()
            .for_each(|iov| iov.iov_len *= 2);

        assert_eq!(copy.len(), deque.len() as usize);
        for (i, iov) in deque.as_slice().iter().enumerate() {
            assert_eq!(iov.iov_len, 2 * copy[i].iov_len);
        }
    }

    #[test]
    fn test_size_less_than_capacity() {
        // Usually we have a queue size of 256 which is a perfect fit
        // for 4K pages. But with 16K or bigger pages the `perfect fit`
        // is not perfect anymore. Need to ensure the wraparound logic
        // remains valid in such cases.
        const L: u16 = 16;
        let mut deque = super::IovDeque::<L>::new().unwrap();
        assert!(deque.as_mut_slice().is_empty());

        // Number of times need to fill/empty the queue to reach the
        // wraparound point.
        let fills = deque.capacity / L;

        // Almost reach the wraparound.
        for _ in 0..(fills - 1) {
            for _ in 0..L {
                deque.push_back(make_iovec(0, 100));
            }
            deque.pop_front(L);
        }
        // 1 element away from the wraparound
        for _ in 0..(L - 1) {
            deque.push_back(make_iovec(0, 100));
        }
        deque.pop_front(L - 1);

        // Start filling the 'second' page
        // First element will be put at the end of the
        // first page, while the rest will be in `second`
        // page.
        for _ in 0..L {
            deque.push_back(make_iovec(1, 100));
        }

        // Pop one element to trigger the wraparound.
        deque.pop_front(1);
        // Now the slice should be pointing to the memory of the `first` page
        // which should have the same content as the `second` page.
        assert_eq!(deque.as_slice(), vec![make_iovec(1, 100); L as usize - 1]);
    }
}
