// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::ErrorKind;

use libc::{c_void, iovec, size_t};
use serde::{Deserialize, Serialize};
use vm_memory::bitmap::Bitmap;
use vm_memory::{
    GuestMemory, GuestMemoryError, ReadVolatile, VolatileMemoryError, VolatileSlice, WriteVolatile,
};

use super::iov_deque::{IovDeque, IovDequeError};
use super::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::devices::virtio::queue::DescriptorChain;
use crate::vstate::memory::GuestMemoryMmap;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum IoVecError {
    /// Tried to create an `IoVec` from a write-only descriptor chain
    WriteOnlyDescriptor,
    /// Tried to create an 'IoVecMut` from a read-only descriptor chain
    ReadOnlyDescriptor,
    /// Tried to create an `IoVec` or `IoVecMut` from a descriptor chain that was too large
    OverflowedDescriptor,
    /// Tried to push to full IovDeque.
    IovDequeOverflow,
    /// Guest memory error: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Error with underlying `IovDeque`: {0}
    IovDeque(#[from] IovDequeError),
}

/// This is essentially a wrapper of a `Vec<libc::iovec>` which can be passed to `libc::writev`.
///
/// It describes a buffer passed to us by the guest that is scattered across multiple
/// memory regions. Additionally, this wrapper provides methods that allow reading arbitrary ranges
/// of data from that buffer.
#[derive(Debug, Default)]
pub struct IoVecBuffer {
    // container of the memory regions included in this IO vector
    vecs: Vec<iovec>,
    // Total length of the IoVecBuffer
    len: u32,
}

// SAFETY: `IoVecBuffer` doesn't allow for interior mutability and no shared ownership is possible
// as it doesn't implement clone
unsafe impl Send for IoVecBuffer {}

impl IoVecBuffer {
    /// Create an `IoVecBuffer` from a `DescriptorChain`
    ///
    /// # Safety
    ///
    /// The descriptor chain cannot be referencing the same memory location as another chain
    pub unsafe fn load_descriptor_chain(
        &mut self,
        mem: &GuestMemoryMmap,
        head: DescriptorChain,
    ) -> Result<(), IoVecError> {
        self.clear();

        let mut next_descriptor = Some(head);
        while let Some(desc) = next_descriptor {
            if desc.is_write_only() {
                return Err(IoVecError::WriteOnlyDescriptor);
            }

            // We use get_slice instead of `get_host_address` here in order to have the whole
            // range of the descriptor chain checked, i.e. [addr, addr + len) is a valid memory
            // region in the GuestMemoryMmap.
            let iov_base = mem
                .get_slice(desc.addr, desc.len as usize)?
                .ptr_guard_mut()
                .as_ptr()
                .cast::<c_void>();
            self.vecs.push(iovec {
                iov_base,
                iov_len: desc.len as size_t,
            });
            self.len = self
                .len
                .checked_add(desc.len)
                .ok_or(IoVecError::OverflowedDescriptor)?;

            next_descriptor = desc.next_descriptor();
        }

        Ok(())
    }

    /// Create an `IoVecBuffer` from a `DescriptorChain`
    ///
    /// # Safety
    ///
    /// The descriptor chain cannot be referencing the same memory location as another chain
    pub unsafe fn from_descriptor_chain(
        mem: &GuestMemoryMmap,
        head: DescriptorChain,
    ) -> Result<Self, IoVecError> {
        let mut new_buffer = Self::default();
        // SAFETY: descriptor chain cannot be referencing the same memory location as another chain
        unsafe {
            new_buffer.load_descriptor_chain(mem, head)?;
        }
        Ok(new_buffer)
    }

    /// Get the total length of the memory regions covered by this `IoVecBuffer`
    pub(crate) fn len(&self) -> u32 {
        self.len
    }

    /// Returns a pointer to the memory keeping the `iovec` structs
    pub fn as_iovec_ptr(&self) -> *const iovec {
        self.vecs.as_ptr()
    }

    /// Returns the length of the `iovec` array.
    pub fn iovec_count(&self) -> usize {
        self.vecs.len()
    }

    /// Clears the `iovec` array
    pub fn clear(&mut self) {
        self.vecs.clear();
        self.len = 0u32;
    }

    /// Reads a number of bytes from the `IoVecBuffer` starting at a given offset.
    ///
    /// This will try to fill `buf` reading bytes from the `IoVecBuffer` starting from
    /// the given offset.
    ///
    /// # Returns
    ///
    /// `Ok(())` if `buf` was filled by reading from this [`IoVecBuffer`],
    /// `Err(VolatileMemoryError::PartialBuffer)` if only part of `buf` could not be filled, and
    /// `Err(VolatileMemoryError::OutOfBounds)` if `offset >= self.len()`.
    pub fn read_exact_volatile_at(
        &self,
        mut buf: &mut [u8],
        offset: usize,
    ) -> Result<(), VolatileMemoryError> {
        if offset < self.len() as usize {
            let expected = buf.len();
            let bytes_read = self.read_volatile_at(&mut buf, offset, expected)?;

            if bytes_read != expected {
                return Err(VolatileMemoryError::PartialBuffer {
                    expected,
                    completed: bytes_read,
                });
            }

            Ok(())
        } else {
            // If `offset` is past size, there's nothing to read.
            Err(VolatileMemoryError::OutOfBounds { addr: offset })
        }
    }

    /// Reads up to `len` bytes from the `IoVecBuffer` starting at the given offset.
    ///
    /// This will try to write to the given [`WriteVolatile`].
    pub fn read_volatile_at<W: WriteVolatile>(
        &self,
        dst: &mut W,
        mut offset: usize,
        mut len: usize,
    ) -> Result<usize, VolatileMemoryError> {
        let mut total_bytes_read = 0;

        for iov in &self.vecs {
            if len == 0 {
                break;
            }

            if offset >= iov.iov_len {
                offset -= iov.iov_len;
                continue;
            }

            let mut slice =
                // SAFETY: the constructor IoVecBufferMut::from_descriptor_chain ensures that
                // all iovecs contained point towards valid ranges of guest memory
                unsafe { VolatileSlice::new(iov.iov_base.cast(), iov.iov_len).offset(offset)? };
            offset = 0;

            if slice.len() > len {
                slice = slice.subslice(0, len)?;
            }

            let bytes_read = loop {
                match dst.write_volatile(&slice) {
                    Err(VolatileMemoryError::IOError(err))
                        if err.kind() == ErrorKind::Interrupted =>
                    {
                        continue;
                    }
                    Ok(bytes_read) => break bytes_read,
                    Err(volatile_memory_error) => return Err(volatile_memory_error),
                }
            };
            total_bytes_read += bytes_read;

            if bytes_read < slice.len() {
                break;
            }
            len -= bytes_read;
        }

        Ok(total_bytes_read)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedDescriptorChain {
    pub head_index: u16,
    pub length: u32,
    pub nr_iovecs: u16,
}

/// This is essentially a wrapper of a `Vec<libc::iovec>` which can be passed to `libc::readv`.
///
/// It describes a write-only buffer passed to us by the guest that is scattered across multiple
/// memory regions. Additionally, this wrapper provides methods that allow reading arbitrary ranges
/// of data from that buffer.
/// `L` const generic value must be a multiple of 256 as required by the `IovDeque` requirements.
#[derive(Debug)]
pub struct IoVecBufferMut<const L: u16 = FIRECRACKER_MAX_QUEUE_SIZE> {
    // container of the memory regions included in this IO vector
    pub vecs: IovDeque<L>,
    // Total length of the IoVecBufferMut
    // We use `u32` here because we use this type in devices which
    // should not give us huge buffers. In any case this
    // value will not overflow as we explicitly check for this case.
    pub len: u32,
}

// SAFETY: `IoVecBufferMut` doesn't allow for interior mutability and no shared ownership is
// possible as it doesn't implement clone
unsafe impl<const L: u16> Send for IoVecBufferMut<L> {}

impl<const L: u16> IoVecBufferMut<L> {
    /// Append a `DescriptorChain` in this `IoVecBufferMut`
    ///
    /// # Safety
    ///
    /// The descriptor chain cannot be referencing the same memory location as another chain
    pub unsafe fn append_descriptor_chain(
        &mut self,
        mem: &GuestMemoryMmap,
        head: DescriptorChain,
    ) -> Result<ParsedDescriptorChain, IoVecError> {
        let head_index = head.index;
        let mut next_descriptor = Some(head);
        let mut length = 0u32;
        let mut nr_iovecs = 0u16;
        while let Some(desc) = next_descriptor {
            if !desc.is_write_only() {
                self.vecs.pop_back(nr_iovecs);
                return Err(IoVecError::ReadOnlyDescriptor);
            }

            // We use get_slice instead of `get_host_address` here in order to have the whole
            // range of the descriptor chain checked, i.e. [addr, addr + len) is a valid memory
            // region in the GuestMemoryMmap.
            let slice = mem
                .get_slice(desc.addr, desc.len as usize)
                .inspect_err(|_| {
                    self.vecs.pop_back(nr_iovecs);
                })?;
            // We need to mark the area of guest memory that will be mutated through this
            // IoVecBufferMut as dirty ahead of time, as we loose access to all
            // vm-memory related information after converting down to iovecs.
            slice.bitmap().mark_dirty(0, desc.len as usize);
            let iov_base = slice.ptr_guard_mut().as_ptr().cast::<c_void>();

            if self.vecs.is_full() {
                self.vecs.pop_back(nr_iovecs);
                return Err(IoVecError::IovDequeOverflow);
            }

            self.vecs.push_back(iovec {
                iov_base,
                iov_len: desc.len as size_t,
            });

            nr_iovecs += 1;
            length = length
                .checked_add(desc.len)
                .ok_or(IoVecError::OverflowedDescriptor)
                .inspect_err(|_| {
                    self.vecs.pop_back(nr_iovecs);
                })?;

            next_descriptor = desc.next_descriptor();
        }

        self.len = self.len.checked_add(length).ok_or_else(|| {
            self.vecs.pop_back(nr_iovecs);
            IoVecError::OverflowedDescriptor
        })?;

        Ok(ParsedDescriptorChain {
            head_index,
            length,
            nr_iovecs,
        })
    }

    /// Create an empty `IoVecBufferMut`.
    pub fn new() -> Result<Self, IovDequeError> {
        let vecs = IovDeque::new()?;
        Ok(Self { vecs, len: 0 })
    }

    /// Create an `IoVecBufferMut` from a `DescriptorChain`
    ///
    /// This will clear any previous `iovec` objects in the buffer and load the new
    /// [`DescriptorChain`].
    ///
    /// # Safety
    ///
    /// The descriptor chain cannot be referencing the same memory location as another chain
    pub unsafe fn load_descriptor_chain(
        &mut self,
        mem: &GuestMemoryMmap,
        head: DescriptorChain,
    ) -> Result<(), IoVecError> {
        self.clear();
        // SAFETY: descriptor chain cannot be referencing the same memory location as another chain
        let _ = unsafe { self.append_descriptor_chain(mem, head)? };
        Ok(())
    }

    /// Drop descriptor chain from the `IoVecBufferMut` front
    ///
    /// This will drop memory described by the `IoVecBufferMut` from the beginning.
    pub fn drop_chain_front(&mut self, parse_descriptor: &ParsedDescriptorChain) {
        self.vecs.pop_front(parse_descriptor.nr_iovecs);
        self.len -= parse_descriptor.length;
    }

    /// Drop descriptor chain from the `IoVecBufferMut` back
    ///
    /// This will drop memory described by the `IoVecBufferMut` from the beginning.
    pub fn drop_chain_back(&mut self, parse_descriptor: &ParsedDescriptorChain) {
        self.vecs.pop_back(parse_descriptor.nr_iovecs);
        self.len -= parse_descriptor.length;
    }

    /// Create an `IoVecBuffer` from a `DescriptorChain`
    ///
    /// # Safety
    ///
    /// The descriptor chain cannot be referencing the same memory location as another chain
    pub unsafe fn from_descriptor_chain(
        mem: &GuestMemoryMmap,
        head: DescriptorChain,
    ) -> Result<Self, IoVecError> {
        let mut new_buffer = Self::new()?;
        // SAFETY: descriptor chain cannot be referencing the same memory location as another chain
        unsafe {
            new_buffer.load_descriptor_chain(mem, head)?;
        }
        Ok(new_buffer)
    }

    /// Get the total length of the memory regions covered by this `IoVecBuffer`
    #[inline(always)]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Returns true if buffer is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a pointer to the memory keeping the `iovec` structs
    pub fn as_iovec_mut_slice(&mut self) -> &mut [iovec] {
        self.vecs.as_mut_slice()
    }

    /// Clears the `iovec` array
    pub fn clear(&mut self) {
        self.vecs.clear();
        self.len = 0;
    }

    /// Writes a number of bytes into the `IoVecBufferMut` starting at a given offset.
    ///
    /// This will try to fill `IoVecBufferMut` writing bytes from the `buf` starting from
    /// the given offset. It will write as many bytes from `buf` as they fit inside the
    /// `IoVecBufferMut` starting from `offset`.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the entire contents of `buf` could be written to this [`IoVecBufferMut`],
    /// `Err(VolatileMemoryError::PartialBuffer)` if only part of `buf` could be transferred, and
    /// `Err(VolatileMemoryError::OutOfBounds)` if `offset >= self.len()`.
    pub fn write_all_volatile_at(
        &mut self,
        mut buf: &[u8],
        offset: usize,
    ) -> Result<(), VolatileMemoryError> {
        if offset < self.len() as usize {
            let expected = buf.len();
            let bytes_written = self.write_volatile_at(&mut buf, offset, expected)?;

            if bytes_written != expected {
                return Err(VolatileMemoryError::PartialBuffer {
                    expected,
                    completed: bytes_written,
                });
            }

            Ok(())
        } else {
            // We cannot write past the end of the `IoVecBufferMut`.
            Err(VolatileMemoryError::OutOfBounds { addr: offset })
        }
    }

    /// Writes up to `len` bytes into the `IoVecBuffer` starting at the given offset.
    ///
    /// This will try to write to the given [`WriteVolatile`].
    pub fn write_volatile_at<W: ReadVolatile>(
        &mut self,
        src: &mut W,
        mut offset: usize,
        mut len: usize,
    ) -> Result<usize, VolatileMemoryError> {
        let mut total_bytes_read = 0;

        for iov in self.vecs.as_slice() {
            if len == 0 {
                break;
            }

            if offset >= iov.iov_len {
                offset -= iov.iov_len;
                continue;
            }

            let mut slice =
                // SAFETY: the constructor IoVecBufferMut::from_descriptor_chain ensures that
                // all iovecs contained point towards valid ranges of guest memory
                unsafe { VolatileSlice::new(iov.iov_base.cast(), iov.iov_len).offset(offset)? };
            offset = 0;

            if slice.len() > len {
                slice = slice.subslice(0, len)?;
            }

            let bytes_read = loop {
                match src.read_volatile(&mut slice) {
                    Err(VolatileMemoryError::IOError(err))
                        if err.kind() == ErrorKind::Interrupted =>
                    {
                        continue;
                    }
                    Ok(bytes_read) => break bytes_read,
                    Err(volatile_memory_error) => return Err(volatile_memory_error),
                }
            };
            total_bytes_read += bytes_read;

            if bytes_read < slice.len() {
                break;
            }
            len -= bytes_read;
        }

        Ok(total_bytes_read)
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use libc::{c_void, iovec};
    use vm_memory::VolatileMemoryError;

    use super::IoVecBuffer;
    // Redefine `IoVecBufferMut` with specific length. Otherwise
    // Rust will not know what to do.
    type IoVecBufferMutDefault = super::IoVecBufferMut<FIRECRACKER_MAX_QUEUE_SIZE>;

    use crate::devices::virtio::iov_deque::IovDeque;
    use crate::devices::virtio::queue::{
        FIRECRACKER_MAX_QUEUE_SIZE, Queue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    };
    use crate::devices::virtio::test_utils::VirtQueue;
    use crate::test_utils::multi_region_mem;
    use crate::vstate::memory::{Bytes, GuestAddress, GuestMemoryMmap};

    impl<'a> From<&'a [u8]> for IoVecBuffer {
        fn from(buf: &'a [u8]) -> Self {
            Self {
                vecs: vec![iovec {
                    iov_base: buf.as_ptr() as *mut c_void,
                    iov_len: buf.len(),
                }],
                len: buf.len().try_into().unwrap(),
            }
        }
    }

    impl<'a> From<Vec<&'a [u8]>> for IoVecBuffer {
        fn from(buffer: Vec<&'a [u8]>) -> Self {
            let mut len = 0_u32;
            let vecs = buffer
                .into_iter()
                .map(|slice| {
                    len += TryInto::<u32>::try_into(slice.len()).unwrap();
                    iovec {
                        iov_base: slice.as_ptr() as *mut c_void,
                        iov_len: slice.len(),
                    }
                })
                .collect();

            Self { vecs, len }
        }
    }

    impl<const L: u16> From<&mut [u8]> for super::IoVecBufferMut<L> {
        fn from(buf: &mut [u8]) -> Self {
            let mut vecs = IovDeque::new().unwrap();
            vecs.push_back(iovec {
                iov_base: buf.as_mut_ptr().cast::<c_void>(),
                iov_len: buf.len(),
            });

            Self {
                vecs,
                len: buf.len() as u32,
            }
        }
    }

    impl<const L: u16> From<Vec<&mut [u8]>> for super::IoVecBufferMut<L> {
        fn from(buffer: Vec<&mut [u8]>) -> Self {
            let mut len = 0;
            let mut vecs = IovDeque::new().unwrap();
            for slice in buffer {
                len += slice.len() as u32;

                vecs.push_back(iovec {
                    iov_base: slice.as_ptr() as *mut c_void,
                    iov_len: slice.len(),
                });
            }

            Self { vecs, len }
        }
    }

    fn default_mem() -> GuestMemoryMmap {
        multi_region_mem(&[
            (GuestAddress(0), 0x10000),
            (GuestAddress(0x20000), 0x10000),
            (GuestAddress(0x40000), 0x10000),
        ])
    }

    fn chain(m: &GuestMemoryMmap, is_write_only: bool) -> (Queue, VirtQueue) {
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        let mut q = vq.create_queue();
        q.ready = true;

        let flags = if is_write_only {
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
        } else {
            VIRTQ_DESC_F_NEXT
        };

        for j in 0..4 {
            vq.dtable[j as usize].set(0x20000 + 64 * u64::from(j), 64, flags, j + 1);
        }

        // one chain: (0, 1, 2, 3)
        vq.dtable[3].flags.set(flags & !VIRTQ_DESC_F_NEXT);
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);

        (q, vq)
    }

    fn read_only_chain(mem: &GuestMemoryMmap) -> (Queue, VirtQueue) {
        let v: Vec<u8> = (0..=255).collect();
        mem.write_slice(&v, GuestAddress(0x20000)).unwrap();

        chain(mem, false)
    }

    fn write_only_chain(mem: &GuestMemoryMmap) -> (Queue, VirtQueue) {
        let v = vec![0; 256];
        mem.write_slice(&v, GuestAddress(0x20000)).unwrap();

        chain(mem, true)
    }

    #[test]
    fn test_access_mode() {
        let mem = default_mem();
        let (mut q, _) = read_only_chain(&mem);
        let head = q.pop().unwrap();
        // SAFETY: This descriptor chain is only loaded into one buffer
        unsafe { IoVecBuffer::from_descriptor_chain(&mem, head).unwrap() };

        let (mut q, _) = write_only_chain(&mem);
        let head = q.pop().unwrap();
        // SAFETY: This descriptor chain is only loaded into one buffer
        unsafe { IoVecBuffer::from_descriptor_chain(&mem, head).unwrap_err() };

        let (mut q, _) = read_only_chain(&mem);
        let head = q.pop().unwrap();
        // SAFETY: This descriptor chain is only loaded into one buffer
        unsafe { IoVecBufferMutDefault::from_descriptor_chain(&mem, head).unwrap_err() };

        let (mut q, _) = write_only_chain(&mem);
        let head = q.pop().unwrap();
        // SAFETY: This descriptor chain is only loaded into one buffer
        unsafe { IoVecBufferMutDefault::from_descriptor_chain(&mem, head).unwrap() };
    }

    #[test]
    fn test_iovec_length() {
        let mem = default_mem();
        let (mut q, _) = read_only_chain(&mem);
        let head = q.pop().unwrap();

        // SAFETY: This descriptor chain is only loaded once in this test
        let iovec = unsafe { IoVecBuffer::from_descriptor_chain(&mem, head).unwrap() };
        assert_eq!(iovec.len(), 4 * 64);
    }

    #[test]
    fn test_iovec_mut_length() {
        let mem = default_mem();
        let (mut q, _) = write_only_chain(&mem);
        let head = q.pop().unwrap();

        // SAFETY: This descriptor chain is only loaded once in this test
        let mut iovec =
            unsafe { IoVecBufferMutDefault::from_descriptor_chain(&mem, head).unwrap() };
        assert_eq!(iovec.len(), 4 * 64);

        // We are creating a new queue where we can get descriptors from. Probably, this is not
        // something that we will ever want to do, as `IoVecBufferMut`s are typically
        // (concpetually) associated with a single `Queue`. We just do this here to be able to test
        // the appending logic.
        let (mut q, _) = write_only_chain(&mem);
        let head = q.pop().unwrap();
        // SAFETY: it is actually unsafe, but we just want to check the length of the
        // `IoVecBufferMut` after appending.
        let _ = unsafe { iovec.append_descriptor_chain(&mem, head).unwrap() };
        assert_eq!(iovec.len(), 8 * 64);
    }

    #[test]
    fn test_iovec_read_at() {
        let mem = default_mem();
        let (mut q, _) = read_only_chain(&mem);
        let head = q.pop().unwrap();

        // SAFETY: This descriptor chain is only loaded once in this test
        let iovec = unsafe { IoVecBuffer::from_descriptor_chain(&mem, head).unwrap() };

        let mut buf = vec![0u8; 257];
        assert_eq!(
            iovec
                .read_volatile_at(&mut buf.as_mut_slice(), 0, 257)
                .unwrap(),
            256
        );
        assert_eq!(buf[0..256], (0..=255).collect::<Vec<_>>());
        assert_eq!(buf[256], 0);

        let mut buf = vec![0; 5];
        iovec.read_exact_volatile_at(&mut buf[..4], 0).unwrap();
        assert_eq!(buf, vec![0u8, 1, 2, 3, 0]);

        iovec.read_exact_volatile_at(&mut buf, 0).unwrap();
        assert_eq!(buf, vec![0u8, 1, 2, 3, 4]);

        iovec.read_exact_volatile_at(&mut buf, 1).unwrap();
        assert_eq!(buf, vec![1u8, 2, 3, 4, 5]);

        iovec.read_exact_volatile_at(&mut buf, 60).unwrap();
        assert_eq!(buf, vec![60u8, 61, 62, 63, 64]);

        assert_eq!(
            iovec
                .read_volatile_at(&mut buf.as_mut_slice(), 252, 5)
                .unwrap(),
            4
        );
        assert_eq!(buf[0..4], vec![252u8, 253, 254, 255]);

        assert!(matches!(
            iovec.read_exact_volatile_at(&mut buf, 252),
            Err(VolatileMemoryError::PartialBuffer {
                expected: 5,
                completed: 4
            })
        ));
        assert!(matches!(
            iovec.read_exact_volatile_at(&mut buf, 256),
            Err(VolatileMemoryError::OutOfBounds { addr: 256 })
        ));
    }

    #[test]
    fn test_iovec_mut_write_at() {
        let mem = default_mem();
        let (mut q, vq) = write_only_chain(&mem);

        // This is a descriptor chain with 4 elements 64 bytes long each.
        let head = q.pop().unwrap();

        // SAFETY: This descriptor chain is only loaded into one buffer
        let mut iovec =
            unsafe { IoVecBufferMutDefault::from_descriptor_chain(&mem, head).unwrap() };
        let buf = vec![0u8, 1, 2, 3, 4];

        // One test vector for each part of the chain
        let mut test_vec1 = vec![0u8; 64];
        let mut test_vec2 = vec![0u8; 64];
        let test_vec3 = vec![0u8; 64];
        let mut test_vec4 = vec![0u8; 64];

        // Control test: Initially all three regions should be zero
        iovec.write_all_volatile_at(&test_vec1, 0).unwrap();
        iovec.write_all_volatile_at(&test_vec2, 64).unwrap();
        iovec.write_all_volatile_at(&test_vec3, 128).unwrap();
        iovec.write_all_volatile_at(&test_vec4, 192).unwrap();
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);

        // Let's initialize test_vec1 with our buffer.
        test_vec1[..buf.len()].copy_from_slice(&buf);
        // And write just a part of it
        iovec.write_all_volatile_at(&buf[..3], 0).unwrap();
        // Not all 5 bytes from buf should be written in memory,
        // just 3 of them.
        vq.dtable[0].check_data(&[0u8, 1, 2, 0, 0]);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);
        // But if we write the whole `buf` in memory then all
        // of it should be observable.
        iovec.write_all_volatile_at(&buf, 0).unwrap();
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);

        // We are now writing with an offset of 1. So, initialize
        // the corresponding part of `test_vec1`
        test_vec1[1..buf.len() + 1].copy_from_slice(&buf);
        iovec.write_all_volatile_at(&buf, 1).unwrap();
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);

        // Perform a write that traverses two of the underlying
        // regions. Writing at offset 60 should write 4 bytes on the
        // first region and one byte on the second
        test_vec1[60..64].copy_from_slice(&buf[0..4]);
        test_vec2[0] = 4;
        iovec.write_all_volatile_at(&buf, 60).unwrap();
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);

        test_vec4[63] = 3;
        test_vec4[62] = 2;
        test_vec4[61] = 1;
        // Now perform a write that does not fit in the buffer. Try writing
        // 5 bytes at offset 252 (only 4 bytes left).
        test_vec4[60..64].copy_from_slice(&buf[0..4]);
        assert_eq!(
            iovec.write_volatile_at(&mut &*buf, 252, buf.len()).unwrap(),
            4
        );
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);

        // Trying to add past the end of the buffer should not write anything
        assert!(matches!(
            iovec.write_all_volatile_at(&buf, 256),
            Err(VolatileMemoryError::OutOfBounds { addr: 256 })
        ));
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);
    }
}

#[cfg(kani)]
#[allow(dead_code)] // Avoid warning when using stubs
mod verification {
    use std::mem::ManuallyDrop;

    use libc::{c_void, iovec};
    use vm_memory::VolatileSlice;
    use vm_memory::bitmap::BitmapSlice;

    use super::IoVecBuffer;
    use crate::arch::GUEST_PAGE_SIZE;
    use crate::devices::virtio::iov_deque::IovDeque;
    // Redefine `IoVecBufferMut` and `IovDeque` with specific length. Otherwise
    // Rust will not know what to do.
    type IoVecBufferMutDefault = super::IoVecBufferMut<FIRECRACKER_MAX_QUEUE_SIZE>;
    type IovDequeDefault = IovDeque<FIRECRACKER_MAX_QUEUE_SIZE>;

    use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;

    // Maximum memory size to use for our buffers. For the time being 1KB.
    const GUEST_MEMORY_SIZE: usize = 1 << 10;

    // Maximum number of descriptors in a chain to use in our proofs. The value is selected upon
    // experimenting with the execution time. Typically, in our virtio devices we use queues of up
    // to 256 entries which is the theoretical maximum length of a `DescriptorChain`, but in reality
    // our code does not make any assumption about the length of the chain, apart from it being
    // >= 1.
    const MAX_DESC_LENGTH: usize = 4;

    mod stubs {
        use super::*;

        /// This is a stub for the `IovDeque::push_back` method.
        ///
        /// `IovDeque` relies on a special allocation of two pages of virtual memory, where both of
        /// these point to the same underlying physical page. This way, the contents of the first
        /// page of virtual memory are automatically mirrored in the second virtual page. We do
        /// that in order to always have the elements that are currently in the ring buffer in
        /// consecutive (virtual) memory.
        ///
        /// To build this particular memory layout we create a new `memfd` object, allocate memory
        /// with `mmap` and call `mmap` again to make sure both pages point to the page allocated
        /// via the `memfd` object. These ffi calls make kani complain, so here we mock the
        /// `IovDeque` object memory with a normal memory allocation of two pages worth of data.
        ///
        /// This stub helps imitate the effect of mirroring without all the elaborate memory
        /// allocation trick.
        pub fn push_back<const L: u16>(deque: &mut IovDeque<L>, iov: iovec) {
            // This should NEVER happen, since our ring buffer is as big as the maximum queue size.
            // We also check for the sanity of the VirtIO queues, in queue.rs, which means that if
            // we ever try to add something in a full ring buffer, there is an internal
            // bug in the device emulation logic. Panic here because the device is
            // hopelessly broken.
            assert!(
                !deque.is_full(),
                "The number of `iovec` objects is bigger than the available space"
            );

            let offset = (deque.start + deque.len) as usize;
            let mirror = if offset >= L as usize {
                offset - L as usize
            } else {
                offset + L as usize
            };

            // SAFETY: self.iov is a valid pointer and `self.start + self.len` is within range (we
            // asserted before that the buffer is not full).
            unsafe { deque.iov.add(offset).write_volatile(iov) };
            unsafe { deque.iov.add(mirror).write_volatile(iov) };
            deque.len += 1;
        }
    }

    fn create_iovecs(mem: *mut u8, size: usize, nr_descs: usize) -> (Vec<iovec>, u32) {
        let mut vecs: Vec<iovec> = Vec::with_capacity(nr_descs);
        let mut len = 0u32;
        for _ in 0..nr_descs {
            // The `IoVecBuffer` constructors ensure that the memory region described by every
            // `Descriptor` in the chain is a valid, i.e. it is memory with then guest's memory
            // mmap. The assumption, here, that the last address is within the memory object's
            // bound substitutes these checks that `IoVecBuffer::new() performs.`
            let addr: usize = kani::any();
            let iov_len: usize =
                kani::any_where(|&len| matches!(addr.checked_add(len), Some(x) if x <= size));
            let iov_base = unsafe { mem.offset(addr.try_into().unwrap()) } as *mut c_void;

            vecs.push(iovec { iov_base, iov_len });
            len += u32::try_from(iov_len).unwrap();
        }

        (vecs, len)
    }

    impl IoVecBuffer {
        fn any_of_length(nr_descs: usize) -> Self {
            // We only read from `IoVecBuffer`, so create here a guest memory object, with arbitrary
            // contents and size up to GUEST_MEMORY_SIZE.
            let mut mem = ManuallyDrop::new(kani::vec::exact_vec::<u8, GUEST_MEMORY_SIZE>());
            let (vecs, len) = create_iovecs(mem.as_mut_ptr(), mem.len(), nr_descs);
            Self { vecs, len }
        }
    }

    fn create_iov_deque() -> IovDequeDefault {
        // SAFETY: safe because the layout has non-zero size
        let mem = unsafe {
            std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                2 * GUEST_PAGE_SIZE,
                GUEST_PAGE_SIZE,
            ))
        };
        IovDequeDefault {
            iov: mem.cast(),
            start: kani::any_where(|&start| start < FIRECRACKER_MAX_QUEUE_SIZE),
            len: 0,
            capacity: FIRECRACKER_MAX_QUEUE_SIZE,
        }
    }

    fn create_iovecs_mut(mem: *mut u8, size: usize, nr_descs: usize) -> (IovDequeDefault, u32) {
        let mut vecs = create_iov_deque();
        let mut len = 0u32;
        for _ in 0..nr_descs {
            // The `IoVecBufferMut` constructors ensure that the memory region described by every
            // `Descriptor` in the chain is a valid, i.e. it is memory with then guest's memory
            // mmap. The assumption, here, that the last address is within the memory object's
            // bound substitutes these checks that `IoVecBufferMut::new() performs.`
            let addr: usize = kani::any();
            let iov_len: usize =
                kani::any_where(|&len| matches!(addr.checked_add(len), Some(x) if x <= size));
            let iov_base = unsafe { mem.offset(addr.try_into().unwrap()) } as *mut c_void;

            vecs.push_back(iovec { iov_base, iov_len });
            len += u32::try_from(iov_len).unwrap();
        }

        (vecs, len)
    }

    impl IoVecBufferMutDefault {
        fn any_of_length(nr_descs: usize) -> Self {
            // We only write into `IoVecBufferMut` objects, so we can simply create a guest memory
            // object initialized to zeroes, trying to be nice to Kani.
            let mem = unsafe {
                std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align_unchecked(
                    GUEST_MEMORY_SIZE,
                    16,
                ))
            };

            let (vecs, len) = create_iovecs_mut(mem, GUEST_MEMORY_SIZE, nr_descs);
            Self {
                vecs,
                len: len.try_into().unwrap(),
            }
        }
    }

    // A mock for the Read-/WriteVolatile implementation for u8 slices that does
    // not go through rust-vmm's machinery (which would cause kani get stuck during post processing)
    struct KaniBuffer<'a>(&'a mut [u8]);

    impl vm_memory::ReadVolatile for KaniBuffer<'_> {
        fn read_volatile<B: BitmapSlice>(
            &mut self,
            buf: &mut VolatileSlice<B>,
        ) -> Result<usize, vm_memory::VolatileMemoryError> {
            let count = buf.len().min(self.0.len());
            unsafe {
                std::ptr::copy_nonoverlapping(self.0.as_ptr(), buf.ptr_guard_mut().as_ptr(), count);
            }
            self.0 = std::mem::take(&mut self.0).split_at_mut(count).1;
            Ok(count)
        }
    }

    impl vm_memory::WriteVolatile for KaniBuffer<'_> {
        fn write_volatile<B: BitmapSlice>(
            &mut self,
            buf: &VolatileSlice<B>,
        ) -> Result<usize, vm_memory::VolatileMemoryError> {
            let count = buf.len().min(self.0.len());
            unsafe {
                std::ptr::copy_nonoverlapping(
                    buf.ptr_guard_mut().as_ptr(),
                    self.0.as_mut_ptr(),
                    count,
                );
            }
            self.0 = std::mem::take(&mut self.0).split_at_mut(count).1;
            Ok(count)
        }
    }

    #[kani::proof]
    #[kani::unwind(5)]
    #[kani::solver(cadical)]
    fn verify_read_from_iovec() {
        for nr_descs in 0..MAX_DESC_LENGTH {
            let iov = IoVecBuffer::any_of_length(nr_descs);

            let mut buf = vec![0; GUEST_MEMORY_SIZE];
            let offset: u32 = kani::any();

            // We can't really check the contents that the operation here writes into `buf`, because
            // our `IoVecBuffer` being completely arbitrary can contain overlapping memory regions,
            // so checking the data copied is not exactly trivial.
            //
            // What we can verify is the bytes that we read out from guest memory:
            //    - `buf.len()`, if `offset + buf.len() < iov.len()`;
            //    - `iov.len() - offset`, otherwise.
            // Furthermore, we know our Read-/WriteVolatile implementation above is infallible, so
            // provided that the logic inside read_volatile_at is correct, we should always get
            // Ok(...)
            assert_eq!(
                iov.read_volatile_at(
                    &mut KaniBuffer(&mut buf),
                    offset as usize,
                    GUEST_MEMORY_SIZE
                )
                .unwrap(),
                buf.len().min(iov.len().saturating_sub(offset) as usize)
            );
        }
    }

    #[kani::proof]
    #[kani::unwind(5)]
    #[kani::solver(cadical)]
    #[kani::stub(IovDeque::push_back, stubs::push_back)]
    fn verify_write_to_iovec() {
        for nr_descs in 0..MAX_DESC_LENGTH {
            let mut iov_mut = IoVecBufferMutDefault::any_of_length(nr_descs);

            let mut buf = kani::vec::any_vec::<u8, GUEST_MEMORY_SIZE>();
            let offset: u32 = kani::any();

            // We can't really check the contents that the operation here writes into
            // `IoVecBufferMut`, because our `IoVecBufferMut` being completely arbitrary
            // can contain overlapping memory regions, so checking the data copied is
            // not exactly trivial.
            //
            // What we can verify is the bytes that we write into guest memory:
            //    - `buf.len()`, if `offset + buf.len() < iov.len()`;
            //    - `iov.len() - offset`, otherwise.
            // Furthermore, we know our Read-/WriteVolatile implementation above is infallible, so
            // provided that the logic inside write_volatile_at is correct, we should always get
            // Ok(...)
            assert_eq!(
                iov_mut
                    .write_volatile_at(
                        &mut KaniBuffer(&mut buf),
                        offset as usize,
                        GUEST_MEMORY_SIZE
                    )
                    .unwrap(),
                buf.len().min(iov_mut.len().saturating_sub(offset) as usize)
            );
            std::mem::forget(iov_mut.vecs);
        }
    }
}
