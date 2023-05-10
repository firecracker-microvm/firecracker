// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use libc::{c_void, iovec, size_t};
use utils::vm_memory::{Bitmap, GuestMemory, GuestMemoryMmap};

use crate::virtio::DescriptorChain;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// We found a write-only descriptor where read-only was expected
    #[error("Tried to create an `IoVec` from a write-only descriptor chain")]
    WriteOnlyDescriptor,
    /// We found a read-only descriptor where write-only was expected
    #[error("Tried to create an 'IoVecMut` from a read-only descriptor chain")]
    ReadOnlyDescriptor,
    /// An error happened with guest memory handling
    #[error("Guest memory error: {0}")]
    GuestMemory(#[from] utils::vm_memory::GuestMemoryError),
}

type Result<T> = std::result::Result<T, Error>;

// Describes a sub-region of a buffer described as a slice of `iovec` structs.
struct IovVecSubregion<'a> {
    // An iterator of the iovec items we are iterating
    iovecs: Vec<iovec>,
    // Lifetime of the origin buffer
    phantom: PhantomData<&'a iovec>,
}

impl<'a> IovVecSubregion<'a> {
    // Create a new `IovVecSubregion`
    //
    // Given an initial buffer (described as a collecetion of `iovec` structs) and a sub-region
    // inside it, in the form of [offset; size] create a "sub-region" inside it, if the sub-region
    // does not fall outside the original buffer, i.e. `offset` is not after the end of the original
    // buffer.
    //
    // # Arguments
    //
    // * `iovecs` - A slice of `iovec` structures describing the buffer.
    // * `len`    - The total length of the buffer, i.e. the sum of the lengths of all `iovec`
    //   structs.
    // * `offset` - The offset inside the buffer at which the sub-region starts.
    // * `size`   - The size of the sub-region
    //
    // # Returns
    //
    // If the sub-region is within the range of the buffer, i.e. the offset is not past the end of
    // the buffer, it will return an `IovVecSubregion`.
    fn new(iovecs: &'a [iovec], len: usize, mut offset: usize, mut size: usize) -> Option<Self> {
        // Out-of-bounds sub-region
        if offset >= len {
            return None;
        }

        // Empty sub-region
        if size == 0 {
            return None;
        }

        let sub_regions = iovecs
            .iter()
            .filter_map(|iov| {
                // If offset is bigger than the length of the current `iovec`, this `iovec` is not
                // part of the sub-range
                if offset >= iov.iov_len {
                    offset -= iov.iov_len;
                    return None;
                }

                // No more `iovec` structs needed
                if size == 0 {
                    return None;
                }

                // SAFETY: This is safe because we chacked that `offset < iov.iov_len`.
                let iov_base = unsafe { iov.iov_base.add(offset) };
                let iov_len = std::cmp::min(iov.iov_len - offset, size);
                offset = 0;
                size -= iov_len;

                Some(iovec { iov_base, iov_len })
            })
            .collect();

        Some(Self {
            iovecs: sub_regions,
            phantom: PhantomData,
        })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.iovecs.iter().fold(0, |acc, iov| acc + iov.iov_len)
    }
}

impl<'a> IntoIterator for IovVecSubregion<'a> {
    type Item = iovec;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.iovecs.into_iter()
    }
}

/// This is essentially a wrapper of a `Vec<libc::iovec>` which can be passed to `libc::writev`.
///
/// It describes a buffer passed to us by the guest that is scattered across multiple
/// memory regions. Additionally, this wrapper provides methods that allow reading arbitrary ranges
/// of data from that buffer.
#[derive(Debug)]
pub(crate) struct IoVecBuffer {
    // container of the memory regions included in this IO vector
    vecs: Vec<iovec>,
    // Total length of the IoVecBuffer
    len: usize,
}

impl IoVecBuffer {
    /// Create an `IoVecBuffer` from a `DescriptorChain`
    pub fn from_descriptor_chain(mem: &GuestMemoryMmap, head: DescriptorChain) -> Result<Self> {
        let mut vecs = vec![];
        let mut len = 0usize;

        let mut next_descriptor = Some(head);
        while let Some(desc) = next_descriptor {
            if desc.is_write_only() {
                return Err(Error::WriteOnlyDescriptor);
            }

            // We use get_slice instead of `get_host_address` here in order to have the whole
            // range of the descriptor chain checked, i.e. [addr, addr + len) is a valid memory
            // region in the GuestMemoryMmap.
            let iov_base = mem
                .get_slice(desc.addr, desc.len as usize)?
                .as_ptr()
                .cast::<c_void>();
            vecs.push(iovec {
                iov_base,
                iov_len: desc.len as size_t,
            });
            len += desc.len as usize;

            next_descriptor = desc.next_descriptor();
        }

        Ok(Self { vecs, len })
    }

    /// Get the total length of the memory regions covered by this `IoVecBuffer`
    pub fn len(&self) -> usize {
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

    /// Get a sub-region of the buffer
    fn sub_region(&self, offset: usize, size: usize) -> Option<IovVecSubregion> {
        IovVecSubregion::new(&self.vecs, self.len, offset, size)
    }

    /// Reads a number of bytes from the `IoVecBuffer` starting at a given offset.
    ///
    /// This will try to fill `buf` reading bytes from the `IoVecBuffer` starting from
    /// the given offset.
    ///
    /// # Returns
    ///
    /// The number of bytes read (if any)
    pub fn read_at(&self, buf: &mut [u8], offset: usize) -> Option<usize> {
        self.sub_region(offset, buf.len()).map(|sub_region| {
            let mut bytes = 0;
            let mut buf_ptr = buf.as_mut_ptr();

            sub_region.into_iter().for_each(|iov| {
                let src = iov.iov_base.cast::<u8>();
                // SAFETY:
                // The call to `copy_nonoverlapping` is safe because:
                // 1. `iov` is a an iovec describing a segment inside `Self`. `IoVecSubregion` has
                //    performed all necessary bound checks.
                // 2. `buf_ptr` is a pointer inside the memory of `buf`
                // 3. Both pointers point to `u8` elements, so they're always aligned.
                // 4. The memory regions these pointers point to are not overlapping. `src` points
                //    to guest physical memory and `buf_ptr` to Firecracker-owned memory.
                //
                // `buf_ptr.add()` is safe because `IoVecSubregion` gives us `iovec` structs that
                // their size adds up to `buf.len()`.
                unsafe {
                    std::ptr::copy_nonoverlapping(src, buf_ptr, iov.iov_len);
                    buf_ptr = buf_ptr.add(iov.iov_len);
                }
                bytes += iov.iov_len;
            });

            bytes
        })
    }
}

/// This is essentially a wrapper of a `Vec<libc::iovec>` which can be passed to `libc::readv`.
///
/// It describes a write-only buffer passed to us by the guest that is scattered across multiple
/// memory regions. Additionally, this wrapper provides methods that allow reading arbitrary ranges
/// of data from that buffer.
#[derive(Debug)]
pub(crate) struct IoVecBufferMut {
    // container of the memory regions included in this IO vector
    vecs: Vec<iovec>,
    // Total length of the IoVecBufferMut
    len: usize,
}

impl IoVecBufferMut {
    /// Create an `IoVecBufferMut` from a `DescriptorChain`
    pub fn from_descriptor_chain(mem: &GuestMemoryMmap, head: DescriptorChain) -> Result<Self> {
        let mut vecs = vec![];
        let mut len = 0usize;

        for desc in head {
            if !desc.is_write_only() {
                return Err(Error::ReadOnlyDescriptor);
            }

            // We use get_slice instead of `get_host_address` here in order to have the whole
            // range of the descriptor chain checked, i.e. [addr, addr + len) is a valid memory
            // region in the GuestMemoryMmap.
            let slice = mem.get_slice(desc.addr, desc.len as usize)?;

            // We need to mark the area of guest memory that will be mutated through this
            // IoVecBufferMut as dirty ahead of time, as we loose access to all
            // vm-memory related information after converting down to iovecs.
            slice.bitmap().mark_dirty(0, desc.len as usize);

            let iov_base = slice.as_ptr().cast::<c_void>();
            vecs.push(iovec {
                iov_base,
                iov_len: desc.len as size_t,
            });
            len += desc.len as usize;
        }

        Ok(Self { vecs, len })
    }

    /// Get the total length of the memory regions covered by this `IoVecBuffer`
    pub fn len(&self) -> usize {
        self.len
    }

    /// Get a sub-region of the buffer
    fn sub_region(&self, offset: usize, size: usize) -> Option<IovVecSubregion> {
        IovVecSubregion::new(&self.vecs, self.len, offset, size)
    }

    /// Writes a number of bytes into the `IoVecBufferMut` starting at a given offset.
    ///
    /// This will try to fill `IoVecBufferMut` writing bytes from the `buf` starting from
    /// the given offset. It will write as many bytes from `buf` as they fit inside the
    /// `IoVecBufferMut` starting from `offset`.
    ///
    /// # Returns
    ///
    /// The number of bytes written (if any)
    pub fn write_at(&mut self, buf: &[u8], offset: usize) -> Option<usize> {
        self.sub_region(offset, buf.len()).map(|sub_region| {
            let mut bytes = 0;
            let mut buf_ptr = buf.as_ptr();

            sub_region.into_iter().for_each(|iov| {
                let dst = iov.iov_base.cast::<u8>();
                // SAFETY:
                // The call to `copy_nonoverlapping` is safe because:
                // 1. `iov` is a an iovec describing a segment inside `Self`. `IoVecSubregion` has
                //    performed all necessary bound checks.
                // 2. `buf_ptr` is a pointer inside the memory of `buf`
                // 3. Both pointers point to `u8` elements, so they're always aligned.
                // 4. The memory regions these pointers point to are not overlapping. `src` points
                //    to guest physical memory and `buf_ptr` to Firecracker-owned memory.
                //
                // `buf_ptr.add()` is safe because `IoVecSubregion` gives us `iovec` structs that
                // their size adds up to `buf.len()`.
                unsafe {
                    std::ptr::copy_nonoverlapping(buf_ptr, dst, iov.iov_len);
                    buf_ptr = buf_ptr.add(iov.iov_len);
                }
                bytes += iov.iov_len;
            });

            bytes
        })
    }
}

#[cfg(test)]
mod tests {
    use libc::{c_void, iovec};
    use utils::vm_memory::test_utils::create_anon_guest_memory;
    use utils::vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::{IoVecBuffer, IoVecBufferMut};
    use crate::virtio::queue::{Queue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::virtio::test_utils::VirtQueue;

    impl<'a> From<&'a [u8]> for IoVecBuffer {
        fn from(buf: &'a [u8]) -> Self {
            Self {
                vecs: vec![iovec {
                    iov_base: buf.as_ptr() as *mut c_void,
                    iov_len: buf.len(),
                }],
                len: buf.len(),
            }
        }
    }

    impl<'a> From<Vec<&'a [u8]>> for IoVecBuffer {
        fn from(buffer: Vec<&'a [u8]>) -> Self {
            let mut len = 0;
            let vecs = buffer
                .into_iter()
                .map(|slice| {
                    len += slice.len();
                    iovec {
                        iov_base: slice.as_ptr() as *mut c_void,
                        iov_len: slice.len(),
                    }
                })
                .collect();

            Self { vecs, len }
        }
    }

    impl From<&mut [u8]> for IoVecBufferMut {
        fn from(buf: &mut [u8]) -> Self {
            Self {
                vecs: vec![iovec {
                    iov_base: buf.as_mut_ptr().cast::<c_void>(),
                    iov_len: buf.len(),
                }],
                len: buf.len(),
            }
        }
    }

    fn default_mem() -> GuestMemoryMmap {
        create_anon_guest_memory(
            &[
                (GuestAddress(0), 0x10000),
                (GuestAddress(0x20000), 0x10000),
                (GuestAddress(0x40000), 0x10000),
            ],
            false,
        )
        .unwrap()
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
            vq.dtable[j].set(0x20000 + 64 * j as u64, 64, flags, (j + 1) as u16);
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
        let head = q.pop(&mem).unwrap();
        assert!(IoVecBuffer::from_descriptor_chain(&mem, head).is_ok());

        let (mut q, _) = write_only_chain(&mem);
        let head = q.pop(&mem).unwrap();
        assert!(IoVecBuffer::from_descriptor_chain(&mem, head).is_err());

        let (mut q, _) = read_only_chain(&mem);
        let head = q.pop(&mem).unwrap();
        assert!(IoVecBufferMut::from_descriptor_chain(&mem, head).is_err());

        let (mut q, _) = write_only_chain(&mem);
        let head = q.pop(&mem).unwrap();
        assert!(IoVecBufferMut::from_descriptor_chain(&mem, head).is_ok());
    }

    #[test]
    fn test_iovec_length() {
        let mem = default_mem();
        let (mut q, _) = read_only_chain(&mem);
        let head = q.pop(&mem).unwrap();

        let iovec = IoVecBuffer::from_descriptor_chain(&mem, head).unwrap();
        assert_eq!(iovec.len(), 4 * 64);
    }

    #[test]
    fn test_iovec_mut_length() {
        let mem = default_mem();
        let (mut q, _) = write_only_chain(&mem);
        let head = q.pop(&mem).unwrap();

        let iovec = IoVecBufferMut::from_descriptor_chain(&mem, head).unwrap();
        assert_eq!(iovec.len(), 4 * 64);
    }

    #[test]
    fn test_iovec_read_at() {
        let mem = default_mem();
        let (mut q, _) = read_only_chain(&mem);
        let head = q.pop(&mem).unwrap();

        let iovec = IoVecBuffer::from_descriptor_chain(&mem, head).unwrap();

        let mut buf = vec![0; 5];
        assert_eq!(iovec.read_at(&mut buf[..4], 0), Some(4));
        assert_eq!(buf, vec![0u8, 1, 2, 3, 0]);

        assert_eq!(iovec.read_at(&mut buf, 0), Some(5));
        assert_eq!(buf, vec![0u8, 1, 2, 3, 4]);

        assert_eq!(iovec.read_at(&mut buf, 1), Some(5));
        assert_eq!(buf, vec![1u8, 2, 3, 4, 5]);

        assert_eq!(iovec.read_at(&mut buf, 60), Some(5));
        assert_eq!(buf, vec![60u8, 61, 62, 63, 64]);

        assert_eq!(iovec.read_at(&mut buf, 252), Some(4));
        assert_eq!(buf[0..4], vec![252u8, 253, 254, 255]);

        assert_eq!(iovec.read_at(&mut buf, 256), None);
    }

    #[test]
    fn test_iovec_mut_write_at() {
        let mem = default_mem();
        let (mut q, vq) = write_only_chain(&mem);

        // This is a descriptor chain with 4 elements 64 bytes long each.
        let head = q.pop(&mem).unwrap();

        let mut iovec = IoVecBufferMut::from_descriptor_chain(&mem, head).unwrap();
        let buf = vec![0u8, 1, 2, 3, 4];

        // One test vector for each part of the chain
        let mut test_vec1 = vec![0u8; 64];
        let mut test_vec2 = vec![0u8; 64];
        let test_vec3 = vec![0u8; 64];
        let mut test_vec4 = vec![0u8; 64];

        // Control test: Initially all three regions should be zero
        assert_eq!(iovec.write_at(&test_vec1, 0), Some(64));
        assert_eq!(iovec.write_at(&test_vec2, 64), Some(64));
        assert_eq!(iovec.write_at(&test_vec3, 128), Some(64));
        assert_eq!(iovec.write_at(&test_vec4, 192), Some(64));
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);

        // Let's initialize test_vec1 with our buffer.
        test_vec1[..buf.len()].copy_from_slice(&buf);
        // And write just a part of it
        assert_eq!(iovec.write_at(&buf[..3], 0), Some(3));
        // Not all 5 bytes from buf should be written in memory,
        // just 3 of them.
        vq.dtable[0].check_data(&[0u8, 1, 2, 0, 0]);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);
        // But if we write the whole `buf` in memory then all
        // of it should be observable.
        assert_eq!(iovec.write_at(&buf, 0), Some(5));
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);

        // We are now writing with an offset of 1. So, initialize
        // the corresponding part of `test_vec1`
        test_vec1[1..buf.len() + 1].copy_from_slice(&buf);
        assert_eq!(iovec.write_at(&buf, 1), Some(5));
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);

        // Perform a write that traverses two of the underlying
        // regions. Writing at offset 60 should write 4 bytes on the
        // first region and one byte on the second
        test_vec1[60..64].copy_from_slice(&buf[0..4]);
        test_vec2[0] = 4;
        assert_eq!(iovec.write_at(&buf, 60), Some(5));
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
        assert_eq!(iovec.write_at(&buf, 252), Some(4));
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);

        // Trying to add past the end of the buffer should not write anything
        assert_eq!(iovec.write_at(&buf, 256), None);
        vq.dtable[0].check_data(&test_vec1);
        vq.dtable[1].check_data(&test_vec2);
        vq.dtable[2].check_data(&test_vec3);
        vq.dtable[3].check_data(&test_vec4);
    }

    #[test]
    fn test_sub_range() {
        let mem = default_mem();
        let (mut q, _) = read_only_chain(&mem);
        let head = q.pop(&mem).unwrap();

        // This is a descriptor chain with 4 elements 64 bytes long each,
        // so 256 bytes long.
        let iovec = IoVecBuffer::from_descriptor_chain(&mem, head).unwrap();

        // Sub-ranges past the end of the buffer are invalid
        assert!(iovec.sub_region(iovec.len(), 256).is_none());

        // Getting an empty sub-range is invalid
        assert!(iovec.sub_region(0, 0).is_none());

        // Let's take the whole region
        let sub = iovec.sub_region(0, iovec.len()).unwrap();
        assert_eq!(iovec.len(), sub.len());

        // Let's take a valid sub-region that ends past the the end of the buffer
        let sub = iovec.sub_region(128, 256).unwrap();
        assert_eq!(128, sub.len());

        // Getting a sub-region that falls in a single iovec of the buffer
        for i in 0..4 {
            let sub = iovec.sub_region(10 + i * 64, 50).unwrap();
            assert_eq!(50, sub.len());
            assert_eq!(1, sub.iovecs.len());
            // SAFETY: All `iovecs` are 64 bytes long
            assert_eq!(sub.iovecs[0].iov_base, unsafe {
                iovec.vecs[i].iov_base.add(10)
            });
        }

        // Get a sub-region that traverses more than one iovec of the buffer
        let sub = iovec.sub_region(10, 100).unwrap();
        assert_eq!(100, sub.len());
        assert_eq!(2, sub.iovecs.len());
        // SAFETY: all `iovecs` are 64 bytes long
        assert_eq!(sub.iovecs[0].iov_base, unsafe {
            iovec.vecs[0].iov_base.add(10)
        });

        assert_eq!(sub.iovecs[1].iov_base, iovec.vecs[1].iov_base);
    }
}
