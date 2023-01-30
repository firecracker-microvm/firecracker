// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use libc::{c_void, iovec, size_t};
use vm_memory::{GuestMemory, GuestMemoryMmap};

use crate::virtio::DescriptorChain;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// We found a write-only descriptor where read-only was expected
    #[error("Tried to create an `IoVec` from a write-only descriptor chain")]
    WriteOnlyDescriptor,
    /// An error happened with guest memory handling
    #[error("Guest memory error: {0}")]
    GuestMemory(#[from] vm_memory::GuestMemoryError),
}

type Result<T> = std::result::Result<T, Error>;

/// This is essentially a wrapper of a `Vec<libc::iovec>` which can be passed `libc::writev`.
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

    /// Reads a number of bytes from the `IoVecBuffer` starting at a given offset.
    ///
    /// This will try to fill `buf` reading bytes from the `IoVecBuffer` starting from
    /// the given offset.
    ///
    /// # Returns
    ///
    /// The number of bytes read (if any)
    pub fn read_at(&self, buf: &mut [u8], offset: usize) -> Option<usize> {
        // We can't read past the end of this `IoVecBuffer`
        if offset >= self.len() {
            return None;
        }

        // The number of bytes that we will read out
        let size = std::cmp::min(buf.len(), self.len() - offset);
        // This is the first byte of `self` that we will not read out
        let last = offset + size;
        // byte index in `self`
        let mut seg_end = 0;
        // byte index in `buf`
        let mut buf_start = 0;

        for seg in self.vecs.iter() {
            let seg_start = seg_end;
            seg_end = seg_start + seg.iov_len;

            // If the beginning of the segment is past the end we are done
            if last <= seg_start {
                break;
            }

            // If the start offset is past the end of the segment we just skip this segment
            if offset >= seg_end {
                continue;
            }

            let start = if offset < seg_start {
                0
            } else {
                offset - seg_start
            };

            let end = if last < seg_end {
                last - seg_start
            } else {
                seg.iov_len
            };

            let buf_end = buf_start + end - start;

            let buf_ptr = buf[buf_start..buf_end].as_mut_ptr();

            // SAFETY:
            // The call to `std::ptr::add` is safe because `seg.iov_base` is a valid pointer (it's
            // the pointer to a valid guest memory region (`GuestMemoryMmap` implementation checked
            // its boundaries) and `start` is less than `seg.iov_len`.
            //
            // The call to `copy_nonoverlapping` is safe because:
            // 1. `buf_ptr` is a pointer valid for writing `buf_end - buf_start + 1` bytes.
            // 2. `seg_ptr` is a pointer valid for reading `buf_end - buf_start + 1` bytes.
            // 3. Both pointers pointers are pointing to `u8`, so they are properly aligned.
            // 4. The memory regions these pointers point to are not overlapping. `seg_ptr` points
            //    to guest physical memory, whereas `buf_ptr` to Firecracaker-owned memory.
            unsafe {
                let seg_ptr = (seg.iov_base as *const u8).add(start);
                std::ptr::copy_nonoverlapping(seg_ptr, buf_ptr, buf_end - buf_start);
            }

            buf_start = buf_end;
        }

        Some(size)
    }
}

#[cfg(test)]
mod tests {
    use libc::{c_void, iovec};
    use vm_memory::test_utils::create_anon_guest_memory;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::IoVecBuffer;
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

    fn chain(is_write_only: bool) -> (Queue, GuestMemoryMmap) {
        let m = create_anon_guest_memory(
            &[
                (GuestAddress(0), 0x10000),
                (GuestAddress(0x20000), 0x10000),
                (GuestAddress(0x40000), 0x10000),
            ],
            false,
        )
        .unwrap();

        let v: Vec<u8> = (0..=255).collect();
        m.write_slice(&v, GuestAddress(0x20000)).unwrap();

        let vq = VirtQueue::new(GuestAddress(0), &m, 16);

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

        (q, m)
    }

    #[test]
    fn test_access_mode() {
        let (mut q, mem) = chain(false);
        let head = q.pop(&mem).unwrap();
        assert!(IoVecBuffer::from_descriptor_chain(&mem, head).is_ok());

        let (mut q, mem) = chain(true);
        let head = q.pop(&mem).unwrap();
        assert!(IoVecBuffer::from_descriptor_chain(&mem, head).is_err());
    }

    #[test]
    fn test_iovec_length() {
        let (mut q, mem) = chain(false);
        let head = q.pop(&mem).unwrap();

        let iovec = IoVecBuffer::from_descriptor_chain(&mem, head).unwrap();
        assert_eq!(iovec.len(), 4 * 64);
    }

    #[test]
    fn test_iovec_read_at() {
        let (mut q, mem) = chain(false);
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
}
