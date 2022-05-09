// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::virtio::DescriptorChain;
use std::io::IoSlice;
use std::ops::Deref;
use vm_memory::{GuestMemory, GuestMemoryError, GuestMemoryMmap};

#[derive(Debug)]
pub enum Error {
    /// We found a write-only descriptor where read-only was expected
    WriteOnlyDescriptor,
    /// An error happened with guest memory handling
    GuestMemory(vm_memory::GuestMemoryError),
}

impl From<GuestMemoryError> for Error {
    fn from(err: GuestMemoryError) -> Self {
        Error::GuestMemory(err)
    }
}

type Result<T> = std::result::Result<T, Error>;

/// This is essentially a wrapper of a `Vec<IoSlice>` which can be passed `writev`.
///
/// It describes a buffer passed to us by the guest that is scattered across multiple
/// memory regions. Additionally, this wrapper provides methods that allow reading arbitrary ranges
/// of data from that buffer.
#[derive(Debug)]
pub(crate) struct IoVecBuffer<'a> {
    // container of the memory regions included in this IO vector
    vecs: Vec<IoSlice<'a>>,
    // Total length of the IoVecBuffer
    len: usize,
}

impl<'a> Deref for IoVecBuffer<'a> {
    type Target = [IoSlice<'a>];

    fn deref(&self) -> &Self::Target {
        self.vecs.as_slice()
    }
}

#[cfg(test)]
impl<'a> From<&'a [u8]> for IoVecBuffer<'a> {
    fn from(buf: &'a [u8]) -> Self {
        Self {
            vecs: vec![IoSlice::new(buf)],
            len: buf.len(),
        }
    }
}

impl<'a> IoVecBuffer<'a> {
    /// Create an `IoVecBuffer` from a `DescriptorChain`
    pub fn from_descriptor_chain(mem: &'a GuestMemoryMmap, head: DescriptorChain) -> Result<Self> {
        let mut vecs = vec![];
        let mut len = 0usize;

        let mut next_descriptor = Some(head);
        while let Some(desc) = next_descriptor {
            if desc.is_write_only() {
                return Err(Error::WriteOnlyDescriptor);
            }

            // This is safe since we get `ptr` from `get_slice` which also checks the length
            // of the descriptor
            let ptr = mem.get_slice(desc.addr, desc.len as usize)?.as_ptr();
            let slice = unsafe { std::slice::from_raw_parts(ptr, desc.len as usize) };
            vecs.push(IoSlice::new(slice));
            len += desc.len as usize;

            next_descriptor = desc.next_descriptor();
        }

        Ok(Self { vecs, len })
    }

    /// Get the total length of the memory regions covered by this `IoVecBuffer`
    pub fn len(&self) -> usize {
        self.len
    }

    /// Reads a number of bytes from the `IoVecBuffer` starting at a given offset.
    ///
    /// This will try to fill `buf` reading bytes from the `IoVecBuffer` starting from
    /// the given offset.
    ///
    /// # Retruns
    ///
    /// The number of bytes read (if any)
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> Option<usize> {
        // We can't read past the end of this `IoVecBuffer`
        if offset >= self.len() as u64 {
            return None;
        }

        // We try to fill up `buf` with as many bytes as we have
        let size = std::cmp::min(buf.len(), self.len() - offset as usize);
        // This is the last byte of `self` that we will reado out
        let end = offset as usize + size;
        // byte index in `self`
        let mut seg_start = 0;
        // byte index in `buf`
        let mut buf_start = 0;

        for seg in self.vecs.iter() {
            let seg_end = seg_start + seg.len();

            let mut write_start = std::cmp::max(seg_start, offset as usize);
            let mut write_end = std::cmp::min(seg_end, end);

            if write_start < write_end {
                write_start -= seg_start;
                write_end -= seg_start;
                let bytes = write_end - write_start;
                let buf_end = buf_start + bytes;
                buf[buf_start..buf_end].copy_from_slice(&seg[write_start..write_end]);
                buf_start += bytes;
            }

            seg_start = seg_end;
            // The next segment is out of range, we are done here.
            if seg_start >= end {
                break;
            }
        }

        Some(size)
    }
}

#[cfg(test)]
pub mod tests {
    use super::IoVecBuffer;
    use crate::virtio::queue::{Queue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::virtio::test_utils::VirtQueue;
    use vm_memory::{test_utils::create_anon_guest_memory, Bytes, GuestAddress, GuestMemoryMmap};

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
