// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::offset_of;
use std::num::Wrapping;

use libc::{c_void, iovec, size_t};
use serde::{Deserialize, Serialize};
use vm_memory::bitmap::Bitmap;
use vm_memory::{GuestMemory, GuestMemoryError};

use crate::devices::virtio::gen::virtio_net::virtio_net_hdr_v1;
use crate::devices::virtio::iov_ring_buffer::{IovRingBuffer, IovRingBufferError};
use crate::devices::virtio::net::device::vnet_hdr_len;
use crate::devices::virtio::queue::{DescriptorChain, Queue, FIRECRACKER_MAX_QUEUE_SIZE};
use crate::logger::error;
use crate::utils::ring_buffer::RingBuffer;
use crate::vstate::memory::GuestMemoryMmap;

/// Writes number of buffers to the [`num_buffers`] field of a virtio_net_hdr_v1 struct
/// pointed by the [`ptr`].
///
/// # Safety
/// Memory area needs to be big enoug for virtio_net_hdr_v1 to fit.
pub unsafe fn header_set_num_buffers(ptr: *mut virtio_net_hdr_v1, num_buffers: u16) {
    debug_assert!(
        ptr.is_aligned(),
        "Pointer should have at least 0x2 aligment"
    );

    let ptr: *mut u8 = ptr.cast();
    let ptr = ptr.add(offset_of!(virtio_net_hdr_v1, num_buffers));
    let bytes = num_buffers.to_le_bytes();
    let ptr: *mut [u8; 2] = ptr.cast();
    ptr.write_volatile(bytes);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RxBufferState {
    pub chains_count: u16,
    pub used_descriptors: u16,
}

impl RxBufferState {
    pub fn from_rx_buffer(buffer: &RxBuffer) -> Self {
        // The maximum number of chains is the maximum size of the queue
        // which is FIRECRACKER_MAX_QUEUE_SIZE (256).
        Self {
            chains_count: buffer.chain_infos.len().try_into().unwrap(),
            used_descriptors: buffer.used_descriptors,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ChainInfo {
    pub head_index: u16,
    pub chain_len: u16,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RxBufferError {
    /// Cannot create `RxBuffer` due to error for `IovRingBuffer`: {0}
    New(#[from] IovRingBufferError),
    /// Guest memory error: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Tried to add a read-only descriptor chain to the `RxBuffer`
    ReadOnlyDescriptor,
    /// Tried to write more bytes than `RxBuffer` can hold.
    WriteOverflow,
}

/// A map of all the memory the guest has provided us with for performing RX
#[derive(Debug)]
pub struct RxBuffer {
    // An ring covering all the memory we have available for receiving network
    // frames.
    pub iovecs: IovRingBuffer,
    // Ring buffer of meta data about descriptor chains stored in the `iov_ring`.
    pub chain_infos: RingBuffer<ChainInfo>,
    // Number of descriptor chains we have used to process packets.
    pub used_descriptors: u16,
}

impl RxBuffer {
    /// Create a new [`RxBuffers`] object for storing guest memory for performing RX
    pub fn new() -> Result<Self, RxBufferError> {
        Ok(Self {
            iovecs: IovRingBuffer::new()?,
            chain_infos: RingBuffer::new_with_size(u32::from(FIRECRACKER_MAX_QUEUE_SIZE)),
            used_descriptors: 0,
        })
    }

    /// Is number of iovecs is zero.
    pub fn is_empty(&self) -> bool {
        self.iovecs.is_empty()
    }

    /// Returns a slice of underlying iovec for the first chain
    /// in the buffer.
    pub fn one_chain_mut_slice(&mut self) -> &mut [iovec] {
        if let Some(chain_info) = self.chain_infos.first() {
            let chain_len = usize::from(chain_info.chain_len);
            &mut self.iovecs.as_mut_slice()[0..chain_len]
        } else {
            &mut []
        }
    }

    /// Add a new `DescriptorChain` that we received from the RX queue in the buffer.
    ///
    /// # Safety
    /// The `DescriptorChain` cannot be referencing the same memory location as any other
    /// `DescriptorChain`.
    pub unsafe fn add_chain(
        &mut self,
        mem: &GuestMemoryMmap,
        head: DescriptorChain,
    ) -> Result<(), RxBufferError> {
        let head_index = head.index;

        let mut next_descriptor = Some(head);
        let mut chain_len: u16 = 0;
        while let Some(desc) = next_descriptor {
            if !desc.is_write_only() {
                self.iovecs.pop_back(usize::from(chain_len));
                return Err(RxBufferError::ReadOnlyDescriptor);
            }

            // We use get_slice instead of `get_host_address` here in order to have the whole
            // range of the descriptor chain checked, i.e. [addr, addr + len) is a valid memory
            // region in the GuestMemoryMmap.
            let slice = match mem.get_slice(desc.addr, desc.len as usize) {
                Ok(slice) => slice,
                Err(e) => {
                    self.iovecs.pop_back(usize::from(chain_len));
                    return Err(RxBufferError::GuestMemory(e));
                }
            };

            // We need to mark the area of guest memory that will be mutated through this
            // IoVecBufferMut as dirty ahead of time, as we loose access to all
            // vm-memory related information after converting down to iovecs.
            slice.bitmap().mark_dirty(0, desc.len as usize);

            let iov_base = slice.ptr_guard_mut().as_ptr().cast::<c_void>();
            self.iovecs.push_back(iovec {
                iov_base,
                iov_len: desc.len as size_t,
            });
            chain_len += 1;

            next_descriptor = desc.next_descriptor();
        }
        self.chain_infos.push_back(ChainInfo {
            head_index,
            chain_len,
        });

        Ok(())
    }

    /// Writes bytes from a slice into buffer.
    pub fn write(&mut self, mut bytes: &[u8]) -> Result<(), RxBufferError> {
        for iov in self.iovecs.as_mut_slice() {
            if bytes.is_empty() {
                break;
            }
            let iov_slice_len = bytes.len().min(iov.iov_len);
            // SAFETY: The user space pointer and the length were verified during
            // the iovec creation.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), iov.iov_base.cast(), iov_slice_len)
            };
            bytes = &bytes[iov_slice_len..];
        }
        if !bytes.is_empty() {
            Err(RxBufferError::WriteOverflow)
        } else {
            Ok(())
        }
    }

    /// Finish packet processing by removing used iovecs from the buffer and
    /// writing information about used descriptor chains into the queue.
    ///
    /// # Safety
    /// `RxBuffer` should not be empty when this method is called because it
    /// assumes there is at least one chain holding data.
    pub unsafe fn finish_packet(&mut self, bytes_written: u32, rx_queue: &mut Queue) {
        // This function is called only after some bytes were written to the
        // buffer. This means the iov_ring cannot be empty.
        debug_assert!(!self.iovecs.is_empty());
        let header_ptr: *mut virtio_net_hdr_v1 = self.iovecs.as_slice()[0].iov_base.cast();
        let header_buff_len = self.iovecs.as_slice()[0].iov_len;
        assert!(
            vnet_hdr_len() <= header_buff_len,
            "Network buffer should be big enough for virtio_net_hdr_v1 object"
        );

        let iov_info = self
            .chain_infos
            .pop_front()
            .expect("This should never happen if write to the buffer succeded.");
        self.iovecs.pop_front(usize::from(iov_info.chain_len));

        if let Err(err) = rx_queue.write_used_element(
            (rx_queue.next_used + Wrapping(self.used_descriptors)).0,
            iov_info.head_index,
            bytes_written,
        ) {
            error!(
                "net: Failed to add used descriptor {} of length {} to RX queue: {err}",
                iov_info.head_index, bytes_written
            );
        }
        self.used_descriptors += 1;

        // SAFETY: The user space pointer was verified at the point of creation and
        // we verified the alignment and header buffer size.
        unsafe {
            header_set_num_buffers(header_ptr, 1);
        }
    }

    /// Notify queue about all descriptor chains we used to process packets so far.
    pub fn notify_queue(&mut self, rx_queue: &mut Queue) {
        rx_queue.advance_used_ring(self.used_descriptors);
        self.used_descriptors = 0;
    }
}

#[cfg(test)]
// TODO why are we going through this? why clippy hates everything?
#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::needless_range_loop)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use vm_memory::GuestAddress;

    use super::*;
    use crate::devices::virtio::test_utils::{set_dtable_one_chain, VirtQueue};
    use crate::test_utils::single_region_mem;

    #[test]
    fn test_rx_buffer_new() {
        let mut buff = RxBuffer::new().unwrap();
        assert!(buff.is_empty());
        assert_eq!(buff.one_chain_mut_slice(), &mut []);
    }

    #[test]
    fn test_rx_buffer_add_chain() {
        let mem = single_region_mem(65562);
        let rxq = VirtQueue::new(GuestAddress(0), &mem, 256);
        let mut queue = rxq.create_queue();

        // Single chain with len of 16
        {
            let chain_len = 16;
            set_dtable_one_chain(&rxq, chain_len);
            let desc = queue.pop().unwrap();

            let mut buff = RxBuffer::new().unwrap();
            // SAFETY: safe it is a test memory
            unsafe {
                buff.add_chain(&mem, desc).unwrap();
            }
            let slice = buff.one_chain_mut_slice();
            for i in 0..chain_len {
                assert_eq!(
                    slice[i].iov_base as u64,
                    mem.get_host_address(GuestAddress((2048 + 1024 * i) as u64))
                        .unwrap() as u64
                );
                assert_eq!(slice[i].iov_len, 1024);
            }
            assert_eq!(buff.chain_infos.len(), 1);
            assert_eq!(
                buff.chain_infos.items[0],
                ChainInfo {
                    head_index: 0,
                    chain_len: 16
                }
            );
        }
    }

    #[test]
    #[should_panic]
    fn test_rx_buffer_write_panic() {
        let mem = single_region_mem(65562);
        let rxq = VirtQueue::new(GuestAddress(0), &mem, 256);
        let mut queue = rxq.create_queue();

        set_dtable_one_chain(&rxq, 1);
        let desc = queue.pop().unwrap();

        let mut buff = RxBuffer::new().unwrap();
        // SAFETY: safe it is a test memory
        unsafe {
            buff.add_chain(&mem, desc).unwrap();
        }

        // Write should panic, because we unwrap on error
        // because we try to write more than buffer can hold.
        buff.write(&[69; 2 * 1024]).unwrap();
    }

    #[test]
    fn test_rx_buffer_write() {
        let mem = single_region_mem(65562);
        let rxq = VirtQueue::new(GuestAddress(0), &mem, 256);
        let mut queue = rxq.create_queue();

        set_dtable_one_chain(&rxq, 1);
        let desc = queue.pop().unwrap();

        let mut buff = RxBuffer::new().unwrap();
        // SAFETY: safe it is a test memory
        unsafe {
            buff.add_chain(&mem, desc).unwrap();
        }

        // Initially data should be all zeros
        let slice = buff.one_chain_mut_slice();
        let data_slice_before: &[u8] =
            // SAFETY: safe as iovecs are verified on creation
            unsafe { std::slice::from_raw_parts(slice[0].iov_base.cast(), slice[0].iov_len) };
        assert_eq!(data_slice_before, &[0; 1024]);

        // Write should happen to first iovec (as there is only 1)
        buff.write(&[69; 1024]).unwrap();

        let slice = buff.one_chain_mut_slice();
        let data_slice_after: &[u8] =
            // SAFETY: safe as iovecs are verified on creation
            unsafe { std::slice::from_raw_parts(slice[0].iov_base.cast(), slice[0].iov_len) };
        assert_eq!(data_slice_after, &[69; 1024]);
    }

    #[test]
    fn test_rx_buffer_finish_packet_and_notify() {
        let mem = single_region_mem(65562);
        let rxq = VirtQueue::new(GuestAddress(0), &mem, 256);
        let mut queue = rxq.create_queue();

        let chain_len = 16;
        set_dtable_one_chain(&rxq, chain_len);
        let desc = queue.pop().unwrap();

        let mut buff = RxBuffer::new().unwrap();
        // SAFETY: safe it is a test memory
        unsafe {
            buff.add_chain(&mem, desc).unwrap();
        }

        let slice = buff.one_chain_mut_slice();
        // SAFETY: The user space pointer was verified at the  point of creation.
        #[allow(clippy::transmute_ptr_to_ref)]
        let header: &virtio_net_hdr_v1 = unsafe { std::mem::transmute(slice[0].iov_base) };
        assert_eq!(header.num_buffers, 0);

        // There is one chain in the buffer. The length of the data "written" does
        // not really matter. We just need to check that single chain present was popped
        // and number of buffers is correctly set in the header.
        // SAFETY: the buff is not empty
        unsafe {
            buff.finish_packet(1024, &mut queue);
        }
        assert_eq!(buff.iovecs.len(), 0);
        assert!(buff.is_empty());
        assert_eq!(header.num_buffers, 1);

        assert_eq!(buff.used_descriptors, 1);
        assert_eq!(rxq.used.idx.get(), 0);
        buff.notify_queue(&mut queue);
        assert_eq!(buff.used_descriptors, 0);
        assert_eq!(rxq.used.idx.get(), 1);
    }
}
