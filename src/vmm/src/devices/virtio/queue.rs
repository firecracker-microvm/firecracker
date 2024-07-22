// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp::min;
use std::num::Wrapping;
use std::sync::atomic::{fence, Ordering};

use utils::usize_to_u64;

use crate::logger::error;
use crate::vstate::memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap,
};

pub(super) const VIRTQ_DESC_F_NEXT: u16 = 0x1;
pub(super) const VIRTQ_DESC_F_WRITE: u16 = 0x2;

/// Max size of virtio queues offered by firecracker's virtio devices.
pub(super) const FIRECRACKER_MAX_QUEUE_SIZE: u16 = 256;

// GuestMemoryMmap::read_obj_from_addr() will be used to fetch the descriptor,
// which has an explicit constraint that the entire descriptor doesn't
// cross the page boundary. Otherwise the descriptor may be splitted into
// two mmap regions which causes failure of GuestMemoryMmap::read_obj_from_addr().
//
// The Virtio Spec 1.0 defines the alignment of VirtIO descriptor is 16 bytes,
// which fulfills the explicit constraint of GuestMemoryMmap::read_obj_from_addr().

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum QueueError {
    /// Descriptor index out of bounds: {0}.
    DescIndexOutOfBounds(u32),
    /// Failed to write value into the virtio queue used ring: {0}
    UsedRing(#[from] vm_memory::GuestMemoryError),
}

/// A virtio descriptor constraints with C representative.
/// Taken from Virtio spec:
/// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-430008
/// 2.6.5 The Virtqueue Descriptor Table
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Descriptor {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

// SAFETY: `Descriptor` is a POD and contains no padding.
unsafe impl ByteValued for Descriptor {}

/// A virtio used element in the used ring.
/// Taken from Virtio spec:
/// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-430008
/// 2.6.8 The Virtqueue Used Ring
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct UsedElement {
    id: u32,
    len: u32,
}

// SAFETY: `UsedElement` is a POD and contains no padding.
unsafe impl ByteValued for UsedElement {}

/// A virtio descriptor chain.
#[derive(Debug)]
pub struct DescriptorChain<'a, M: GuestMemory = GuestMemoryMmap> {
    desc_table: GuestAddress,
    queue_size: u16,
    ttl: u16, // used to prevent infinite chain cycles

    /// Reference to guest memory
    pub mem: &'a M,

    /// Index into the descriptor table
    pub index: u16,

    /// Guest physical address of device specific data
    pub addr: GuestAddress,

    /// Length of device specific data
    pub len: u32,

    /// Includes next, write, and indirect bits
    pub flags: u16,

    /// Index into the descriptor table of the next descriptor if flags has
    /// the next bit set
    pub next: u16,
}

impl<'a, M: GuestMemory> DescriptorChain<'a, M> {
    fn checked_new(
        mem: &'a M,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
    ) -> Option<Self> {
        if index >= queue_size {
            return None;
        }

        let desc_head = mem.checked_offset(desc_table, (index as usize) * 16)?;
        mem.checked_offset(desc_head, 16)?;

        // These reads can't fail unless Guest memory is hopelessly broken.
        let desc = match mem.read_obj::<Descriptor>(desc_head) {
            Ok(ret) => ret,
            Err(err) => {
                error!(
                    "Failed to read virtio descriptor from memory at address {:#x}: {}",
                    desc_head.0, err
                );
                return None;
            }
        };
        let chain = DescriptorChain {
            mem,
            desc_table,
            queue_size,
            ttl: queue_size,
            index,
            addr: GuestAddress(desc.addr),
            len: desc.len,
            flags: desc.flags,
            next: desc.next,
        };

        if chain.is_valid() {
            Some(chain)
        } else {
            None
        }
    }

    fn is_valid(&self) -> bool {
        !self.has_next() || self.next < self.queue_size
    }

    /// Gets if this descriptor chain has another descriptor chain linked after it.
    pub fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0 && self.ttl > 1
    }

    /// If the driver designated this as a write only descriptor.
    ///
    /// If this is false, this descriptor is read only.
    /// Write only means the emulated device can write and the driver can read.
    pub fn is_write_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    /// Gets the next descriptor in this descriptor chain, if there is one.
    ///
    /// Note that this is distinct from the next descriptor chain returned by `AvailIter`, which is
    /// the head of the next _available_ descriptor chain.
    pub fn next_descriptor(&self) -> Option<Self> {
        if self.has_next() {
            DescriptorChain::checked_new(self.mem, self.desc_table, self.queue_size, self.next).map(
                |mut c| {
                    c.ttl = self.ttl - 1;
                    c
                },
            )
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct DescriptorIterator<'a>(Option<DescriptorChain<'a>>);

impl<'a> IntoIterator for DescriptorChain<'a> {
    type Item = DescriptorChain<'a>;
    type IntoIter = DescriptorIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        DescriptorIterator(Some(self))
    }
}

impl<'a> Iterator for DescriptorIterator<'a> {
    type Item = DescriptorChain<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.take().map(|desc| {
            self.0 = desc.next_descriptor();
            desc
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// A virtio queue's parameters.
pub struct Queue {
    /// The maximal size in elements offered by the device
    pub(crate) max_size: u16,

    /// The queue size in elements the driver selected
    pub size: u16,

    /// Indicates if the queue is finished with configuration
    pub ready: bool,

    /// Guest physical address of the descriptor table
    pub desc_table: GuestAddress,

    /// Guest physical address of the available ring
    pub avail_ring: GuestAddress,

    /// Guest physical address of the used ring
    pub used_ring: GuestAddress,

    pub(crate) next_avail: Wrapping<u16>,
    pub(crate) next_used: Wrapping<u16>,

    /// VIRTIO_F_RING_EVENT_IDX negotiated (notification suppression enabled)
    pub(crate) uses_notif_suppression: bool,
    /// The number of added used buffers since last guest kick
    pub(crate) num_added: Wrapping<u16>,
}

#[allow(clippy::len_without_is_empty)]
impl Queue {
    /// Constructs an empty virtio queue with the given `max_size`.
    pub fn new(max_size: u16) -> Queue {
        Queue {
            max_size,
            size: 0,
            ready: false,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            uses_notif_suppression: false,
            num_added: Wrapping(0),
        }
    }

    /// Maximum size of the queue.
    pub fn get_max_size(&self) -> u16 {
        self.max_size
    }

    /// Return the actual size of the queue, as the driver may not set up a
    /// queue as big as the device allows.
    pub fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    /// Validates the queue's in-memory layout is correct.
    pub fn is_layout_valid<M: GuestMemory>(&self, mem: &M) -> bool {
        let queue_size = usize::from(self.actual_size());
        let desc_table = self.desc_table;
        let desc_table_size = 16 * queue_size;
        let avail_ring = self.avail_ring;
        let avail_ring_size = 6 + 2 * queue_size;
        let used_ring = self.used_ring;
        let used_ring_size = 6 + 8 * queue_size;

        if !self.ready {
            error!("attempt to use virtio queue that is not marked ready");
            false
        } else if self.size > self.max_size || self.size == 0 || (self.size & (self.size - 1)) != 0
        {
            error!("virtio queue with invalid size: {}", self.size);
            false
        } else if desc_table.raw_value() & 0xf != 0 {
            error!("virtio queue descriptor table breaks alignment constraints");
            false
        } else if avail_ring.raw_value() & 0x1 != 0 {
            error!("virtio queue available ring breaks alignment constraints");
            false
        } else if used_ring.raw_value() & 0x3 != 0 {
            error!("virtio queue used ring breaks alignment constraints");
            false
        // range check entire descriptor table to be assigned valid guest physical addresses
        } else if mem.get_slice(desc_table, desc_table_size).is_err() {
            error!(
                "virtio queue descriptor table goes out of bounds: start:0x{:08x} size:0x{:08x}",
                desc_table.raw_value(),
                desc_table_size
            );
            false
        } else if mem.get_slice(avail_ring, avail_ring_size).is_err() {
            error!(
                "virtio queue available ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                avail_ring.raw_value(),
                avail_ring_size
            );
            false
        } else if mem.get_slice(used_ring, used_ring_size).is_err() {
            error!(
                "virtio queue used ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                used_ring.raw_value(),
                used_ring_size
            );
            false
        } else {
            true
        }
    }

    /// Validates that the queue's representation is correct.
    pub fn is_valid<M: GuestMemory>(&self, mem: &M) -> bool {
        if !self.is_layout_valid(mem) {
            false
        } else if self.len(mem) > self.max_size {
            error!(
                "virtio queue number of available descriptors {} is greater than queue max size {}",
                self.len(mem),
                self.max_size
            );
            false
        } else {
            true
        }
    }

    /// Returns the number of yet-to-be-popped descriptor chains in the avail ring.
    pub fn len<M: GuestMemory>(&self, mem: &M) -> u16 {
        debug_assert!(self.is_layout_valid(mem));

        (self.avail_idx(mem) - self.next_avail).0
    }

    /// Checks if the driver has made any descriptor chains available in the avail ring.
    pub fn is_empty<M: GuestMemory>(&self, mem: &M) -> bool {
        self.len(mem) == 0
    }

    /// Pop the first available descriptor chain from the avail ring.
    pub fn pop<'b, M: GuestMemory>(&mut self, mem: &'b M) -> Option<DescriptorChain<'b, M>> {
        debug_assert!(self.is_layout_valid(mem));

        let len = self.len(mem);
        // The number of descriptor chain heads to process should always
        // be smaller or equal to the queue size, as the driver should
        // never ask the VMM to process a available ring entry more than
        // once. Checking and reporting such incorrect driver behavior
        // can prevent potential hanging and Denial-of-Service from
        // happening on the VMM side.
        if len > self.actual_size() {
            // We are choosing to interrupt execution since this could be a potential malicious
            // driver scenario. This way we also eliminate the risk of repeatedly
            // logging and potentially clogging the microVM through the log system.
            panic!(
                "The number of available virtio descriptors {len} is greater than queue size: {}!",
                self.actual_size()
            );
        }

        if len == 0 {
            return None;
        }

        self.do_pop_unchecked(mem)
    }

    /// Try to pop the first available descriptor chain from the avail ring.
    /// If no descriptor is available, enable notifications.
    pub fn pop_or_enable_notification<'b, M: GuestMemory>(
        &mut self,
        mem: &'b M,
    ) -> Option<DescriptorChain<'b, M>> {
        if !self.uses_notif_suppression {
            return self.pop(mem);
        }

        if self.try_enable_notification(mem) {
            return None;
        }

        self.do_pop_unchecked(mem)
    }

    /// Pop the first available descriptor chain from the avail ring.
    ///
    /// # Important
    /// This is an internal method that ASSUMES THAT THERE ARE AVAILABLE DESCRIPTORS. Otherwise it
    /// will retrieve a descriptor that contains garbage data (obsolete/empty).
    fn do_pop_unchecked<'b, M: GuestMemory>(
        &mut self,
        mem: &'b M,
    ) -> Option<DescriptorChain<'b, M>> {
        // This fence ensures all subsequent reads see the updated driver writes.
        fence(Ordering::Acquire);

        // We'll need to find the first available descriptor, that we haven't yet popped.
        // In a naive notation, that would be:
        // `descriptor_table[avail_ring[next_avail]]`.
        //
        // First, we compute the byte-offset (into `self.avail_ring`) of the index of the next
        // available descriptor. `self.avail_ring` stores the address of a `struct
        // virtq_avail`, as defined by the VirtIO spec:
        //
        // ```C
        // struct virtq_avail {
        //   le16 flags;
        //   le16 idx;
        //   le16 ring[QUEUE_SIZE];
        //   le16 used_event
        // }
        // ```
        //
        // We use `self.next_avail` to store the position, in `ring`, of the next available
        // descriptor index, with a twist: we always only increment `self.next_avail`, so the
        // actual position will be `self.next_avail % self.actual_size()`.
        // We are now looking for the offset of `ring[self.next_avail % self.actual_size()]`.
        // `ring` starts after `flags` and `idx` (4 bytes into `struct virtq_avail`), and holds
        // 2-byte items, so the offset will be:
        let index_offset = 4 + 2 * (self.next_avail.0 % self.actual_size());

        // `self.is_valid()` already performed all the bound checks on the descriptor table
        // and virtq rings, so it's safe to unwrap guest memory reads and to use unchecked
        // offsets.
        let desc_index: u16 = mem
            .read_obj(self.avail_ring.unchecked_add(u64::from(index_offset)))
            .unwrap();

        DescriptorChain::checked_new(mem, self.desc_table, self.actual_size(), desc_index).map(
            |dc| {
                self.next_avail += Wrapping(1);
                dc
            },
        )
    }

    /// Undo the effects of the last `self.pop()` call.
    /// The caller can use this, if it was unable to consume the last popped descriptor chain.
    pub fn undo_pop(&mut self) {
        self.next_avail -= Wrapping(1);
    }

    /// Puts an available descriptor head into the used ring for use by the guest.
    pub fn add_used<M: GuestMemory>(
        &mut self,
        mem: &M,
        desc_index: u16,
        len: u32,
    ) -> Result<(), QueueError> {
        debug_assert!(self.is_layout_valid(mem));

        let next_used = self.next_used.0 % self.actual_size();
        let used_element = UsedElement {
            id: u32::from(desc_index),
            len,
        };
        self.write_used_ring(mem, next_used, used_element)?;

        self.num_added += Wrapping(1);
        self.next_used += Wrapping(1);

        // This fence ensures all descriptor writes are visible before the index update is.
        fence(Ordering::Release);

        self.set_used_ring_idx(self.next_used.0, mem);
        Ok(())
    }

    fn write_used_ring<M: GuestMemory>(
        &self,
        mem: &M,
        index: u16,
        used_element: UsedElement,
    ) -> Result<(), QueueError> {
        if used_element.id >= u32::from(self.actual_size()) {
            error!(
                "attempted to add out of bounds descriptor to used ring: {}",
                used_element.id
            );
            return Err(QueueError::DescIndexOutOfBounds(used_element.id));
        }

        // Used ring has layout:
        // struct UsedRing {
        //     flags: u16,
        //     idx: u16,
        //     ring: [UsedElement; <queue size>],
        //     avail_event: u16,
        // }
        // We calculate offset into `ring` field.
        let used_ring_offset = std::mem::size_of::<u16>()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<UsedElement>() * usize::from(index);
        let used_element_address = self.used_ring.unchecked_add(usize_to_u64(used_ring_offset));

        mem.write_obj(used_element, used_element_address)
            .map_err(QueueError::UsedRing)
    }

    /// Fetch the available ring index (`virtq_avail->idx`) from guest memory.
    /// This is written by the driver, to indicate the next slot that will be filled in the avail
    /// ring.
    pub fn avail_idx<M: GuestMemory>(&self, mem: &M) -> Wrapping<u16> {
        // Bound checks for queue inner data have already been performed, at device activation time,
        // via `self.is_valid()`, so it's safe to unwrap and use unchecked offsets here.
        // Note: the `MmioTransport` code ensures that queue addresses cannot be changed by the
        // guest       after device activation, so we can be certain that no change has
        // occurred since the last `self.is_valid()` check.
        let addr = self.avail_ring.unchecked_add(2);
        Wrapping(mem.read_obj::<u16>(addr).unwrap())
    }

    /// Get the value of the used event field of the avail ring.
    #[inline(always)]
    pub fn used_event<M: GuestMemory>(&self, mem: &M) -> Wrapping<u16> {
        debug_assert!(self.is_layout_valid(mem));

        // We need to find the `used_event` field from the avail ring.
        let used_event_addr = self
            .avail_ring
            .unchecked_add(u64::from(4 + 2 * self.actual_size()));

        Wrapping(mem.read_obj::<u16>(used_event_addr).unwrap())
    }

    /// Helper method that writes to the `avail_event` field of the used ring.
    #[inline(always)]
    fn set_used_ring_avail_event<M: GuestMemory>(&mut self, avail_event: u16, mem: &M) {
        debug_assert!(self.is_layout_valid(mem));

        // Used ring has layout:
        // struct UsedRing {
        //     flags: u16,
        //     idx: u16,
        //     ring: [UsedElement; <queue size>],
        //     avail_event: u16,
        // }
        // We calculate offset into `avail_event` field.
        let avail_event_offset = std::mem::size_of::<u16>()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<UsedElement>() * usize::from(self.actual_size());
        let avail_event_addr = self
            .used_ring
            .unchecked_add(usize_to_u64(avail_event_offset));

        mem.write_obj(avail_event, avail_event_addr).unwrap();
    }

    /// Helper method that writes to the `idx` field of the used ring.
    #[inline(always)]
    fn set_used_ring_idx<M: GuestMemory>(&mut self, next_used: u16, mem: &M) {
        debug_assert!(self.is_layout_valid(mem));

        // Used ring has layout:
        // struct UsedRing {
        //     flags: u16,
        //     idx: u16,
        //     ring: [UsedElement; <queue size>],
        //     avail_event: u16,
        // }
        // We calculate offset into `idx` field.
        let idx_offset = std::mem::size_of::<u16>();
        let next_used_addr = self.used_ring.unchecked_add(usize_to_u64(idx_offset));
        mem.write_obj(next_used, next_used_addr).unwrap();
    }

    /// Try to enable notification events from the guest driver. Returns true if notifications were
    /// successfully enabled. Otherwise it means that one or more descriptors can still be consumed
    /// from the available ring and we can't guarantee that there will be a notification. In this
    /// case the caller might want to consume the mentioned descriptors and call this method again.
    pub fn try_enable_notification<M: GuestMemory>(&mut self, mem: &M) -> bool {
        debug_assert!(self.is_layout_valid(mem));

        // If the device doesn't use notification suppression, we'll continue to get notifications
        // no matter what.
        if !self.uses_notif_suppression {
            return true;
        }

        let len = self.len(mem);
        if len != 0 {
            // The number of descriptor chain heads to process should always
            // be smaller or equal to the queue size.
            if len > self.actual_size() {
                // We are choosing to interrupt execution since this could be a potential malicious
                // driver scenario. This way we also eliminate the risk of
                // repeatedly logging and potentially clogging the microVM through
                // the log system.
                panic!(
                    "The number of available virtio descriptors {len} is greater than queue size: \
                     {}!",
                    self.actual_size()
                );
            }
            return false;
        }

        // Set the next expected avail_idx as avail_event.
        self.set_used_ring_avail_event(self.next_avail.0, mem);

        // Make sure all subsequent reads are performed after `set_used_ring_avail_event`.
        fence(Ordering::SeqCst);

        // If the actual avail_idx is different than next_avail one or more descriptors can still
        // be consumed from the available ring.
        self.next_avail.0 == self.avail_idx(mem).0
    }

    /// Enable notification suppression.
    pub fn enable_notif_suppression(&mut self) {
        self.uses_notif_suppression = true;
    }

    /// Check if we need to kick the guest.
    ///
    /// Please note this method has side effects: once it returns `true`, it considers the
    /// driver will actually be notified, and won't return `true` again until the driver
    /// updates `used_event` and/or the notification conditions hold once more.
    ///
    /// This is similar to the `vring_need_event()` method implemented by the Linux kernel.
    pub fn prepare_kick<M: GuestMemory>(&mut self, mem: &M) -> bool {
        debug_assert!(self.is_layout_valid(mem));

        // If the device doesn't use notification suppression, always return true
        if !self.uses_notif_suppression {
            return true;
        }

        // We need to expose used array entries before checking the used_event.
        fence(Ordering::SeqCst);

        let new = self.next_used;
        let old = self.next_used - self.num_added;
        let used_event = self.used_event(mem);

        self.num_added = Wrapping(0);

        new - used_event - Wrapping(1) < new - old
    }
}

#[cfg(kani)]
#[allow(dead_code)]
mod verification {
    use std::mem::ManuallyDrop;
    use std::num::Wrapping;

    use vm_memory::guest_memory::GuestMemoryIterator;
    use vm_memory::{GuestMemoryRegion, MemoryRegionAddress};

    use crate::devices::virtio::queue::{
        Descriptor, DescriptorChain, Queue, FIRECRACKER_MAX_QUEUE_SIZE, VIRTQ_DESC_F_NEXT,
    };
    use crate::vstate::memory::{Bytes, FileOffset, GuestAddress, GuestMemory, MmapRegion};

    /// A made-for-kani version of `vm_memory::GuestMemoryMmap`. Unlike the real
    /// `GuestMemoryMmap`, which manages a list of regions and then does a binary
    /// search to determine which region a specific read or write request goes to,
    /// this only uses a single region. Eliminating this binary search significantly
    /// speeds up all queue proofs, because it eliminates the only loop contained herein,
    /// meaning we can use `kani::unwind(0)` instead of `kani::unwind(2)`. Functionally,
    /// it works identically to `GuestMemoryMmap` with only a single contained region.
    pub struct ProofGuestMemory {
        the_region: vm_memory::GuestRegionMmap,
    }

    impl<'a> GuestMemoryIterator<'a, vm_memory::GuestRegionMmap> for ProofGuestMemory {
        type Iter = std::iter::Once<&'a vm_memory::GuestRegionMmap>;
    }

    impl GuestMemory for ProofGuestMemory {
        type R = vm_memory::GuestRegionMmap;
        type I = Self;

        fn num_regions(&self) -> usize {
            1
        }

        fn find_region(&self, addr: GuestAddress) -> Option<&Self::R> {
            self.the_region
                .to_region_addr(addr)
                .map(|_| &self.the_region)
        }

        fn iter(&self) -> <Self::I as GuestMemoryIterator<Self::R>>::Iter {
            std::iter::once(&self.the_region)
        }

        fn try_access<F>(
            &self,
            count: usize,
            addr: GuestAddress,
            mut f: F,
        ) -> vm_memory::guest_memory::Result<usize>
        where
            F: FnMut(
                usize,
                usize,
                MemoryRegionAddress,
                &Self::R,
            ) -> vm_memory::guest_memory::Result<usize>,
        {
            // We only have a single region, meaning a lot of the complications of the default
            // try_access implementation for dealing with reads/writes across multiple
            // regions does not apply.
            let region_addr = self
                .the_region
                .to_region_addr(addr)
                .ok_or(vm_memory::guest_memory::Error::InvalidGuestAddress(addr))?;
            self.the_region
                .checked_offset(region_addr, count)
                .ok_or(vm_memory::guest_memory::Error::InvalidGuestAddress(addr))?;
            f(0, count, region_addr, &self.the_region)
        }
    }

    pub struct ProofContext(pub Queue, pub ProofGuestMemory);

    pub struct MmapRegionStub {
        addr: *mut u8,
        size: usize,
        bitmap: (),
        file_offset: Option<FileOffset>,
        prot: i32,
        flags: i32,
        owned: bool,
        hugetlbfs: Option<bool>,
    }

    /// We start the first guest memory region at an offset so that harnesses using
    /// Queue::any() will be exposed to queue segments both before and after valid guest memory.
    const GUEST_MEMORY_BASE: u64 = 512;

    // We size our guest memory to fit a properly aligned queue, plus some wiggles bytes
    // to make sure we not only test queues where all segments are consecutively aligned.
    // We need to give at least 16 bytes of buffer space for the descriptor table to be
    // able to change its address, as it is 16-byte aligned.
    const GUEST_MEMORY_SIZE: usize = QUEUE_END as usize + 30;

    fn guest_memory(memory: *mut u8) -> ProofGuestMemory {
        // Ideally, we'd want to do
        // let region = unsafe {MmapRegionBuilder::new(GUEST_MEMORY_SIZE)
        //    .with_raw_mmap_pointer(bytes.as_mut_ptr())
        //    .build()
        //    .unwrap()};
        // However, .build() calls to .build_raw(), which contains a call to libc::sysconf.
        // Since kani 0.34.0, stubbing out foreign functions is supported, but due to the rust
        // standard library using a special version of the libc crate, it runs into some problems
        // [1] Even if we work around those problems, we run into performance problems [2].
        // Therefore, for now we stick to this ugly transmute hack (which only works because
        // the kani compiler will never re-order fields, so we can treat repr(Rust) as repr(C)).
        //
        // [1]: https://github.com/model-checking/kani/issues/2673
        // [2]: https://github.com/model-checking/kani/issues/2538
        let region_stub = MmapRegionStub {
            addr: memory,
            size: GUEST_MEMORY_SIZE,
            bitmap: Default::default(),
            file_offset: None,
            prot: 0,
            flags: libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            owned: false,
            hugetlbfs: None,
        };

        let region: MmapRegion<()> = unsafe { std::mem::transmute(region_stub) };

        let guest_region =
            vm_memory::GuestRegionMmap::new(region, GuestAddress(GUEST_MEMORY_BASE)).unwrap();

        // Use a single memory region, just as firecracker does for guests of size < 2GB
        // For largest guests, firecracker uses two regions (due to the MMIO gap being
        // at the top of 32-bit address space)
        ProofGuestMemory {
            the_region: guest_region,
        }
    }

    // can't implement kani::Arbitrary for the relevant types due to orphan rules
    fn setup_kani_guest_memory() -> ProofGuestMemory {
        // Non-deterministic Vec that will be used as the guest memory. We use `exact_vec` for now
        // as `any_vec` will likely result in worse performance. We do not loose much from
        // `exact_vec`, as our proofs do not make any assumptions about "filling" guest
        // memory: Since everything is placed at non-deterministic addresses with
        // non-deterministic lengths, we still cover all scenarios that would be covered by
        // smaller guest memory closely. We leak the memory allocated here, so that it
        // doesnt get deallocated at the end of this function. We do not explicitly
        // de-allocate, but since this is a kani proof, that does not matter.
        guest_memory(
            ManuallyDrop::new(kani::vec::exact_vec::<u8, GUEST_MEMORY_SIZE>()).as_mut_ptr(),
        )
    }

    fn setup_zeroed_guest_memory() -> ProofGuestMemory {
        guest_memory(unsafe {
            std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align_unchecked(
                GUEST_MEMORY_SIZE,
                16,
            ))
        })
    }

    // Constants describing the in-memory layout of a queue of size FIRECRACKER_MAX_SIZE starting
    // at the beginning of guest memory. These are based on Section 2.6 of the VirtIO 1.1
    // specification.
    const QUEUE_BASE_ADDRESS: u64 = GUEST_MEMORY_BASE;

    /// descriptor table has 16 bytes per entry, avail ring starts right after
    const AVAIL_RING_BASE_ADDRESS: u64 =
        QUEUE_BASE_ADDRESS + FIRECRACKER_MAX_QUEUE_SIZE as u64 * 16;

    /// Used ring starts after avail ring (which has size 6 + 2 * FIRECRACKER_MAX_QUEUE_SIZE),
    /// and needs 2 bytes of padding
    const USED_RING_BASE_ADDRESS: u64 =
        AVAIL_RING_BASE_ADDRESS + 6 + 2 * FIRECRACKER_MAX_QUEUE_SIZE as u64 + 2;

    /// The address of the first byte after the queue. Since our queue starts at guest physical
    /// address 0, this is also the size of the memory area occupied by the queue.
    /// Note that the used ring structure has size 6 + 8 * FIRECRACKER_MAX_QUEUE_SIZE
    const QUEUE_END: u64 = USED_RING_BASE_ADDRESS + 6 + 8 * FIRECRACKER_MAX_QUEUE_SIZE as u64;

    fn less_arbitrary_queue() -> Queue {
        let mut queue = Queue::new(FIRECRACKER_MAX_QUEUE_SIZE);

        queue.size = FIRECRACKER_MAX_QUEUE_SIZE;
        queue.ready = true;
        queue.desc_table = GuestAddress(QUEUE_BASE_ADDRESS);
        queue.avail_ring = GuestAddress(AVAIL_RING_BASE_ADDRESS);
        queue.used_ring = GuestAddress(USED_RING_BASE_ADDRESS);
        queue.next_avail = Wrapping(kani::any());
        queue.next_used = Wrapping(kani::any());
        queue.uses_notif_suppression = kani::any();
        queue.num_added = Wrapping(kani::any());

        queue
    }

    impl ProofContext {
        /// Creates a [`ProofContext`] where the queue layout is not arbitrary and instead
        /// fixed to a known valid one
        pub fn bounded_queue() -> Self {
            let mem = setup_kani_guest_memory();
            let queue = less_arbitrary_queue();

            assert!(queue.is_layout_valid(&mem));

            ProofContext(queue, mem)
        }

        /// Creates a [`ProofContext`] where the queue layout is fixed to a valid one and where
        /// guest memory is initialized to all zeros.
        pub fn bounded() -> Self {
            let mem = setup_zeroed_guest_memory();
            let queue = less_arbitrary_queue();

            assert!(queue.is_layout_valid(&mem));

            ProofContext(queue, mem)
        }
    }

    impl kani::Arbitrary for ProofContext {
        fn any() -> Self {
            let mem = setup_kani_guest_memory();
            let queue: Queue = kani::any();

            kani::assume(queue.is_layout_valid(&mem));

            ProofContext(queue, mem)
        }
    }

    impl kani::Arbitrary for Queue {
        fn any() -> Queue {
            // firecracker statically sets the maximal queue size to 256
            let mut queue = Queue::new(FIRECRACKER_MAX_QUEUE_SIZE);

            queue.size = kani::any();
            queue.ready = true;
            queue.desc_table = GuestAddress(kani::any());
            queue.avail_ring = GuestAddress(kani::any());
            queue.used_ring = GuestAddress(kani::any());
            queue.next_avail = Wrapping(kani::any());
            queue.next_used = Wrapping(kani::any());
            queue.uses_notif_suppression = kani::any();
            queue.num_added = Wrapping(kani::any());

            queue
        }
    }

    impl kani::Arbitrary for Descriptor {
        fn any() -> Descriptor {
            Descriptor {
                addr: kani::any(),
                len: kani::any(),
                flags: kani::any(),
                next: kani::any(),
            }
        }
    }

    mod stubs {
        use super::*;

        // Calls to set_used_ring_avail_event tend to cause memory to grow unboundedly during
        // verification. The function writes to the `avail_event` of the virtio queue, which
        // is not read from by the device. It is only intended to be used by guest.
        // Therefore, it does not affect any device functionality (e.g. its only call site,
        // try_enable_notification, will behave independently of what value was written
        // here). Thus we can stub it out with a no-op. Note that we have a separate harness
        // for set_used_ring_avail_event, to ensure the function itself is sound.
        fn set_used_ring_avail_event<M: GuestMemory>(_self: &mut Queue, _val: u16, _mem: &M) {
            // do nothing
        }
    }

    #[kani::proof]
    #[kani::unwind(0)] // There are no loops anywhere, but kani really enjoys getting stuck in std::ptr::drop_in_place.
                       // This is a compiler intrinsic that has a "dummy" implementation in stdlib that just
                       // recursively calls itself. Kani will generally unwind this recursion infinitely
    fn verify_spec_2_6_7_2() {
        // Section 2.6.7.2 deals with device-to-driver notification suppression.
        // It describes a mechanism by which the driver can tell the device that it does not
        // want notifications (IRQs) about the device finishing processing individual buffers
        // (descriptor chain heads) from the avail ring until a specific number of descriptors
        // has been processed. This is done by the driver
        // defining a "used_event" index, which tells the device "please do not notify me until
        // used.ring[used_event] has been written to by you".
        let ProofContext(mut queue, mem) = ProofContext::bounded_queue();

        let num_added_old = queue.num_added.0;
        let needs_notification = queue.prepare_kick(&mem);

        // uses_notif_suppression equivalent to VIRTIO_F_EVENT_IDX negotiated
        if !queue.uses_notif_suppression {
            // The specification here says
            // After the device writes a descriptor index into the used ring:
            // – If flags is 1, the device SHOULD NOT send a notification.
            // – If flags is 0, the device MUST send a notification
            // flags is the first field in the avail_ring, which we completely ignore. We
            // always send a notification, and as there only is a SHOULD NOT, that is okay
            assert!(needs_notification);
        } else {
            // next_used - 1 is where the previous descriptor was placed
            if queue.used_event(&mem) == queue.next_used - Wrapping(1) && num_added_old > 0 {
                // If the idx field in the used ring (which determined where that descriptor index
                // was placed) was equal to used_event, the device MUST send a
                // notification.
                assert!(needs_notification);

                kani::cover!();
            }

            // The other case is handled by a "SHOULD NOT send a notification" in the spec.
            // So we do not care
        }
    }

    #[kani::proof]
    #[kani::unwind(0)]
    fn verify_prepare_kick() {
        // Firecracker's virtio queue implementation is not completely spec conform:
        // According to the spec, we have to check whether to notify the driver after every call
        // to add_used. We don't do that. Instead, we call add_used a bunch of times (with the
        // number of added descriptors being counted in Queue.num_added), and then use
        // "prepare_kick" to check if any of those descriptors should have triggered a
        // notification.
        let ProofContext(mut queue, mem) = ProofContext::bounded_queue();

        queue.enable_notif_suppression();
        assert!(queue.uses_notif_suppression);

        // With firecracker's batching of used IRQs, we need to check if addition of the last
        // queue.num_added buffers is what caused us to cross the used_event index (e.g. if the
        // index used_event was written to since the last call to prepare_kick). We have to
        // take various ring-wrapping behavior into consideration here. This is the case if
        // used_event in [next_used - num_added, next_used - 1]. However, intervals
        // in modular arithmetic are a finicky thing, as we do not have a notion of order
        // (consider for example u16::MAX + 1 = 0. Clearly, x + 1 > x, but that would imply 0 >
        // u16::MAX) This gives us some interesting corner cases: What if our "interval" is
        // "[u16::MAX - 1, 1]"? For these "wrapped" intervals, we can instead consider
        // [next_used - num_added - 1, u16::MAX] ∪ [0, next_used - 1]. Since queue size is at most
        // 2^15, intervals can only wrap at most once. This gives us the following logic:

        let used_event = queue.used_event(&mem);
        let interval_start = queue.next_used - queue.num_added;
        let interval_end = queue.next_used - Wrapping(1);
        let needs_notification = if queue.num_added.0 == 0 {
            false
        } else if interval_start > interval_end {
            used_event <= interval_end || used_event >= interval_start
        } else {
            used_event >= interval_start && used_event <= interval_end
        };

        assert_eq!(queue.prepare_kick(&mem), needs_notification);
    }

    #[kani::proof]
    #[kani::unwind(0)]
    fn verify_is_empty() {
        let ProofContext(queue, mem) = ProofContext::bounded_queue();

        assert_eq!(queue.len(&mem) == 0, queue.is_empty(&mem));
    }

    #[kani::proof]
    #[kani::unwind(0)]
    #[kani::solver(cadical)]
    fn verify_is_valid() {
        let ProofContext(queue, mem) = kani::any();

        if queue.is_valid(&mem) {
            // Section 2.6: Alignment of descriptor table, available ring and used ring; size of
            // queue
            fn alignment_of(val: u64) -> u64 {
                if val == 0 {
                    u64::MAX
                } else {
                    val & (!val + 1)
                }
            }

            assert!(alignment_of(queue.desc_table.0) >= 16);
            assert!(alignment_of(queue.avail_ring.0) >= 2);
            assert!(alignment_of(queue.used_ring.0) >= 4);

            // length of queue must be power-of-two, and at most 2^15
            assert_eq!(queue.size.count_ones(), 1);
            assert!(queue.size <= 1u16 << 15);
        }
    }

    #[kani::proof]
    #[kani::unwind(0)]
    fn verify_actual_size() {
        let ProofContext(queue, _) = kani::any();

        assert!(queue.actual_size() <= queue.get_max_size());
        assert!(queue.actual_size() <= queue.size);
    }

    #[kani::proof]
    #[kani::unwind(0)]
    fn verify_set_used_ring_avail_event() {
        let ProofContext(mut queue, mem) = ProofContext::bounded_queue();

        queue.set_used_ring_avail_event(kani::any(), &mem);
    }

    #[kani::proof]
    #[kani::unwind(0)]
    #[kani::solver(cadical)]
    fn verify_pop() {
        let ProofContext(mut queue, mem) = ProofContext::bounded_queue();

        // This is an assertion in pop which we use to abort firecracker in a ddos scenario
        // This condition being false means that the guest is asking us to process every element
        // in the queue multiple times. It cannot be checked by is_valid, as that function
        // is called when the queue is being initialized, e.g. empty. We compute it using
        // local variables here to make things easier on kani: One less roundtrip through vm-memory.
        let queue_len = queue.len(&mem);
        kani::assume(queue_len <= queue.actual_size());

        let next_avail = queue.next_avail;

        if let Some(_) = queue.pop(&mem) {
            // Can't get anything out of an empty queue, assert queue_len != 0
            assert_ne!(queue_len, 0);
            assert_eq!(queue.next_avail, next_avail + Wrapping(1));
        }
    }

    #[kani::proof]
    #[kani::unwind(0)]
    #[kani::solver(cadical)]
    fn verify_undo_pop() {
        let ProofContext(mut queue, mem) = ProofContext::bounded_queue();

        // See verify_pop for explanation
        kani::assume(queue.len(&mem) <= queue.actual_size());

        let queue_clone = queue.clone();
        if let Some(_) = queue.pop(&mem) {
            queue.undo_pop();
            assert_eq!(queue, queue_clone);

            // TODO: can we somehow check that guest memory wasn't touched?
        }
    }

    #[kani::proof]
    #[kani::unwind(0)]
    #[kani::stub(Queue::set_used_ring_avail_event, stubs::set_used_ring_avail_event)]
    fn verify_try_enable_notification() {
        let ProofContext(mut queue, mem) = ProofContext::bounded_queue();

        kani::assume(queue.len(&mem) <= queue.actual_size());

        if queue.try_enable_notification(&mem) && queue.uses_notif_suppression {
            // We only require new notifications if the queue is empty (e.g. we've processed
            // everything we've been notified about), or if suppression is disabled.
            assert!(queue.is_empty(&mem));

            assert_eq!(queue.avail_idx(&mem), queue.next_avail)
        }
    }

    #[kani::proof]
    #[kani::unwind(0)]
    #[kani::solver(cadical)]
    fn verify_checked_new() {
        let ProofContext(queue, mem) = ProofContext::bounded_queue();

        let index = kani::any();
        let maybe_chain =
            DescriptorChain::checked_new(&mem, queue.desc_table, queue.actual_size(), index);

        if index >= queue.actual_size() {
            assert!(maybe_chain.is_none())
        } else {
            // If the index was in-bounds for the descriptor table, we at least should be
            // able to compute the address of the descriptor table entry without going out
            // of bounds anywhere, and also read from that address.
            let desc_head = mem
                .checked_offset(queue.desc_table, (index as usize) * 16)
                .unwrap();
            mem.checked_offset(desc_head, 16).unwrap();
            let desc = mem.read_obj::<Descriptor>(desc_head).unwrap();

            match maybe_chain {
                None => {
                    // This assert is the negation of the "is_valid" check in checked_new
                    assert!(desc.flags & VIRTQ_DESC_F_NEXT == 1 && desc.next >= queue.actual_size())
                }
                Some(head) => {
                    assert!(head.is_valid())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    pub use super::*;
    use crate::devices::virtio::queue::QueueError::{DescIndexOutOfBounds, UsedRing};
    use crate::devices::virtio::test_utils::{default_mem, VirtQueue};
    use crate::utilities::test_utils::{multi_region_mem, single_region_mem};
    use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

    impl Queue {
        fn avail_event(&self, mem: &GuestMemoryMmap) -> u16 {
            let avail_event_addr = self
                .used_ring
                .unchecked_add(u64::from(4 + 8 * self.actual_size()));

            mem.read_obj::<u16>(avail_event_addr).unwrap()
        }
    }

    #[test]
    fn test_checked_new_descriptor_chain() {
        let m = &multi_region_mem(&[(GuestAddress(0), 0x10000), (GuestAddress(0x20000), 0x2000)]);
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        assert!(vq.end().0 < 0x1000);

        // index >= queue_size
        assert!(DescriptorChain::checked_new(m, vq.dtable_start(), 16, 16).is_none());

        // desc_table address is way off
        assert!(DescriptorChain::checked_new(m, GuestAddress(0x00ff_ffff_ffff), 16, 0).is_none());

        // Let's create an invalid chain.
        {
            // The first desc has a normal len, and the next_descriptor flag is set.
            vq.dtable[0].addr.set(0x1000);
            vq.dtable[0].len.set(0x1000);
            vq.dtable[0].flags.set(VIRTQ_DESC_F_NEXT);
            // .. but the index of the next descriptor is too large
            vq.dtable[0].next.set(16);

            assert!(DescriptorChain::checked_new(m, vq.dtable_start(), 16, 0).is_none());
        }

        // Finally, let's test an ok chain.
        {
            vq.dtable[0].next.set(1);
            vq.dtable[1].set(0x2000, 0x1000, 0, 0);

            let c = DescriptorChain::checked_new(m, vq.dtable_start(), 16, 0).unwrap();

            assert_eq!(c.mem as *const GuestMemoryMmap, m as *const GuestMemoryMmap);
            assert_eq!(c.desc_table, vq.dtable_start());
            assert_eq!(c.queue_size, 16);
            assert_eq!(c.ttl, c.queue_size);
            assert_eq!(c.index, 0);
            assert_eq!(c.addr, GuestAddress(0x1000));
            assert_eq!(c.len, 0x1000);
            assert_eq!(c.flags, VIRTQ_DESC_F_NEXT);
            assert_eq!(c.next, 1);

            assert!(c.next_descriptor().unwrap().next_descriptor().is_none());
        }
    }

    #[test]
    fn test_queue_validation() {
        let m = &default_mem();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        let mut q = vq.create_queue();

        // q is currently valid
        assert!(q.is_valid(m));

        // shouldn't be valid when not marked as ready
        q.ready = false;
        assert!(!q.is_valid(m));
        q.ready = true;

        // or when size > max_size
        q.size = q.max_size << 1;
        assert!(!q.is_valid(m));
        q.size = q.max_size;

        // or when size is 0
        q.size = 0;
        assert!(!q.is_valid(m));
        q.size = q.max_size;

        // or when size is not a power of 2
        q.size = 11;
        assert!(!q.is_valid(m));
        q.size = q.max_size;

        // or when avail_idx - next_avail > max_size
        q.next_avail = Wrapping(5);
        assert!(!q.is_valid(m));
        // avail_ring + 2 is the address of avail_idx in guest mem
        m.write_obj::<u16>(64_u16, q.avail_ring.unchecked_add(2))
            .unwrap();
        assert!(!q.is_valid(m));
        m.write_obj::<u16>(5_u16, q.avail_ring.unchecked_add(2))
            .unwrap();
        q.max_size = 2;
        assert!(!q.is_valid(m));

        // reset dirtied values
        q.max_size = 16;
        q.next_avail = Wrapping(0);
        m.write_obj::<u16>(0, q.avail_ring.unchecked_add(2))
            .unwrap();

        // or if the various addresses are off

        q.desc_table = GuestAddress(0xffff_ffff);
        assert!(!q.is_valid(m));
        q.desc_table = GuestAddress(0x1001);
        assert!(!q.is_valid(m));
        q.desc_table = vq.dtable_start();

        q.avail_ring = GuestAddress(0xffff_ffff);
        assert!(!q.is_valid(m));
        q.avail_ring = GuestAddress(0x1001);
        assert!(!q.is_valid(m));
        q.avail_ring = vq.avail_start();

        q.used_ring = GuestAddress(0xffff_ffff);
        assert!(!q.is_valid(m));
        q.used_ring = GuestAddress(0x1001);
        assert!(!q.is_valid(m));
        q.used_ring = vq.used_start();
    }

    #[test]
    fn test_queue_processing() {
        let m = &default_mem();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);
        let mut q = vq.create_queue();

        q.ready = true;

        // Let's create two simple descriptor chains.

        for j in 0..5 {
            vq.dtable[j as usize].set(0x1000 * u64::from(j + 1), 0x1000, VIRTQ_DESC_F_NEXT, j + 1);
        }

        // the chains are (0, 1) and (2, 3, 4)
        vq.dtable[1].flags.set(0);
        vq.dtable[4].flags.set(0);
        vq.avail.ring[0].set(0);
        vq.avail.ring[1].set(2);
        vq.avail.idx.set(2);

        // We've just set up two chains.
        assert_eq!(q.len(m), 2);

        // The first chain should hold exactly two descriptors.
        let d = q.pop(m).unwrap().next_descriptor().unwrap();
        assert!(!d.has_next());
        assert!(d.next_descriptor().is_none());

        // We popped one chain, so there should be only one left.
        assert_eq!(q.len(m), 1);

        // The next chain holds three descriptors.
        let d = q
            .pop(m)
            .unwrap()
            .next_descriptor()
            .unwrap()
            .next_descriptor()
            .unwrap();
        assert!(!d.has_next());
        assert!(d.next_descriptor().is_none());

        // We've popped both chains, so the queue should be empty.
        assert!(q.is_empty(m));
        assert!(q.pop(m).is_none());

        // Undoing the last pop should let us walk the last chain again.
        q.undo_pop();
        assert_eq!(q.len(m), 1);

        // Walk the last chain again (three descriptors).
        let d = q
            .pop(m)
            .unwrap()
            .next_descriptor()
            .unwrap()
            .next_descriptor()
            .unwrap();
        assert!(!d.has_next());
        assert!(d.next_descriptor().is_none());

        // Undoing the last pop should let us walk the last chain again.
        q.undo_pop();
        assert_eq!(q.len(m), 1);

        // Walk the last chain again (three descriptors) using pop_or_enable_notification().
        let d = q
            .pop_or_enable_notification(m)
            .unwrap()
            .next_descriptor()
            .unwrap()
            .next_descriptor()
            .unwrap();
        assert!(!d.has_next());
        assert!(d.next_descriptor().is_none());

        // There are no more descriptors, but notification suppression is disabled.
        // Calling pop_or_enable_notification() should simply return None.
        assert_eq!(q.avail_event(m), 0);
        assert!(q.pop_or_enable_notification(m).is_none());
        assert_eq!(q.avail_event(m), 0);

        // There are no more descriptors and notification suppression is enabled. Calling
        // pop_or_enable_notification() should enable notifications.
        q.enable_notif_suppression();
        assert!(q.pop_or_enable_notification(m).is_none());
        assert_eq!(q.avail_event(m), 2);
    }

    #[test]
    #[should_panic(
        expected = "The number of available virtio descriptors 5 is greater than queue size: 4!"
    )]
    fn test_invalid_avail_idx_no_notification() {
        // This test ensures constructing a descriptor chain succeeds
        // with valid available ring indexes while it produces an error with invalid
        // indexes.
        // No notification suppression enabled.
        let m = &single_region_mem(0x6000);

        // We set up a queue of size 4.
        let vq = VirtQueue::new(GuestAddress(0), m, 4);
        let mut q = vq.create_queue();

        for j in 0..4 {
            vq.dtable[j as usize].set(0x1000 * u64::from(j + 1), 0x1000, VIRTQ_DESC_F_NEXT, j + 1);
        }

        // Create 2 descriptor chains.
        // the chains are (0, 1) and (2, 3)
        vq.dtable[1].flags.set(0);
        vq.dtable[3].flags.set(0);
        vq.avail.ring[0].set(0);
        vq.avail.ring[1].set(2);
        vq.avail.idx.set(2);

        // We've just set up two chains.
        assert_eq!(q.len(m), 2);

        // We process the first descriptor.
        let d = q.pop(m).unwrap().next_descriptor();
        assert!(matches!(d, Some(x) if !x.has_next()));
        // We confuse the device and set the available index as being 6.
        vq.avail.idx.set(6);

        // We've actually just popped a descriptor so 6 - 1 = 5.
        assert_eq!(q.len(m), 5);

        // However, since the apparent length set by the driver is more than the queue size,
        // we would be running the risk of going through some descriptors more than once.
        // As such, we expect to panic.
        q.pop(m);
    }

    #[test]
    #[should_panic(
        expected = "The number of available virtio descriptors 6 is greater than queue size: 4!"
    )]
    fn test_invalid_avail_idx_with_notification() {
        // This test ensures constructing a descriptor chain succeeds
        // with valid available ring indexes while it produces an error with invalid
        // indexes.
        // Notification suppression is enabled.
        let m = &single_region_mem(0x6000);

        // We set up a queue of size 4.
        let vq = VirtQueue::new(GuestAddress(0), m, 4);
        let mut q = vq.create_queue();

        q.uses_notif_suppression = true;

        // Create 1 descriptor chain of 4.
        for j in 0..4 {
            vq.dtable[j as usize].set(0x1000 * u64::from(j + 1), 0x1000, VIRTQ_DESC_F_NEXT, j + 1);
        }
        // We need to clear the VIRTQ_DESC_F_NEXT for the last descriptor.
        vq.dtable[3].flags.set(0);
        vq.avail.ring[0].set(0);

        // driver sets available index to suspicious value.
        vq.avail.idx.set(6);

        q.pop_or_enable_notification(m);
    }

    #[test]
    fn test_add_used() {
        let m = &default_mem();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        let mut q = vq.create_queue();
        assert_eq!(vq.used.idx.get(), 0);

        // Valid queue addresses configuration
        {
            // index too large
            match q.add_used(m, 16, 0x1000) {
                Err(DescIndexOutOfBounds(16)) => (),
                _ => unreachable!(),
            }

            // should be ok
            q.add_used(m, 1, 0x1000).unwrap();
            assert_eq!(vq.used.idx.get(), 1);
            let x = vq.used.ring[0].get();
            assert_eq!(x.id, 1);
            assert_eq!(x.len, 0x1000);
        }
    }

    #[test]
    fn test_used_event() {
        let m = &default_mem();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        let q = vq.create_queue();
        assert_eq!(q.used_event(m), Wrapping(0));

        vq.avail.event.set(10);
        assert_eq!(q.used_event(m), Wrapping(10));

        vq.avail.event.set(u16::MAX);
        assert_eq!(q.used_event(m), Wrapping(u16::MAX));
    }

    #[test]
    fn test_set_used_ring_avail_event() {
        let m = &default_mem();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        let mut q = vq.create_queue();
        assert_eq!(vq.used.event.get(), 0);

        q.set_used_ring_avail_event(10, m);
        assert_eq!(vq.used.event.get(), 10);

        q.set_used_ring_avail_event(u16::MAX, m);
        assert_eq!(vq.used.event.get(), u16::MAX);
    }

    #[test]
    fn test_needs_kick() {
        let m = &default_mem();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);
        let mut q = vq.create_queue();

        {
            // If the device doesn't have notification suppression support,
            // `needs_notification()` should always return true.
            q.uses_notif_suppression = false;
            for used_idx in 0..10 {
                for used_event in 0..10 {
                    for num_added in 0..10 {
                        q.next_used = Wrapping(used_idx);
                        vq.avail.event.set(used_event);
                        q.num_added = Wrapping(num_added);
                        assert!(q.prepare_kick(m));
                    }
                }
            }
        }

        q.enable_notif_suppression();
        {
            // old used idx < used_event < next_used
            q.next_used = Wrapping(10);
            vq.avail.event.set(6);
            q.num_added = Wrapping(5);
            assert!(q.prepare_kick(m));
        }

        {
            // old used idx = used_event < next_used
            q.next_used = Wrapping(10);
            vq.avail.event.set(6);
            q.num_added = Wrapping(4);
            assert!(q.prepare_kick(m));
        }

        {
            // used_event < old used idx < next_used
            q.next_used = Wrapping(10);
            vq.avail.event.set(6);
            q.num_added = Wrapping(3);
            assert!(!q.prepare_kick(m));
        }
    }

    #[test]
    fn test_try_enable_notification() {
        let m = &default_mem();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);
        let mut q = vq.create_queue();

        q.ready = true;

        // We create a simple descriptor chain
        vq.dtable[0].set(0x1000_u64, 0x1000, 0, 0);
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);

        assert_eq!(q.len(m), 1);

        // Notification suppression is disabled. try_enable_notification shouldn't do anything.
        assert!(q.try_enable_notification(m));
        assert_eq!(q.avail_event(m), 0);

        // Enable notification suppression and check again. There is 1 available descriptor chain.
        // Again nothing should happen.
        q.enable_notif_suppression();
        assert!(!q.try_enable_notification(m));
        assert_eq!(q.avail_event(m), 0);

        // Consume the descriptor. avail_event should be modified
        assert!(q.pop(m).is_some());
        assert!(q.try_enable_notification(m));
        assert_eq!(q.avail_event(m), 1);
    }

    #[test]
    fn test_queue_error_display() {
        let err = UsedRing(vm_memory::GuestMemoryError::InvalidGuestAddress(
            GuestAddress(0),
        ));
        let _ = format!("{}{:?}", err, err);

        let err = DescIndexOutOfBounds(1);
        let _ = format!("{}{:?}", err, err);
    }
}
