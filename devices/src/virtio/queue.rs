// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::num::Wrapping;
use std::sync::atomic::{fence, Ordering};

use sys_util::{GuestAddress, GuestMemory};

const VIRTQ_DESC_F_NEXT: u16 = 0x1;
const VIRTQ_DESC_F_WRITE: u16 = 0x2;

/// A virtio descriptor chain.
pub struct DescriptorChain<'a> {
    mem: &'a GuestMemory,
    desc_table: GuestAddress,
    queue_size: u16,
    ttl: u16, // used to prevent infinite chain cycles

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

impl<'a> DescriptorChain<'a> {
    fn checked_new(
        mem: &GuestMemory,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
    ) -> Option<DescriptorChain> {
        if index >= queue_size {
            return None;
        }

        let desc_head = match mem.checked_offset(desc_table, (index as usize) * 16) {
            Some(a) => a,
            None => return None,
        };
        // These reads can't fail unless Guest memory is hopelessly broken.
        let addr = GuestAddress(mem.read_obj_from_addr::<u64>(desc_head).unwrap() as usize);
        if mem.checked_offset(desc_head, 16).is_none() {
            return None;
        }
        let len: u32 = mem.read_obj_from_addr(desc_head.unchecked_add(8)).unwrap();
        let flags: u16 = mem.read_obj_from_addr(desc_head.unchecked_add(12)).unwrap();
        let next: u16 = mem.read_obj_from_addr(desc_head.unchecked_add(14)).unwrap();
        let chain = DescriptorChain {
            mem: mem,
            desc_table: desc_table,
            queue_size: queue_size,
            ttl: queue_size,
            index: index,
            addr: addr,
            len: len,
            flags: flags,
            next: next,
        };

        if chain.is_valid() {
            Some(chain)
        } else {
            None
        }
    }

    fn is_valid(&self) -> bool {
        if self.mem
            .checked_offset(self.addr, self.len as usize)
            .is_none()
        {
            false
        } else if self.has_next() && self.next >= self.queue_size {
            false
        } else {
            true
        }
    }

    /// Gets if this descriptor chain has another descriptor chain linked after it.
    pub fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0 && self.ttl > 1
    }

    /// If the driver designated this as a write only descriptor.
    ///
    /// If this is false, this descriptor is read only.
    /// Write only means the the emulated device can write and the driver can read.
    pub fn is_write_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    /// Gets the next descriptor in this descriptor chain, if there is one.
    ///
    /// Note that this is distinct from the next descriptor chain returned by `AvailIter`, which is
    /// the head of the next _available_ descriptor chain.
    pub fn next_descriptor(&self) -> Option<DescriptorChain<'a>> {
        if self.has_next() {
            DescriptorChain::checked_new(self.mem, self.desc_table, self.queue_size, self.next)
                .map(|mut c| {
                    c.ttl = self.ttl - 1;
                    c
                })
        } else {
            None
        }
    }
}

/// Consuming iterator over all available descriptor chain heads in the queue.
pub struct AvailIter<'a, 'b> {
    mem: &'a GuestMemory,
    desc_table: GuestAddress,
    avail_ring: GuestAddress,
    next_index: Wrapping<u16>,
    last_index: Wrapping<u16>,
    queue_size: u16,
    next_avail: &'b mut Wrapping<u16>,
}

impl<'a, 'b> Iterator for AvailIter<'a, 'b> {
    type Item = DescriptorChain<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index == self.last_index {
            return None;
        }

        let offset = (4 + (self.next_index.0 % self.queue_size) * 2) as usize;
        let avail_addr = match self.mem.checked_offset(self.avail_ring, offset) {
            Some(a) => a,
            None => return None,
        };
        // This index is checked below in checked_new
        let desc_index: u16 = self.mem.read_obj_from_addr(avail_addr).unwrap();

        self.next_index += Wrapping(1);

        let ret =
            DescriptorChain::checked_new(self.mem, self.desc_table, self.queue_size, desc_index);
        if ret.is_some() {
            *self.next_avail += Wrapping(1);
        }
        ret
    }
}

#[derive(Clone)]
/// A virtio queue's parameters.
pub struct Queue {
    /// The maximal size in elements offered by the device
    max_size: u16,

    /// The queue size in elements the driver selected
    pub size: u16,

    /// Inidcates if the queue is finished with configuration
    pub ready: bool,

    /// Guest physical address of the descriptor table
    pub desc_table: GuestAddress,

    /// Guest physical address of the available ring
    pub avail_ring: GuestAddress,

    /// Guest physical address of the used ring
    pub used_ring: GuestAddress,

    next_avail: Wrapping<u16>,
    next_used: Wrapping<u16>,
}

impl Queue {
    /// Constructs an empty virtio queue with the given `max_size`.
    pub fn new(max_size: u16) -> Queue {
        Queue {
            max_size: max_size,
            size: 0,
            ready: false,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
        }
    }

    pub fn get_max_size(&self) -> u16 {
        self.max_size
    }

    /// Return the actual size of the queue, as the driver may not set up a
    /// queue as big as the device allows.
    pub fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    pub fn is_valid(&self, mem: &GuestMemory) -> bool {
        let queue_size = self.actual_size() as usize;
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
        } else if desc_table
            .checked_add(desc_table_size)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue descriptor table goes out of bounds: start:0x{:08x} size:0x{:08x}",
                desc_table.offset(),
                desc_table_size
            );
            false
        } else if avail_ring
            .checked_add(avail_ring_size)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue available ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                avail_ring.offset(),
                avail_ring_size
            );
            false
        } else if used_ring
            .checked_add(used_ring_size)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue used ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                used_ring.offset(),
                used_ring_size
            );
            false
        } else {
            true
        }
    }

    /// A consuming iterator over all available descriptor chain heads offered by the driver.
    pub fn iter<'a, 'b>(&'b mut self, mem: &'a GuestMemory) -> AvailIter<'a, 'b> {
        if !self.is_valid(mem) {
            return AvailIter {
                mem: mem,
                desc_table: GuestAddress(0),
                avail_ring: GuestAddress(0),
                next_index: Wrapping(0),
                last_index: Wrapping(0),
                queue_size: 0,
                next_avail: &mut self.next_avail,
            };
        }
        let queue_size = self.actual_size();
        let avail_ring = self.avail_ring;

        let index_addr = mem.checked_offset(avail_ring, 2).unwrap();
        // Note that last_index has no invalid values
        let last_index: u16 = mem.read_obj_from_addr::<u16>(index_addr).unwrap();

        AvailIter {
            mem: mem,
            desc_table: self.desc_table,
            avail_ring: avail_ring,
            next_index: self.next_avail,
            last_index: Wrapping(last_index),
            queue_size: queue_size,
            next_avail: &mut self.next_avail,
        }
    }

    /// Puts an available descriptor head into the used ring for use by the guest.
    pub fn add_used(&mut self, mem: &GuestMemory, desc_index: u16, len: u32) {
        if desc_index >= self.actual_size() {
            error!(
                "attempted to add out of bounds descriptor to used ring: {}",
                desc_index
            );
            return;
        }

        let used_ring = self.used_ring;
        let next_used = (self.next_used.0 % self.actual_size()) as usize;
        let used_elem = used_ring.unchecked_add(4 + next_used * 8);

        // These writes can't fail as we are guaranteed to be within the descriptor ring.
        mem.write_obj_at_addr(desc_index as u32, used_elem).unwrap();
        mem.write_obj_at_addr(len as u32, used_elem.unchecked_add(4))
            .unwrap();

        self.next_used += Wrapping(1);

        // This fence ensures all descriptor writes are visible before the index update is.
        fence(Ordering::Release);

        mem.write_obj_at_addr(self.next_used.0 as u16, used_ring.unchecked_add(2))
            .unwrap();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate data_model;

    use std::marker::PhantomData;
    use std::mem;

    pub use super::*;
    use sys_util::{GuestAddress, GuestMemory};

    // Represents a location in GuestMemory which holds a given type.
    pub struct SomeplaceInMemory<'a, T> {
        pub location: GuestAddress,
        mem: &'a GuestMemory,
        phantom: PhantomData<*const T>,
    }

    // The DataInit trait is required to use mem.read_obj_from_addr and write_obj_at_addr.
    impl<'a, T> SomeplaceInMemory<'a, T>
    where
        T: data_model::DataInit,
    {
        fn new(location: GuestAddress, mem: &'a GuestMemory) -> Self {
            SomeplaceInMemory {
                location,
                mem,
                phantom: PhantomData,
            }
        }

        // Reads from the actual memory location.
        pub fn get(&self) -> T {
            self.mem.read_obj_from_addr(self.location).unwrap()
        }

        // Writes to the actual memory location.
        pub fn set(&self, val: T) {
            self.mem.write_obj_at_addr(val, self.location).unwrap()
        }

        // This function returns a place in memory which holds a value of type U, and starts
        // offset bytes after the current location.
        fn map_offset<U>(&self, offset: usize) -> SomeplaceInMemory<'a, U> {
            SomeplaceInMemory {
                location: self.location.checked_add(offset).unwrap(),
                mem: self.mem,
                phantom: PhantomData,
            }
        }

        // This function returns a place in memory which holds a value of type U, and starts
        // immediately after the end of self (which is location + sizeof(T)).
        fn next_place<U>(&self) -> SomeplaceInMemory<'a, U> {
            self.map_offset::<U>(mem::size_of::<T>())
        }

        fn end(&self) -> GuestAddress {
            self.location.checked_add(mem::size_of::<T>()).unwrap()
        }
    }

    // Represents a virtio descriptor in guest memory.
    pub struct VirtqDesc<'a> {
        pub addr: SomeplaceInMemory<'a, u64>,
        pub len: SomeplaceInMemory<'a, u32>,
        pub flags: SomeplaceInMemory<'a, u16>,
        pub next: SomeplaceInMemory<'a, u16>,
    }

    impl<'a> VirtqDesc<'a> {
        fn new(start: GuestAddress, mem: &'a GuestMemory) -> Self {
            assert_eq!(start.0 & 0xf, 0);

            let addr = SomeplaceInMemory::new(start, mem);
            let len = addr.next_place();
            let flags = len.next_place();
            let next = flags.next_place();

            VirtqDesc {
                addr,
                len,
                flags,
                next,
            }
        }

        fn start(&self) -> GuestAddress {
            self.addr.location
        }

        fn end(&self) -> GuestAddress {
            self.next.end()
        }

        pub fn set(&self, addr: u64, len: u32, flags: u16, next: u16) {
            self.addr.set(addr);
            self.len.set(len);
            self.flags.set(flags);
            self.next.set(next);
        }
    }

    // Represents a virtio queue ring. The only difference between the used and available rings,
    // is the ring element type.
    pub struct VirtqRing<'a, T> {
        pub flags: SomeplaceInMemory<'a, u16>,
        pub idx: SomeplaceInMemory<'a, u16>,
        pub ring: Vec<SomeplaceInMemory<'a, T>>,
        pub event: SomeplaceInMemory<'a, u16>,
    }

    impl<'a, T> VirtqRing<'a, T>
    where
        T: data_model::DataInit,
    {
        fn new(start: GuestAddress, mem: &'a GuestMemory, qsize: u16, alignment: usize) -> Self {
            assert_eq!(start.0 & (alignment - 1), 0);

            let flags = SomeplaceInMemory::new(start, mem);
            let idx = flags.next_place();

            let mut ring = Vec::with_capacity(qsize as usize);

            ring.push(idx.next_place());

            for _ in 1..qsize as usize {
                let x = ring.last().unwrap().next_place();
                ring.push(x)
            }

            let event = ring.last().unwrap().next_place();

            flags.set(0);
            idx.set(0);
            event.set(0);

            VirtqRing {
                flags,
                idx,
                ring,
                event,
            }
        }

        pub fn end(&self) -> GuestAddress {
            self.event.end()
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct VirtqUsedElem {
        pub id: u32,
        pub len: u32,
    }

    unsafe impl data_model::DataInit for VirtqUsedElem {}

    pub type VirtqAvail<'a> = VirtqRing<'a, u16>;
    pub type VirtqUsed<'a> = VirtqRing<'a, VirtqUsedElem>;

    pub struct VirtQueue<'a> {
        pub dtable: Vec<VirtqDesc<'a>>,
        pub avail: VirtqAvail<'a>,
        pub used: VirtqUsed<'a>,
    }

    impl<'a> VirtQueue<'a> {
        // We try to make sure things are aligned properly :-s
        pub fn new(start: GuestAddress, mem: &'a GuestMemory, qsize: u16) -> Self {
            // power of 2?
            assert!(qsize > 0 && qsize & qsize - 1 == 0);

            let mut dtable = Vec::with_capacity(qsize as usize);

            let mut end = start;

            for _ in 0..qsize {
                let d = VirtqDesc::new(end, mem);
                end = d.end();
                dtable.push(d);
            }

            const AVAIL_ALIGN: usize = 2;

            let avail = VirtqAvail::new(end, mem, qsize, AVAIL_ALIGN);

            const USED_ALIGN: usize = 4;

            let mut x = avail.end().0;
            x = (x + USED_ALIGN - 1) & !(USED_ALIGN - 1);

            let used = VirtqUsed::new(GuestAddress(x), mem, qsize, USED_ALIGN);

            VirtQueue {
                dtable,
                avail,
                used,
            }
        }

        fn size(&self) -> u16 {
            self.dtable.len() as u16
        }

        fn dtable_start(&self) -> GuestAddress {
            self.dtable.first().unwrap().start()
        }

        fn avail_start(&self) -> GuestAddress {
            self.avail.flags.location
        }

        fn used_start(&self) -> GuestAddress {
            self.used.flags.location
        }

        // Creates a new Queue, using the underlying memory regions represented by the VirtQueue.
        pub fn create_queue(&self) -> Queue {
            let mut q = Queue::new(self.size());

            q.size = self.size();
            q.ready = true;
            q.desc_table = self.dtable_start();
            q.avail_ring = self.avail_start();
            q.used_ring = self.used_start();

            q
        }

        pub fn start(&self) -> GuestAddress {
            self.dtable_start()
        }

        pub fn end(&self) -> GuestAddress {
            self.used.end()
        }
    }
}
