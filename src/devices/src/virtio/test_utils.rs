// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::virtio::{Queue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

#[macro_export]
macro_rules! check_metric_after_block {
    ($metric:expr, $delta:expr, $block:expr) => {{
        let before = $metric.count();
        let _ = $block;
        assert_eq!($metric.count(), before + $delta, "unexpected metric value");
    }};
}

pub fn default_mem() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
}

pub fn initialize_virtqueue(vq: &VirtQueue) {
    let request_type_desc: usize = 0;
    let data_desc: usize = 1;
    let status_desc: usize = 2;

    let request_addr: u64 = 0x1000;
    let data_addr: u64 = 0x2000;
    let status_addr: u64 = 0x3000;
    let len = 0x1000;

    // Set the request type descriptor.
    vq.avail.ring[request_type_desc].set(request_type_desc as u16);
    vq.dtable[request_type_desc].set(request_addr, len, VIRTQ_DESC_F_NEXT, data_desc as u16);

    // Set the data descriptor.
    vq.avail.ring[data_desc].set(data_desc as u16);
    vq.dtable[data_desc].set(
        data_addr,
        len,
        VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
        status_desc as u16,
    );

    // Set the status descriptor.
    vq.avail.ring[status_desc].set(status_desc as u16);
    vq.dtable[status_desc].set(
        status_addr,
        len,
        VIRTQ_DESC_F_WRITE,
        (status_desc + 1) as u16,
    );

    // Mark the next available descriptor.
    vq.avail.idx.set(1);
}

pub struct InputData {
    pub data: Vec<u8>,
    pub read_pos: AtomicUsize,
}

impl InputData {
    pub fn get_slice(&self, len: usize) -> &[u8] {
        let old_pos = self.read_pos.fetch_add(len, Ordering::AcqRel);
        &self.data[old_pos..old_pos + len]
    }
}

// Represents a location in GuestMemoryMmap which holds a given type.
pub struct SomeplaceInMemory<'a, T> {
    pub location: GuestAddress,
    mem: &'a GuestMemoryMmap,
    phantom: PhantomData<*const T>,
}

// The ByteValued trait is required to use mem.read_obj_from_addr and write_obj_at_addr.
impl<'a, T> SomeplaceInMemory<'a, T>
where
    T: vm_memory::ByteValued,
{
    fn new(location: GuestAddress, mem: &'a GuestMemoryMmap) -> Self {
        SomeplaceInMemory {
            location,
            mem,
            phantom: PhantomData,
        }
    }

    // Reads from the actual memory location.
    pub fn get(&self) -> T {
        self.mem.read_obj(self.location).unwrap()
    }

    // Writes to the actual memory location.
    pub fn set(&self, val: T) {
        self.mem.write_obj(val, self.location).unwrap()
    }

    // This function returns a place in memory which holds a value of type U, and starts
    // offset bytes after the current location.
    fn map_offset<U>(&self, offset: usize) -> SomeplaceInMemory<'a, U> {
        SomeplaceInMemory {
            location: self.location.checked_add(offset as u64).unwrap(),
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
        self.location
            .checked_add(mem::size_of::<T>() as u64)
            .unwrap()
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
    pub const ALIGNMENT: u64 = 16;

    fn new(start: GuestAddress, mem: &'a GuestMemoryMmap) -> Self {
        assert_eq!(start.0 & (Self::ALIGNMENT - 1), 0);

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

    pub fn check_data(&self, expected_data: &[u8]) {
        assert!(self.len.get() as usize >= expected_data.len());
        let mem = self.addr.mem;
        let mut buf = vec![0; expected_data.len() as usize];
        assert!(mem
            .read_slice(&mut buf, GuestAddress::new(self.addr.get()))
            .is_ok());
        assert_eq!(buf.as_slice(), expected_data);
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
    T: vm_memory::ByteValued,
{
    fn new(start: GuestAddress, mem: &'a GuestMemoryMmap, qsize: u16, alignment: usize) -> Self {
        assert_eq!(start.0 & (alignment as u64 - 1), 0);

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
#[derive(Clone, Copy, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

unsafe impl vm_memory::ByteValued for VirtqUsedElem {}

pub type VirtqAvail<'a> = VirtqRing<'a, u16>;
pub type VirtqUsed<'a> = VirtqRing<'a, VirtqUsedElem>;

pub struct VirtQueue<'a> {
    pub dtable: Vec<VirtqDesc<'a>>,
    pub avail: VirtqAvail<'a>,
    pub used: VirtqUsed<'a>,
}

impl<'a> VirtQueue<'a> {
    // We try to make sure things are aligned properly :-s
    pub fn new(start: GuestAddress, mem: &'a GuestMemoryMmap, qsize: u16) -> Self {
        // power of 2?
        assert!(qsize > 0 && qsize & (qsize - 1) == 0);

        let mut dtable = Vec::with_capacity(qsize as usize);

        let mut end = start;

        for _ in 0..qsize {
            let d = VirtqDesc::new(end, mem);
            end = d.end();
            dtable.push(d);
        }

        const AVAIL_ALIGN: usize = 2;

        let avail = VirtqAvail::new(end, mem, qsize, AVAIL_ALIGN);

        const USED_ALIGN: u64 = 4;

        let mut x = avail.end().0;
        x = (x + USED_ALIGN - 1) & !(USED_ALIGN - 1);

        let used = VirtqUsed::new(GuestAddress(x), mem, qsize, USED_ALIGN as usize);

        VirtQueue {
            dtable,
            avail,
            used,
        }
    }

    pub fn size(&self) -> u16 {
        self.dtable.len() as u16
    }

    pub fn dtable_start(&self) -> GuestAddress {
        self.dtable.first().unwrap().start()
    }

    pub fn avail_start(&self) -> GuestAddress {
        self.avail.flags.location
    }

    pub fn used_start(&self) -> GuestAddress {
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

    pub fn check_used_elem(&self, used_index: u16, expected_id: u16, expected_len: u32) {
        let used_elem = self.used.ring[used_index as usize].get();
        assert_eq!(used_elem.id, expected_id as u32);
        assert_eq!(used_elem.len, expected_len);
    }
}
