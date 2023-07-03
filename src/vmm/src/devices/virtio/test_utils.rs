// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc(hidden)]

use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};

use utils::vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

use crate::devices::virtio::Queue;

#[macro_export]
macro_rules! check_metric_after_block {
    ($metric:expr, $delta:expr, $block:expr) => {{
        let before = $metric.count();
        let _ = $block;
        assert_eq!($metric.count(), before + $delta, "unexpected metric value");
    }};
}

/// Creates a [`GuestMemoryMmap`] with a single region of the given size starting at guest physical
/// address 0
pub fn single_region_mem(region_size: usize) -> GuestMemoryMmap {
    utils::vm_memory::test_utils::create_anon_guest_memory(&[(GuestAddress(0), region_size)], false)
        .unwrap()
}

/// Creates a [`GuestMemoryMmap`] with a single region  of size 65536 (= 0x10000 hex) starting at
/// guest physical address 0
pub fn default_mem() -> GuestMemoryMmap {
    single_region_mem(0x10000)
}

#[derive(Debug)]
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
#[derive(Debug)]
pub struct SomeplaceInMemory<'a, T> {
    pub location: GuestAddress,
    mem: &'a GuestMemoryMmap,
    phantom: PhantomData<*const T>,
}

// The ByteValued trait is required to use mem.read_obj_from_addr and write_obj_at_addr.
impl<'a, T> SomeplaceInMemory<'a, T>
where
    T: Debug + utils::vm_memory::ByteValued,
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
    fn map_offset<U: Debug>(&self, offset: usize) -> SomeplaceInMemory<'a, U> {
        SomeplaceInMemory {
            location: self.location.checked_add(offset as u64).unwrap(),
            mem: self.mem,
            phantom: PhantomData,
        }
    }

    // This function returns a place in memory which holds a value of type U, and starts
    // immediately after the end of self (which is location + sizeof(T)).
    fn next_place<U: Debug>(&self) -> SomeplaceInMemory<'a, U> {
        self.map_offset::<U>(mem::size_of::<T>())
    }

    fn end(&self) -> GuestAddress {
        self.location
            .checked_add(mem::size_of::<T>() as u64)
            .unwrap()
    }
}

// Represents a virtio descriptor in guest memory.
#[derive(Debug)]
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

    pub fn memory(&self) -> &'a GuestMemoryMmap {
        self.addr.mem
    }

    pub fn set_data(&mut self, data: &[u8]) {
        assert!(self.len.get() as usize >= data.len());
        let mem = self.addr.mem;
        assert!(mem
            .write_slice(data, GuestAddress::new(self.addr.get()))
            .is_ok());
    }

    pub fn check_data(&self, expected_data: &[u8]) {
        assert!(self.len.get() as usize >= expected_data.len());
        let mem = self.addr.mem;
        let mut buf = vec![0; expected_data.len()];
        assert!(mem
            .read_slice(&mut buf, GuestAddress::new(self.addr.get()))
            .is_ok());
        assert_eq!(buf.as_slice(), expected_data);
    }
}

// Represents a virtio queue ring. The only difference between the used and available rings,
// is the ring element type.
#[derive(Debug)]
pub struct VirtqRing<'a, T> {
    pub flags: SomeplaceInMemory<'a, u16>,
    pub idx: SomeplaceInMemory<'a, u16>,
    pub ring: Vec<SomeplaceInMemory<'a, T>>,
    pub event: SomeplaceInMemory<'a, u16>,
}

impl<'a, T> VirtqRing<'a, T>
where
    T: Debug + utils::vm_memory::ByteValued,
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
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

// SAFETY: `VirtqUsedElem` is a POD and contains no padding.
unsafe impl utils::vm_memory::ByteValued for VirtqUsedElem {}

pub type VirtqAvail<'a> = VirtqRing<'a, u16>;
pub type VirtqUsed<'a> = VirtqRing<'a, VirtqUsedElem>;

#[derive(Debug)]
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

    pub fn memory(&self) -> &'a GuestMemoryMmap {
        self.used.flags.mem
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
        assert_eq!(used_elem.id, u32::from(expected_id));
        assert_eq!(used_elem.len, expected_len);
    }
}

#[cfg(test)]
pub(crate) mod test {

    use std::fmt::{self, Debug};
    use std::sync::{Arc, Mutex, MutexGuard};

    use event_manager::{EventManager, MutEventSubscriber, SubscriberId, SubscriberOps};
    use utils::vm_memory::{Address, GuestAddress, GuestMemoryMmap};

    use crate::devices::virtio::test_utils::{VirtQueue, VirtqDesc};
    use crate::devices::virtio::{Queue, VirtioDevice, MAX_BUFFER_SIZE, VIRTQ_DESC_F_NEXT};

    pub fn create_virtio_mem() -> GuestMemoryMmap {
        utils::vm_memory::test_utils::create_guest_memory_unguarded(
            &[(GuestAddress(0), MAX_BUFFER_SIZE)],
            false,
        )
        .unwrap()
    }

    /// Provides functionality necessary for testing a VirtIO device with
    /// [`VirtioTestHelper`](VirtioTestHelper)
    pub trait VirtioTestDevice: VirtioDevice {
        /// Replace the queues used by the device
        fn set_queues(&mut self, queues: Vec<Queue>);
        /// Number of queues this device supports
        fn num_queues() -> usize;
    }

    /// A helper type to allow testing VirtIO devices
    ///
    /// `VirtioTestHelper` provides functionality to allow testing a VirtIO device by
    /// 1. Emulating the guest size of things (essentially the handling of Virtqueues) and
    /// 2. Emulating an event loop that handles device specific events
    ///
    /// It creates and handles a guest memory address space, which uses for keeping the
    /// Virtqueues of the device and storing data, i.e. storing data described by DescriptorChains
    /// that the guest would pass to the device during normal operation
    pub struct VirtioTestHelper<'a, T>
    where
        T: VirtioTestDevice + MutEventSubscriber,
    {
        event_manager: EventManager<Arc<Mutex<T>>>,
        _subscriber_id: SubscriberId,
        device: Arc<Mutex<T>>,
        virtqueues: Vec<VirtQueue<'a>>,
    }

    impl<T: VirtioTestDevice + MutEventSubscriber + Debug> fmt::Debug for VirtioTestHelper<'_, T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("VirtioTestHelper")
                .field("event_manager", &"?")
                .field("_subscriber_id", &self._subscriber_id)
                .field("device", &self.device)
                .field("virtqueues", &self.virtqueues)
                .finish()
        }
    }

    impl<'a, T> VirtioTestHelper<'a, T>
    where
        T: VirtioTestDevice + MutEventSubscriber + Debug,
    {
        const QUEUE_SIZE: u16 = 16;

        // Helper function to create a set of Virtqueues for the device
        fn create_virtqueues(mem: &'a GuestMemoryMmap, num_queues: usize) -> Vec<VirtQueue> {
            (0..num_queues)
                .scan(GuestAddress(0), |next_addr, _| {
                    let vqueue = VirtQueue::new(*next_addr, mem, Self::QUEUE_SIZE);
                    // Address for the next virt queue will be the first aligned address after
                    // the end of this one.
                    *next_addr = vqueue.end().unchecked_align_up(VirtqDesc::ALIGNMENT);
                    Some(vqueue)
                })
                .collect::<Vec<_>>()
        }

        /// Create a new Virtio Device test helper
        pub fn new(mem: &'a GuestMemoryMmap, mut device: T) -> VirtioTestHelper<'a, T> {
            let mut event_manager = EventManager::new().unwrap();

            let virtqueues = Self::create_virtqueues(mem, T::num_queues());
            let queues = virtqueues.iter().map(|vq| vq.create_queue()).collect();
            device.set_queues(queues);
            let device = Arc::new(Mutex::new(device));
            let _subscriber_id = event_manager.add_subscriber(device.clone());

            Self {
                event_manager,
                _subscriber_id,
                device,
                virtqueues,
            }
        }

        /// Get a (locked) reference to the device
        pub fn device(&mut self) -> MutexGuard<T> {
            self.device.lock().unwrap()
        }

        /// Activate the device
        pub fn activate_device(&mut self, mem: &'a GuestMemoryMmap) {
            self.device.lock().unwrap().activate(mem.clone()).unwrap();
            // Process the activate event
            let ev_count = self.event_manager.run_with_timeout(100).unwrap();
            assert_eq!(ev_count, 1);
        }

        /// Get the start of the data region
        ///
        /// The first address that can be used for data in the guest memory mmap
        /// is the first address after the memory occupied by the last Virtqueue
        /// used by the device
        pub fn data_address(&self) -> u64 {
            self.virtqueues.last().unwrap().end().raw_value()
        }

        /// Add a new Descriptor in one of the device's queues
        ///
        /// This function adds in one of the queues of the device a DescriptorChain at some offset
        /// in the "data range" of the guest memory. The number of descriptors to create is passed
        /// as a list of descriptors (a triple of (index, length, flags)).
        ///
        /// The total size of the buffer is the sum of all lengths of this list of descriptors.
        /// The fist descriptor will be stored at `self.data_address() + addr_offset`. Subsequent
        /// descriptors will be placed at random addresses after that.
        ///
        /// # Arguments
        ///
        /// * `queue` - The index of the device queue to use
        /// * `addr_offset` - Offset within the data region where to put the first descriptor
        /// * `desc_list` - List of descriptors to create in the chain
        pub fn add_desc_chain(
            &mut self,
            queue: usize,
            addr_offset: u64,
            desc_list: &[(u16, u32, u16)],
        ) {
            let device = self.device.lock().unwrap();

            let event_fd = &device.queue_events()[queue];
            let vq = &self.virtqueues[queue];

            // Create the descriptor chain
            let mut iter = desc_list.iter().peekable();
            let mut addr = self.data_address() + addr_offset;
            while let Some(&(index, len, flags)) = iter.next() {
                let desc = &vq.dtable[index as usize];
                desc.set(addr, len, flags, 0);
                if let Some(&&(next_index, _, _)) = iter.peek() {
                    desc.flags.set(flags | VIRTQ_DESC_F_NEXT);
                    desc.next.set(next_index);
                }

                addr += u64::from(len);
                // Add small random gaps between descriptor addresses in order to make sure we
                // don't blindly read contiguous memory.
                addr += u64::from(utils::rand::xor_pseudo_rng_u32()) % 10;
            }

            // Mark the chain as available.
            if let Some(&(index, _, _)) = desc_list.first() {
                let ring_index = vq.avail.idx.get();
                vq.avail.ring[ring_index as usize].set(index);
                vq.avail.idx.set(ring_index + 1);
            }
            event_fd.write(1).unwrap();
        }

        /// Emulate the device for a period of time
        ///
        /// # Arguments
        ///
        /// * `msec` - The amount pf time in milliseconds for which to Emulate
        pub fn emulate_for_msec(&mut self, msec: i32) -> Result<usize, event_manager::Error> {
            self.event_manager.run_with_timeout(msec)
        }
    }
}
