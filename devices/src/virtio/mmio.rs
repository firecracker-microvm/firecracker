// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use super::*;
use sys_util::{EventFd, GuestAddress, GuestMemory, Result};
use BusDevice;

//TODO crosvm uses 0 here, but IIRC virtio specified some other vendor id that should be used
const VENDOR_ID: u32 = 0;

//required by the virtio mmio device register layout at offset 0 from base
const MMIO_MAGIC_VALUE: u32 = 0x74726976;

//current version specified by the mmio standard (legacy devices used 1 here)
const MMIO_VERSION: u32 = 2;

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. Once the guest driver has configured the device, `VirtioDevice::activate` will be called
/// and all the events, memory, and queues for device operation will be moved into the device.
/// Optionally, a virtio device can implement device reset in which it returns said resources and
/// resets its internal.
pub trait VirtioDevice: Send {
    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16];

    /// The set of feature bits shifted by `page * 32`.
    fn features(&self, page: u32) -> u32 {
        let _ = page;
        0
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, page: u32, value: u32) {
        let _ = page;
        let _ = value;
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let _ = offset;
        let _ = data;
    }

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let _ = offset;
        let _ = data;
    }

    /// Activates this device for real usage.
    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        status: Arc<AtomicUsize>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult;

    /// Optionally deactivates this device and returns ownership of the guest memory map, interrupt
    /// event, and queue events.
    fn reset(&mut self) -> Option<(EventFd, Vec<EventFd>)> {
        None
    }
}

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `virtio::NOITFY_REG_OFFSET` offset from the MMIO
/// base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
/// is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioDevice {
    device: Box<VirtioDevice>,
    device_activated: bool,

    features_select: u32,
    acked_features_select: u32,
    queue_select: u32,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: Option<EventFd>,
    driver_status: u32,
    config_generation: u32,
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    mem: Option<GuestMemory>,
}

impl MmioDevice {
    /// Constructs a new MMIO transport for the given virtio device.
    pub fn new(mem: GuestMemory, device: Box<VirtioDevice>) -> Result<MmioDevice> {
        let mut queue_evts = Vec::new();
        for _ in device.queue_max_sizes().iter() {
            queue_evts.push(EventFd::new()?)
        }
        let queues = device
            .queue_max_sizes()
            .iter()
            .map(|&s| Queue::new(s))
            .collect();
        Ok(MmioDevice {
            device: device,
            device_activated: false,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: Some(EventFd::new()?),
            driver_status: 0,
            config_generation: 0,
            queues: queues,
            queue_evts: queue_evts,
            mem: Some(mem),
        })
    }

    /// Gets the list of queue events that must be triggered whenever the VM writes to
    /// `virtio::NOITFY_REG_OFFSET` past the MMIO base. Each event must be triggered when the
    /// value being written equals the index of the event in this list.
    pub fn queue_evts(&self) -> &[EventFd] {
        self.queue_evts.as_slice()
    }

    /// Gets the event this device uses to interrupt the VM when the used queue is changed.
    pub fn interrupt_evt(&self) -> Option<&EventFd> {
        self.interrupt_evt.as_ref()
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits = DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK;
        self.driver_status == ready_bits && self.driver_status & DEVICE_FAILED == 0
    }

    fn are_queues_valid(&self) -> bool {
        if let Some(mem) = self.mem.as_ref() {
            self.queues.iter().all(|q| q.is_valid(mem))
        } else {
            false
        }
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
    where
        F: FnOnce(&Queue) -> U,
    {
        match self.queues.get(self.queue_select as usize) {
            Some(queue) => f(queue),
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        if let Some(queue) = self.queues.get_mut(self.queue_select as usize) {
            f(queue);
            true
        } else {
            false
        }
    }
}

impl BusDevice for MmioDevice {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        match offset {
            0x00...0xff if data.len() == 4 => {
                let v = match offset {
                    0x0 => MMIO_MAGIC_VALUE,
                    0x04 => MMIO_VERSION,
                    0x08 => self.device.device_type(),
                    0x0c => VENDOR_ID, // vendor id
                    0x10 => {
                        self.device.features(self.features_select)
                            | if self.features_select == 1 { 0x1 } else { 0x0 }
                    }
                    0x34 => self.with_queue(0, |q| q.get_max_size() as u32),
                    0x44 => self.with_queue(0, |q| q.ready as u32),
                    0x60 => self.interrupt_status.load(Ordering::SeqCst) as u32,
                    0x70 => self.driver_status,
                    0xfc => self.config_generation,
                    _ => {
                        warn!("unknown virtio mmio register read: 0x{:x}", offset);
                        return;
                    }
                };
                LittleEndian::write_u32(data, v);
            }
            0x100...0xfff => self.device.read_config(offset - 0x100, data),
            _ => {
                warn!(
                    "invalid virtio mmio read: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        };
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffffffff) | ((x as u64) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffffffff) | (x as u64)
        }

        let mut mut_q = false;
        match offset {
            0x00...0xff if data.len() == 4 => {
                let v = LittleEndian::read_u32(data);
                match offset {
                    0x14 => self.features_select = v,
                    0x20 => self.device.ack_features(self.acked_features_select, v),
                    0x24 => self.acked_features_select = v,
                    0x30 => self.queue_select = v,
                    0x38 => mut_q = self.with_queue_mut(|q| q.size = v as u16),
                    0x44 => mut_q = self.with_queue_mut(|q| q.ready = v == 1),
                    0x64 => {
                        self.interrupt_status
                            .fetch_and(!(v as usize), Ordering::SeqCst);
                    }
                    0x70 => self.driver_status = v,
                    0x80 => mut_q = self.with_queue_mut(|q| lo(&mut q.desc_table, v)),
                    0x84 => mut_q = self.with_queue_mut(|q| hi(&mut q.desc_table, v)),
                    0x90 => mut_q = self.with_queue_mut(|q| lo(&mut q.avail_ring, v)),
                    0x94 => mut_q = self.with_queue_mut(|q| hi(&mut q.avail_ring, v)),
                    0xa0 => mut_q = self.with_queue_mut(|q| lo(&mut q.used_ring, v)),
                    0xa4 => mut_q = self.with_queue_mut(|q| hi(&mut q.used_ring, v)),
                    _ => {
                        warn!("unknown virtio mmio register write: 0x{:x}", offset);
                        return;
                    }
                }
            }
            0x100...0xfff => return self.device.write_config(offset - 0x100, data),
            _ => {
                warn!(
                    "invalid virtio mmio write: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
                return;
            }
        }

        if self.device_activated && mut_q {
            warn!("virtio queue was changed after device was activated");
        }

        if !self.device_activated && self.is_driver_ready() && self.are_queues_valid() {
            if let Some(ref interrupt_evt) = self.interrupt_evt {
                if let Some(mem) = self.mem.take() {
                    self.device
                        .activate(
                            mem,
                            interrupt_evt.try_clone().expect("Failed to clone eventfd"),
                            self.interrupt_status.clone(),
                            self.queues.clone(),
                            self.queue_evts.split_off(0),
                        )
                        .expect("Failed to activate device");
                    self.device_activated = true;
                }
            }
        }
    }

    fn interrupt(&self, irq_mask: u32) {
        self.interrupt_status
            .fetch_or(irq_mask as usize, Ordering::SeqCst);
        // interrupt_evt() is safe to unwrap because the inner interrupt_evt is initialized in the
        // constructor.
        // write() is safe to unwrap because the inner syscall is tailored to be safe as well.
        self.interrupt_evt().unwrap().write(1).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{ByteOrder, LittleEndian};

    use super::*;

    struct DummyDevice {
        acked_features: u32,
        config_bytes: [u8; 0xeff],
    }

    impl DummyDevice {
        fn new() -> Self {
            DummyDevice {
                acked_features: 0,
                config_bytes: [0; 0xeff],
            }
        }
    }

    impl VirtioDevice for DummyDevice {
        fn device_type(&self) -> u32 {
            return 123;
        }

        fn queue_max_sizes(&self) -> &[u16] {
            &[16, 32]
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            for i in 0..data.len() {
                data[i] = self.config_bytes[offset as usize + i];
            }
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            for i in 0..data.len() {
                self.config_bytes[offset as usize + i] = data[i];
            }
        }

        fn ack_features(&mut self, page: u32, value: u32) {
            self.acked_features = page + value;
        }

        fn activate(
            &mut self,
            _mem: GuestMemory,
            _interrupt_evt: EventFd,
            _status: Arc<AtomicUsize>,
            _queues: Vec<Queue>,
            _queue_evts: Vec<EventFd>,
        ) -> ActivateResult {
            Ok(())
        }
    }

    #[test]
    fn test_new() {
        let m = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut d = MmioDevice::new(m, Box::new(DummyDevice::new())).unwrap();

        // We just make sure here that the implementation of a mmio device behaves as we expect,
        // given a known virtio device implementation (the dummy device).

        assert_eq!(d.queue_evts().len(), 2);

        assert!(d.interrupt_evt().is_some());

        assert!(!d.is_driver_ready());

        assert!(!d.are_queues_valid());

        d.queue_select = 0;
        assert_eq!(d.with_queue(0, |q| q.get_max_size()), 16);
        assert!(d.with_queue_mut(|q| q.size = 16));
        assert_eq!(d.queues[d.queue_select as usize].size, 16);

        d.queue_select = 1;
        assert_eq!(d.with_queue(0, |q| q.get_max_size()), 32);
        assert!(d.with_queue_mut(|q| q.size = 16));
        assert_eq!(d.queues[d.queue_select as usize].size, 16);

        d.queue_select = 2;
        assert_eq!(d.with_queue(0, |q| q.get_max_size()), 0);
        assert!(!d.with_queue_mut(|q| q.size = 16));

        d.mem.take().unwrap();
        assert!(!d.are_queues_valid());
    }

    #[test]
    fn test_bus_device_read() {
        let m = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut d = MmioDevice::new(m, Box::new(DummyDevice::new())).unwrap();

        let mut buf = vec![0xff, 0, 0xfe, 0];
        let buf_copy = buf.to_vec();

        // The following read shouldn't be valid, because the length of the buf is not 4.
        buf.push(0);
        d.read(0, &mut buf[..]);
        assert_eq!(buf[..4], buf_copy[..]);

        // the length is ok again
        buf.pop();

        // Now we test that reading at various predefined offsets works as intended.

        d.read(0, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), MMIO_MAGIC_VALUE);

        d.read(0x04, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), MMIO_VERSION);

        d.read(0x08, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), d.device.device_type());

        d.read(0x0c, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), VENDOR_ID);

        d.features_select = 0;
        d.read(0x10, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), d.device.features(0));

        d.features_select = 1;
        d.read(0x10, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), d.device.features(0) | 0x1);

        d.read(0x34, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), 16);

        d.read(0x44, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), false as u32);

        d.interrupt_status.store(111, Ordering::SeqCst);
        d.read(0x60, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), 111);

        d.read(0x70, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0);

        d.config_generation = 5;
        d.read(0xfc, &mut buf[..]);
        assert_eq!(LittleEndian::read_u32(&buf[..]), 5);

        // This read shouldn't do anything, as it's past the readable generic registers, and
        // before the device specific configuration space. Btw, reads from the device specific
        // conf space are going to be tested a bit later, alongside writes.
        buf = buf_copy.to_vec();
        d.read(0xfd, &mut buf[..]);
        assert_eq!(buf[..], buf_copy[..]);
    }

    #[test]
    fn test_bus_device_write() {
        let m = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();

        let dummy_box = Box::new(DummyDevice::new());
        let p = &dummy_box.acked_features as *const u32;

        let mut d = MmioDevice::new(m, dummy_box).unwrap();

        let mut buf = vec![0; 5];
        LittleEndian::write_u32(&mut buf[..4], 1);

        // Nothing should happen, because the slice len > 4.
        d.features_select = 0;
        d.write(0x14, &buf[..]);
        assert_eq!(d.features_select, 0);

        buf.pop();

        // now writes should work
        d.features_select = 0;
        LittleEndian::write_u32(&mut buf[..], 1);
        d.write(0x14, &buf[..]);
        assert_eq!(d.features_select, 1);

        d.acked_features_select = 0x123;
        LittleEndian::write_u32(&mut buf[..], 1);
        d.write(0x20, &buf[..]);
        assert_eq!(unsafe { *p }, 0x124);

        d.acked_features_select = 0;
        LittleEndian::write_u32(&mut buf[..], 2);
        d.write(0x24, &buf[..]);
        assert_eq!(d.acked_features_select, 2);

        d.queue_select = 0;
        LittleEndian::write_u32(&mut buf[..], 3);
        d.write(0x30, &buf[..]);
        assert_eq!(d.queue_select, 3);

        d.queue_select = 0;
        assert_eq!(d.queues[0].size, 0);
        LittleEndian::write_u32(&mut buf[..], 16);
        d.write(0x38, &buf[..]);
        assert_eq!(d.queues[0].size, 16);

        assert!(!d.queues[0].ready);
        LittleEndian::write_u32(&mut buf[..], 1);
        d.write(0x44, &buf[..]);
        assert!(d.queues[0].ready);

        d.interrupt_status.store(0b101010, Ordering::Relaxed);
        LittleEndian::write_u32(&mut buf[..], 0b111);
        d.write(0x64, &buf[..]);
        assert_eq!(d.interrupt_status.load(Ordering::Relaxed), 0b101000);

        assert_eq!(d.driver_status, 0);
        LittleEndian::write_u32(&mut buf[..], 1);
        d.write(0x70, &buf[..]);
        assert_eq!(d.driver_status, 1);

        assert_eq!(d.queues[0].desc_table.0, 0);
        LittleEndian::write_u32(&mut buf[..], 123);
        d.write(0x80, &buf[..]);
        assert_eq!(d.queues[0].desc_table.0, 123);
        d.write(0x84, &buf[..]);
        assert_eq!(d.queues[0].desc_table.0, 123 + (123 << 32));

        assert_eq!(d.queues[0].avail_ring.0, 0);
        LittleEndian::write_u32(&mut buf[..], 124);
        d.write(0x90, &buf[..]);
        assert_eq!(d.queues[0].avail_ring.0, 124);
        d.write(0x94, &buf[..]);
        assert_eq!(d.queues[0].avail_ring.0, 124 + (124 << 32));

        assert_eq!(d.queues[0].used_ring.0, 0);
        LittleEndian::write_u32(&mut buf[..], 125);
        d.write(0xa0, &buf[..]);
        assert_eq!(d.queues[0].used_ring.0, 125);
        d.write(0xa4, &buf[..]);
        assert_eq!(d.queues[0].used_ring.0, 125 + (125 << 32));

        // Here we test writes/read into/from the device specific configuration space.

        let buf1 = vec![1; 0xeff];
        for i in (0..0xeff).rev() {
            let mut buf2 = vec![0; 0xeff];

            d.write(0x100 + i as u64, &buf1[i..]);
            d.read(0x100, &mut buf2[..]);

            for j in 0..i {
                assert_eq!(buf2[j], 0);
            }

            assert_eq!(buf1[i..], buf2[i..]);
        }
    }

    #[test]
    fn test_bus_device_activate() {
        let m = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut d = MmioDevice::new(m, Box::new(DummyDevice::new())).unwrap();

        d.driver_status =
            DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK;
        assert!(d.is_driver_ready());

        for q in d.queues.iter_mut() {
            q.size = 16;
            q.ready = true;
        }
        assert!(d.are_queues_valid());
        assert!(!d.device_activated);

        // Device should be ready for activation now.

        let buf = vec![0; 4];

        // A couple of invalid writes; will trigger warnings; shouldn't activate the device.
        d.write(0xa8, &buf[..]);
        d.write(0x1000, &buf[..]);
        assert!(!d.device_activated);

        // We pretend the device is already activated; activation related logic shouldn't be called
        // in this situation, even for a valid write.
        d.device_activated = true;
        d.write(0x30, &buf[..]);
        assert!(d.mem.is_some());
        assert!(d.interrupt_evt.is_some());

        // Ok, we stop pretending the device is activated.
        d.device_activated = false;

        // We issue this write again to actually activate the device.
        d.write(0x30, &buf[..]);
        assert!(d.device_activated);

        // A write which changes the size of a queue after activation; currently only triggers
        // a warning path.
        d.write(0x44, &buf[..]);
    }
}
