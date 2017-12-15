// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use byteorder::{ByteOrder, LittleEndian};

use BusDevice;
use super::*;
use sys_util::{EventFd, GuestAddress, GuestMemory, Result};

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
    );

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
                let v =
                    match offset {
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
            if let Some(interrupt_evt) = self.interrupt_evt.take() {
                if let Some(mem) = self.mem.take() {
                    self.device.activate(
                        mem,
                        interrupt_evt,
                        self.interrupt_status.clone(),
                        self.queues.clone(),
                        self.queue_evts.split_off(0),
                    );
                    self.device_activated = true;
                }
            }
        }
    }
}
