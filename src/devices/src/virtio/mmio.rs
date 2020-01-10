// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use utils::byte_order;
use vm_memory::{GuestAddress, GuestMemoryMmap};

use super::device_status;
use super::*;
use crate::bus::BusDevice;

//TODO crosvm uses 0 here, but IIRC virtio specified some other vendor id that should be used
const VENDOR_ID: u32 = 0;

//required by the virtio mmio device register layout at offset 0 from base
const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;

//current version specified by the mmio standard (legacy devices used 1 here)
const MMIO_VERSION: u32 = 2;

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `virtio::NOTIFY_REG_OFFSET` offset from the MMIO
/// base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
/// is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioTransport {
    device: Arc<Mutex<dyn VirtioDevice>>,
    device_activated: bool,
    // The register where feature bits are stored.
    features_select: u32,
    // The register where features page is selected.
    acked_features_select: u32,
    queue_select: u32,
    device_status: u32,
    config_generation: u32,
    mem: GuestMemoryMmap,
    interrupt_status: Arc<AtomicUsize>,
}

impl MmioTransport {
    /// Constructs a new MMIO transport for the given virtio device.
    pub fn new(
        mem: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> std::io::Result<MmioTransport> {
        let interrupt_status = device
            .lock()
            .expect("Poisoned device lock")
            .get_interrupt_status();

        Ok(MmioTransport {
            device,
            device_activated: false,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            device_status: device_status::INIT,
            config_generation: 0,
            mem,
            interrupt_status,
        })
    }

    pub fn locked_device(&self) -> MutexGuard<dyn VirtioDevice + 'static> {
        self.device.lock().expect("Poisoned device lock")
    }

    // Gets the encapsulated VirtioDevice.
    pub fn device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.device.clone()
    }

    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.device_status & (set | clr) == set
    }

    fn are_queues_valid(&self) -> bool {
        self.locked_device()
            .get_queues()
            .iter()
            .all(|q| q.is_valid(&self.mem))
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
    where
        F: FnOnce(&Queue) -> U,
    {
        match self
            .locked_device()
            .get_queues()
            .get(self.queue_select as usize)
        {
            Some(queue) => f(queue),
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        if let Some(queue) = self
            .locked_device()
            .get_queues()
            .get_mut(self.queue_select as usize)
        {
            f(queue);
            true
        } else {
            false
        }
    }

    fn update_queue_field<F: FnOnce(&mut Queue)>(&mut self, f: F) {
        if self.check_device_status(
            device_status::FEATURES_OK,
            device_status::DRIVER_OK | device_status::FAILED,
        ) {
            self.with_queue_mut(f);
        } else {
            warn!(
                "update virtio queue in invalid state 0x{:x}",
                self.device_status
            );
        }
    }

    fn reset(&mut self) {
        if self.device_activated {
            warn!("reset device while it's still in active state");
            return;
        }
        self.features_select = 0;
        self.acked_features_select = 0;
        self.queue_select = 0;
        self.interrupt_status.store(0, Ordering::SeqCst);
        self.device_status = device_status::INIT;
        // . Keep interrupt_evt and queue_evts as is. There may be pending
        //   notifications in those eventfds, but nothing will happen other
        //   than supurious wakeups.
        // . Do not reset config_generation and keep it monotonically increasing
        for queue in self.locked_device().get_queues().as_mut_slice() {
            *queue = Queue::new(queue.get_max_size());
        }
    }

    /// Update device status according to the state machine defined by VirtIO Spec 1.0.
    /// Please refer to VirtIO Spec 1.0, section 2.1.1 and 3.1.1.
    ///
    /// The driver MUST update device status, setting bits to indicate the completed steps
    /// of the driver initialization sequence specified in 3.1. The driver MUST NOT clear
    /// a device status bit. If the driver sets the FAILED bit, the driver MUST later reset
    /// the device before attempting to re-initialize.
    #[allow(unused_assignments)]
    fn set_device_status(&mut self, status: u32) {
        use device_status::*;
        // match changed bits
        match !self.device_status & status {
            ACKNOWLEDGE if self.device_status == INIT => {
                self.device_status = status;
            }
            DRIVER if self.device_status == ACKNOWLEDGE => {
                self.device_status = status;
            }
            FEATURES_OK if self.device_status == (ACKNOWLEDGE | DRIVER) => {
                self.device_status = status;
            }
            DRIVER_OK if self.device_status == (ACKNOWLEDGE | DRIVER | FEATURES_OK) => {
                self.device_status = status;
                // If the driver incorrectly sets up the queues, the following
                // check will fail and take the device into an unusable state.
                if !self.device_activated && self.are_queues_valid() {
                    self.locked_device()
                        .activate(self.mem.clone())
                        .expect("Failed to activate device");

                    self.device_activated = true;
                }
            }
            _ if (status & FAILED) != 0 => {
                // TODO: notify backend driver to stop the device
                self.device_status |= FAILED;
            }
            _ if status == 0 => {
                if self.device_activated {
                    let mut device_activated = true;
                    let mut device_status = self.device_status;
                    let reset_result = self.locked_device().reset();
                    match reset_result {
                        Some((_interrupt_evt, mut _queue_evts)) => {
                            device_activated = false;
                        }

                        None => {
                            device_status |= FAILED;
                        }
                    }

                    self.device_activated = device_activated;
                    self.device_status = device_status;
                }

                // If the backend device driver doesn't support reset,
                // just leave the device marked as FAILED.
                if self.device_status & FAILED == 0 {
                    self.reset();
                }
            }
            _ => {
                warn!(
                    "invalid virtio driver status transition: 0x{:x} -> 0x{:x}",
                    self.device_status, status
                );
            }
        }
    }
}

impl BusDevice for MmioTransport {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = match offset {
                    0x0 => MMIO_MAGIC_VALUE,
                    0x04 => MMIO_VERSION,
                    0x08 => self.locked_device().device_type(),
                    0x0c => VENDOR_ID, // vendor id
                    0x10 => {
                        let mut features = self
                            .locked_device()
                            .avail_features_by_page(self.features_select);
                        if self.features_select == 1 {
                            features |= 0x1; // enable support of VirtIO Version 1
                        }
                        features
                    }
                    0x34 => self.with_queue(0, |q| u32::from(q.get_max_size())),
                    0x44 => self.with_queue(0, |q| q.ready as u32),
                    0x60 => self.interrupt_status.load(Ordering::SeqCst) as u32,
                    0x70 => self.device_status,
                    0xfc => self.config_generation,
                    _ => {
                        warn!("unknown virtio mmio register read: 0x{:x}", offset);
                        return;
                    }
                };
                byte_order::write_le_u32(data, v);
            }
            0x100..=0xfff => self.locked_device().read_config(offset - 0x100, data),
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
            *v = (*v & 0xffff_ffff) | (u64::from(x) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | u64::from(x)
        }

        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                match offset {
                    0x14 => self.features_select = v,
                    0x20 => {
                        if self.check_device_status(
                            device_status::DRIVER,
                            device_status::FEATURES_OK | device_status::FAILED,
                        ) {
                            self.locked_device()
                                .ack_features_by_page(self.acked_features_select, v);
                        } else {
                            warn!(
                                "ack virtio features in invalid state 0x{:x}",
                                self.device_status
                            );
                        }
                    }
                    0x24 => self.acked_features_select = v,
                    0x30 => self.queue_select = v,
                    0x38 => self.update_queue_field(|q| q.size = v as u16),
                    0x44 => self.update_queue_field(|q| q.ready = v == 1),
                    0x64 => {
                        if self.check_device_status(device_status::DRIVER_OK, 0) {
                            self.interrupt_status
                                .fetch_and(!(v as usize), Ordering::SeqCst);
                        }
                    }
                    0x70 => self.set_device_status(v),
                    0x80 => self.update_queue_field(|q| lo(&mut q.desc_table, v)),
                    0x84 => self.update_queue_field(|q| hi(&mut q.desc_table, v)),
                    0x90 => self.update_queue_field(|q| lo(&mut q.avail_ring, v)),
                    0x94 => self.update_queue_field(|q| hi(&mut q.avail_ring, v)),
                    0xa0 => self.update_queue_field(|q| lo(&mut q.used_ring, v)),
                    0xa4 => self.update_queue_field(|q| hi(&mut q.used_ring, v)),
                    _ => {
                        warn!("unknown virtio mmio register write: 0x{:x}", offset);
                    }
                }
            }
            0x100..=0xfff => {
                if self.check_device_status(device_status::DRIVER, device_status::FAILED) {
                    self.locked_device().write_config(offset - 0x100, data)
                } else {
                    warn!("can not write to device config data area before driver is ready");
                }
            }
            _ => {
                warn!(
                    "invalid virtio mmio write: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        }
    }

    fn interrupt(&self, irq_mask: u32) -> std::io::Result<()> {
        self.interrupt_status
            .fetch_or(irq_mask as usize, Ordering::SeqCst);
        // interrupt_evt() is safe to unwrap because the inner interrupt_evt is initialized in the
        // constructor.
        // write() is safe to unwrap because the inner syscall is tailored to be safe as well.
        self.locked_device().get_interrupt()?.write(1).unwrap();
        Ok(())
    }
}

// #[cfg(test)]
// mod tests {

//     use super::*;

//     struct DummyDevice {
//         acked_features: u64,
//         avail_features: u64,
//         interrupt_evt: Option<EventFd>,
//         queue_evts: Option<Vec<EventFd>>,
//         config_bytes: [u8; 0xeff],
//     }

//     impl DummyDevice {
//         fn new() -> Self {
//             DummyDevice {
//                 acked_features: 0,
//                 avail_features: 0,
//                 interrupt_evt: None,
//                 queue_evts: None,
//                 config_bytes: [0; 0xeff],
//             }
//         }

//         fn set_avail_features(&mut self, avail_features: u64) {
//             self.avail_features = avail_features;
//         }
//     }

//     impl VirtioDevice for DummyDevice {
//         fn device_type(&self) -> u32 {
//             123
//         }

//         fn queue_max_sizes(&self) -> &[u16] {
//             &[16, 32]
//         }

//         fn read_config(&self, offset: u64, data: &mut [u8]) {
//             data.copy_from_slice(&self.config_bytes[offset as usize..]);
//         }

//         fn write_config(&mut self, offset: u64, data: &[u8]) {
//             for (i, item) in data.iter().enumerate() {
//                 self.config_bytes[offset as usize + i] = *item;
//             }
//         }

//         fn avail_features(&self) -> u64 {
//             self.avail_features
//         }

//         fn acked_features(&self) -> u64 {
//             self.acked_features
//         }

//         fn set_acked_features(&mut self, acked_features: u64) {
//             self.acked_features = acked_features;
//         }

//         fn activate(
//             &mut self,
//             _mem: GuestMemoryMmap,
//             interrupt_evt: EventFd,
//             _status: Arc<AtomicUsize>,
//             _queues: Vec<Queue>,
//             queue_evts: Vec<EventFd>,
//         ) -> ActivateResult {
//             self.interrupt_evt = Some(interrupt_evt);
//             self.queue_evts = Some(queue_evts);
//             Ok(())
//         }
//     }

//     fn set_device_status(d: &mut MmioTransport, status: u32) {
//         let mut buf = vec![0; 4];
//         byte_order::write_le_u32(&mut buf[..], status);
//         d.write(0x70, &buf[..]);
//     }

//     #[test]
//     fn test_new() {
//         let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
//         let mut dummy = DummyDevice::new();
//         // Validate reset is no-op.
//         assert!(dummy.reset().is_none());
//         let mut d = MmioTransport::new(m, Box::new(dummy)).unwrap();

//         // We just make sure here that the implementation of a mmio device behaves as we expect,
//         // given a known virtio device implementation (the dummy device).

//         assert_eq!(d.queue_evts().len(), 2);

//         assert!(d.interrupt_evt().is_some());

//         assert!(!d.are_queues_valid());

//         set_device_status(&mut d, device_status::ACKNOWLEDGE);
//         set_device_status(&mut d, device_status::ACKNOWLEDGE | device_status::DRIVER);
//         set_device_status(
//             &mut d,
//             device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
//         );

//         d.queue_select = 0;
//         assert_eq!(d.with_queue(0, Queue::get_max_size), 16);
//         assert!(d.with_queue_mut(|q| q.size = 16));
//         assert_eq!(d.queues[d.queue_select as usize].size, 16);

//         d.queue_select = 1;
//         assert_eq!(d.with_queue(0, Queue::get_max_size), 32);
//         assert!(d.with_queue_mut(|q| q.size = 16));
//         assert_eq!(d.queues[d.queue_select as usize].size, 16);

//         d.queue_select = 2;
//         assert_eq!(d.with_queue(0, Queue::get_max_size), 0);
//         assert!(!d.with_queue_mut(|q| q.size = 16));

//         d.mem.take().unwrap();
//         assert!(!d.are_queues_valid());
//     }

//     #[test]
//     fn test_bus_device_read() {
//         let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
//         let mut d = MmioTransport::new(m, Box::new(DummyDevice::new())).unwrap();

//         let mut buf = vec![0xff, 0, 0xfe, 0];
//         let buf_copy = buf.to_vec();

//         // The following read shouldn't be valid, because the length of the buf is not 4.
//         buf.push(0);
//         d.read(0, &mut buf[..]);
//         assert_eq!(buf[..4], buf_copy[..]);

//         // the length is ok again
//         buf.pop();

//         // Now we test that reading at various predefined offsets works as intended.

//         d.read(0, &mut buf[..]);
//         assert_eq!(byte_order::read_le_u32(&buf[..]), MMIO_MAGIC_VALUE);

//         d.read(0x04, &mut buf[..]);
//         assert_eq!(byte_order::read_le_u32(&buf[..]), MMIO_VERSION);

//         d.read(0x08, &mut buf[..]);
//         assert_eq!(byte_order::read_le_u32(&buf[..]), d.device.device_type());

//         d.read(0x0c, &mut buf[..]);
//         assert_eq!(byte_order::read_le_u32(&buf[..]), VENDOR_ID);

//         d.features_select = 0;
//         d.read(0x10, &mut buf[..]);
//         assert_eq!(
//             byte_order::read_le_u32(&buf[..]),
//             d.device.avail_features_by_page(0)
//         );

//         d.features_select = 1;
//         d.read(0x10, &mut buf[..]);
//         assert_eq!(
//             byte_order::read_le_u32(&buf[..]),
//             d.device.avail_features_by_page(0) | 0x1
//         );

//         d.read(0x34, &mut buf[..]);
//         assert_eq!(byte_order::read_le_u32(&buf[..]), 16);

//         d.read(0x44, &mut buf[..]);
//         assert_eq!(byte_order::read_le_u32(&buf[..]), false as u32);

//         d.interrupt_status.store(111, Ordering::SeqCst);
//         d.read(0x60, &mut buf[..]);
//         assert_eq!(byte_order::read_le_u32(&buf[..]), 111);

//         d.read(0x70, &mut buf[..]);
//         assert_eq!(byte_order::read_le_u32(&buf[..]), 0);

//         d.config_generation = 5;
//         d.read(0xfc, &mut buf[..]);
//         assert_eq!(byte_order::read_le_u32(&buf[..]), 5);

//         // This read shouldn't do anything, as it's past the readable generic registers, and
//         // before the device specific configuration space. Btw, reads from the device specific
//         // conf space are going to be tested a bit later, alongside writes.
//         buf = buf_copy.to_vec();
//         d.read(0xfd, &mut buf[..]);
//         assert_eq!(buf[..], buf_copy[..]);

//         // Read from an invalid address in generic register range.
//         d.read(0xfb, &mut buf[..]);
//         assert_eq!(buf[..], buf_copy[..]);

//         // Read from an invalid length in generic register range.
//         d.read(0xfc, &mut buf[..3]);
//         assert_eq!(buf[..], buf_copy[..]);
//     }

//     #[test]
//     #[allow(clippy::cognitive_complexity)]
//     fn test_bus_device_write() {
//         let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

//         let mut dummy_box = Box::new(DummyDevice::new());
//         let dummy_dev_acked_features = &dummy_box.acked_features as *const u64;
//         let dummy_dev_avail_features = &mut dummy_box.avail_features as *mut u64;

//         let mut d = MmioTransport::new(m, dummy_box).unwrap();

//         let mut buf = vec![0; 5];
//         byte_order::write_le_u32(&mut buf[..4], 1);

//         // Nothing should happen, because the slice len > 4.
//         d.features_select = 0;
//         d.write(0x14, &buf[..]);
//         assert_eq!(d.features_select, 0);

//         buf.pop();

//         assert_eq!(d.device_status, device_status::INIT);
//         set_device_status(&mut d, device_status::ACKNOWLEDGE);

//         // Acking features in invalid state shouldn't take effect.
//         assert_eq!(unsafe { *dummy_dev_acked_features }, 0x0);
//         d.acked_features_select = 0x0;
//         byte_order::write_le_u32(&mut buf[..], 1);
//         d.write(0x20, &buf[..]);
//         assert_eq!(unsafe { *dummy_dev_acked_features }, 0x0);

//         // Write to device specific configuration space should be ignored before setting device_status::DRIVER
//         let buf1 = vec![1; 0xeff];
//         for i in (0..0xeff).rev() {
//             let mut buf2 = vec![0; 0xeff];

//             d.write(0x100 + i as u64, &buf1[i..]);
//             d.read(0x100, &mut buf2[..]);

//             for item in buf2.iter().take(0xeff) {
//                 assert_eq!(*item, 0);
//             }
//         }

//         set_device_status(&mut d, device_status::ACKNOWLEDGE | device_status::DRIVER);
//         assert_eq!(
//             d.device_status,
//             device_status::ACKNOWLEDGE | device_status::DRIVER
//         );

//         // now writes should work
//         d.features_select = 0;
//         byte_order::write_le_u32(&mut buf[..], 1);
//         d.write(0x14, &buf[..]);
//         assert_eq!(d.features_select, 1);

//         // Test acknowledging features on bus.
//         d.acked_features_select = 0;
//         byte_order::write_le_u32(&mut buf[..], 0x124);
//         // Set the device available features in order to
//         // make acknowledging possible.
//         unsafe {
//             *dummy_dev_avail_features = 0x124;
//         };
//         d.write(0x20, &buf[..]);
//         assert_eq!(unsafe { *dummy_dev_acked_features }, 0x124);

//         d.acked_features_select = 0;
//         byte_order::write_le_u32(&mut buf[..], 2);
//         d.write(0x24, &buf[..]);
//         assert_eq!(d.acked_features_select, 2);

//         set_device_status(
//             &mut d,
//             device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
//         );

//         // Acking features in invalid state shouldn't take effect.
//         assert_eq!(unsafe { *dummy_dev_acked_features }, 0x124);
//         d.acked_features_select = 0x0;
//         byte_order::write_le_u32(&mut buf[..], 1);
//         d.write(0x20, &buf[..]);
//         assert_eq!(unsafe { *dummy_dev_acked_features }, 0x124);

//         // Setup queues
//         d.queue_select = 0;
//         byte_order::write_le_u32(&mut buf[..], 3);
//         d.write(0x30, &buf[..]);
//         assert_eq!(d.queue_select, 3);

//         d.queue_select = 0;
//         assert_eq!(d.queues[0].size, 0);
//         byte_order::write_le_u32(&mut buf[..], 16);
//         d.write(0x38, &buf[..]);
//         assert_eq!(d.queues[0].size, 16);

//         assert!(!d.queues[0].ready);
//         byte_order::write_le_u32(&mut buf[..], 1);
//         d.write(0x44, &buf[..]);
//         assert!(d.queues[0].ready);

//         assert_eq!(d.queues[0].desc_table.0, 0);
//         byte_order::write_le_u32(&mut buf[..], 123);
//         d.write(0x80, &buf[..]);
//         assert_eq!(d.queues[0].desc_table.0, 123);
//         d.write(0x84, &buf[..]);
//         assert_eq!(d.queues[0].desc_table.0, 123 + (123 << 32));

//         assert_eq!(d.queues[0].avail_ring.0, 0);
//         byte_order::write_le_u32(&mut buf[..], 124);
//         d.write(0x90, &buf[..]);
//         assert_eq!(d.queues[0].avail_ring.0, 124);
//         d.write(0x94, &buf[..]);
//         assert_eq!(d.queues[0].avail_ring.0, 124 + (124 << 32));

//         assert_eq!(d.queues[0].used_ring.0, 0);
//         byte_order::write_le_u32(&mut buf[..], 125);
//         d.write(0xa0, &buf[..]);
//         assert_eq!(d.queues[0].used_ring.0, 125);
//         d.write(0xa4, &buf[..]);
//         assert_eq!(d.queues[0].used_ring.0, 125 + (125 << 32));

//         set_device_status(
//             &mut d,
//             device_status::ACKNOWLEDGE
//                 | device_status::DRIVER
//                 | device_status::FEATURES_OK
//                 | device_status::DRIVER_OK,
//         );

//         d.interrupt_status.store(0b10_1010, Ordering::Relaxed);
//         byte_order::write_le_u32(&mut buf[..], 0b111);
//         d.write(0x64, &buf[..]);
//         assert_eq!(d.interrupt_status.load(Ordering::Relaxed), 0b10_1000);

//         // Write to an invalid address in generic register range.
//         byte_order::write_le_u32(&mut buf[..], 0xf);
//         d.config_generation = 0;
//         d.write(0xfb, &buf[..]);
//         assert_eq!(d.config_generation, 0);

//         // Write to an invalid length in generic register range.
//         d.write(0xfc, &buf[..2]);
//         assert_eq!(d.config_generation, 0);

//         // Here we test writes/read into/from the device specific configuration space.
//         let buf1 = vec![1; 0xeff];
//         for i in (0..0xeff).rev() {
//             let mut buf2 = vec![0; 0xeff];

//             d.write(0x100 + i as u64, &buf1[i..]);
//             d.read(0x100, &mut buf2[..]);

//             for item in buf2.iter().take(i) {
//                 assert_eq!(*item, 0);
//             }

//             assert_eq!(buf1[i..], buf2[i..]);
//         }
//     }

//     #[test]
//     fn test_bus_device_activate() {
//         let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
//         let mut d = MmioTransport::new(m, Box::new(DummyDevice::new())).unwrap();

//         assert!(!d.are_queues_valid());
//         assert!(!d.device_activated);
//         assert_eq!(d.device_status, device_status::INIT);

//         set_device_status(&mut d, device_status::ACKNOWLEDGE);
//         set_device_status(&mut d, device_status::ACKNOWLEDGE | device_status::DRIVER);
//         assert_eq!(
//             d.device_status,
//             device_status::ACKNOWLEDGE | device_status::DRIVER
//         );

//         // invalid state transition should have no effect
//         set_device_status(
//             &mut d,
//             device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::DRIVER_OK,
//         );
//         assert_eq!(
//             d.device_status,
//             device_status::ACKNOWLEDGE | device_status::DRIVER
//         );

//         set_device_status(
//             &mut d,
//             device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
//         );
//         assert_eq!(
//             d.device_status,
//             device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK
//         );

//         let mut buf = vec![0; 4];
//         for q in 0..d.queues.len() {
//             d.queue_select = q as u32;
//             byte_order::write_le_u32(&mut buf[..], 16);
//             d.write(0x38, &buf[..]);
//             byte_order::write_le_u32(&mut buf[..], 1);
//             d.write(0x44, &buf[..]);
//         }
//         assert!(d.are_queues_valid());
//         assert!(!d.device_activated);

//         // Device should be ready for activation now.

//         // A couple of invalid writes; will trigger warnings; shouldn't activate the device.
//         d.write(0xa8, &buf[..]);
//         d.write(0x1000, &buf[..]);
//         assert!(!d.device_activated);

//         set_device_status(
//             &mut d,
//             device_status::ACKNOWLEDGE
//                 | device_status::DRIVER
//                 | device_status::FEATURES_OK
//                 | device_status::DRIVER_OK,
//         );
//         assert_eq!(
//             d.device_status,
//             device_status::ACKNOWLEDGE
//                 | device_status::DRIVER
//                 | device_status::FEATURES_OK
//                 | device_status::DRIVER_OK
//         );
//         assert!(d.device_activated);

//         // A write which changes the size of a queue after activation; currently only triggers
//         // a warning path and have no effect on queue state.
//         byte_order::write_le_u32(&mut buf[..], 0);
//         d.queue_select = 0;
//         d.write(0x44, &buf[..]);
//         d.read(0x44, &mut buf[..]);
//         assert_eq!(byte_order::read_le_u32(&buf[..]), 1);
//     }

//     fn activate_device(d: &mut MmioTransport) {
//         set_device_status(d, device_status::ACKNOWLEDGE);
//         set_device_status(d, device_status::ACKNOWLEDGE | device_status::DRIVER);
//         set_device_status(
//             d,
//             device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
//         );

//         // Setup queue data structures
//         let mut buf = vec![0; 4];
//         for q in 0..d.queues.len() {
//             d.queue_select = q as u32;
//             byte_order::write_le_u32(&mut buf[..], 16);
//             d.write(0x38, &buf[..]);
//             byte_order::write_le_u32(&mut buf[..], 1);
//             d.write(0x44, &buf[..]);
//         }
//         assert!(d.are_queues_valid());
//         assert!(!d.device_activated);

//         // Device should be ready for activation now.
//         set_device_status(
//             d,
//             device_status::ACKNOWLEDGE
//                 | device_status::DRIVER
//                 | device_status::FEATURES_OK
//                 | device_status::DRIVER_OK,
//         );
//         assert_eq!(
//             d.device_status,
//             device_status::ACKNOWLEDGE
//                 | device_status::DRIVER
//                 | device_status::FEATURES_OK
//                 | device_status::DRIVER_OK
//         );
//         assert!(d.device_activated);
//     }

//     #[test]
//     fn test_bus_device_reset() {
//         let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
//         let mut d = MmioTransport::new(m, Box::new(DummyDevice::new())).unwrap();
//         let mut buf = vec![0; 4];

//         assert!(!d.are_queues_valid());
//         assert!(!d.device_activated);
//         assert_eq!(d.device_status, 0);
//         activate_device(&mut d);

//         // Marking device as FAILED should not affect device_activated state
//         byte_order::write_le_u32(&mut buf[..], 0x8f);
//         d.write(0x70, &buf[..]);
//         assert_eq!(d.device_status, 0x8f);
//         assert!(d.device_activated);

//         // Nothing happens when backend driver doesn't support reset
//         byte_order::write_le_u32(&mut buf[..], 0x0);
//         d.write(0x70, &buf[..]);
//         assert_eq!(d.device_status, 0x8f);
//         assert!(d.device_activated);
//     }

//     #[test]
//     fn test_get_avail_features() {
//         let dummy_dev = DummyDevice::new();
//         assert_eq!(dummy_dev.avail_features(), dummy_dev.avail_features);
//     }

//     #[test]
//     fn test_get_acked_features() {
//         let dummy_dev = DummyDevice::new();
//         assert_eq!(dummy_dev.acked_features(), dummy_dev.acked_features);
//     }

//     #[test]
//     fn test_set_acked_features() {
//         let mut dummy_dev = DummyDevice::new();

//         assert_eq!(dummy_dev.acked_features(), 0);
//         dummy_dev.set_acked_features(16);
//         assert_eq!(dummy_dev.acked_features(), dummy_dev.acked_features);
//     }

//     #[test]
//     fn test_ack_features_by_page() {
//         let mut dummy_dev = DummyDevice::new();
//         dummy_dev.set_acked_features(16);
//         dummy_dev.set_avail_features(8);
//         dummy_dev.ack_features_by_page(0, 8);
//         assert_eq!(dummy_dev.acked_features(), 24);
//     }

//     #[test]
//     fn test_set_avail_features() {
//         let mut dummy_dev = DummyDevice::new();
//         assert_eq!(dummy_dev.avail_features(), 0);
//         dummy_dev.set_avail_features(4);
//         assert_eq!(dummy_dev.avail_features(), 4);
//     }
// }
