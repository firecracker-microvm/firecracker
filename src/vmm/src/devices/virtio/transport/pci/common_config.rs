// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use vm_memory::GuestAddress;

use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::pci::device::VIRTQ_MSI_NO_VECTOR;
use crate::logger::{debug, error, info, trace, warn};
pub const VIRTIO_PCI_COMMON_CONFIG_ID: &str = "virtio_pci_common_config";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioPciCommonConfigState {
    pub driver_status: u8,
    pub config_generation: u8,
    pub device_feature_select: u32,
    pub driver_feature_select: u32,
    pub queue_select: u16,
    pub msix_config: u16,
    pub msix_queues: Vec<u16>,
}

// The standard layout for the ring is a continuous chunk of memory which looks
// like this.  We assume num is a power of 2.
//
// struct vring
// {
// 	// The actual descriptors (16 bytes each)
// 	struct vring_desc desc[num];
//
// 	// A ring of available descriptor heads with free-running index.
// 	__virtio16 avail_flags;
// 	__virtio16 avail_idx;
// 	__virtio16 available[num];
// 	__virtio16 used_event_idx;
//
// 	// Padding to the next align boundary.
// 	char pad[];
//
// 	// A ring of used descriptor heads with free-running index.
// 	__virtio16 used_flags;
// 	__virtio16 used_idx;
// 	struct vring_used_elem used[num];
// 	__virtio16 avail_event_idx;
// };
// struct vring_desc {
// 	__virtio64 addr;
// 	__virtio32 len;
// 	__virtio16 flags;
// 	__virtio16 next;
// };
//
// struct vring_avail {
// 	__virtio16 flags;
// 	__virtio16 idx;
// 	__virtio16 ring[];
// };
//
// // u32 is used here for ids for padding reasons.
// struct vring_used_elem {
// 	// Index of start of used descriptor chain.
// 	__virtio32 id;
// 	// Total length of the descriptor chain which was used (written to)
// 	__virtio32 len;
// };
//
// Kernel header used for this reference: include/uapi/linux/virtio_ring.h
// Virtio Spec: https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html
//
const VRING_DESC_ELEMENT_SIZE: usize = 16;
const VRING_AVAIL_ELEMENT_SIZE: usize = 2;
const VRING_USED_ELEMENT_SIZE: usize = 8;
#[derive(Debug)]
pub enum VringType {
    Desc,
    Avail,
    Used,
}

pub fn get_vring_size(t: VringType, queue_size: u16) -> u64 {
    let (length_except_ring, element_size) = match t {
        VringType::Desc => (0, VRING_DESC_ELEMENT_SIZE),
        VringType::Avail => (6, VRING_AVAIL_ELEMENT_SIZE),
        VringType::Used => (6, VRING_USED_ELEMENT_SIZE),
    };
    (length_except_ring + element_size * queue_size as usize) as u64
}

/// Contains the data for reading and writing the common configuration structure of a virtio PCI
/// device.
///
/// * Registers:
///
/// ** About the whole device.
///    le32 device_feature_select;     // 0x00 // read-write
///    le32 device_feature;            // 0x04 // read-only for driver
///    le32 driver_feature_select;     // 0x08 // read-write
///    le32 driver_feature;            // 0x0C // read-write
///    le16 msix_config;               // 0x10 // read-write
///    le16 num_queues;                // 0x12 // read-only for driver
///    u8 device_status;               // 0x14 // read-write (driver_status)
///    u8 config_generation;           // 0x15 // read-only for driver
///
/// ** About a specific virtqueue.
///    le16 queue_select;              // 0x16 // read-write
///    le16 queue_size;                // 0x18 // read-write, power of 2, or 0.
///    le16 queue_msix_vector;         // 0x1A // read-write
///    le16 queue_enable;              // 0x1C // read-write (Ready)
///    le16 queue_notify_off;          // 0x1E // read-only for driver
///    le64 queue_desc;                // 0x20 // read-write
///    le64 queue_avail;               // 0x28 // read-write
///    le64 queue_used;                // 0x30 // read-write
#[derive(Debug)]
pub struct VirtioPciCommonConfig {
    pub driver_status: u8,
    pub config_generation: u8,
    pub device_feature_select: u32,
    pub driver_feature_select: u32,
    pub queue_select: u16,
    pub msix_config: Arc<AtomicU16>,
    pub msix_queues: Arc<Mutex<Vec<u16>>>,
}

impl VirtioPciCommonConfig {
    pub fn new(state: VirtioPciCommonConfigState) -> Self {
        VirtioPciCommonConfig {
            driver_status: state.driver_status,
            config_generation: state.config_generation,
            device_feature_select: state.device_feature_select,
            driver_feature_select: state.driver_feature_select,
            queue_select: state.queue_select,
            msix_config: Arc::new(AtomicU16::new(state.msix_config)),
            msix_queues: Arc::new(Mutex::new(state.msix_queues)),
        }
    }

    pub fn state(&self) -> VirtioPciCommonConfigState {
        VirtioPciCommonConfigState {
            driver_status: self.driver_status,
            config_generation: self.config_generation,
            device_feature_select: self.device_feature_select,
            driver_feature_select: self.driver_feature_select,
            queue_select: self.queue_select,
            msix_config: self.msix_config.load(Ordering::Acquire),
            msix_queues: self.msix_queues.lock().unwrap().clone(),
        }
    }

    pub fn read(&mut self, offset: u64, data: &mut [u8], device: Arc<Mutex<dyn VirtioDevice>>) {
        assert!(data.len() <= 8);

        match data.len() {
            1 => {
                let v = self.read_common_config_byte(offset);
                data[0] = v;
            }
            2 => {
                let v = self.read_common_config_word(offset, device.lock().unwrap().queues());
                LittleEndian::write_u16(data, v);
            }
            4 => {
                let v = self.read_common_config_dword(offset, device);
                LittleEndian::write_u32(data, v);
            }
            8 => {
                let v = self.read_common_config_qword(offset);
                LittleEndian::write_u64(data, v);
            }
            _ => error!("invalid data length for virtio read: len {}", data.len()),
        }
    }

    pub fn write(&mut self, offset: u64, data: &[u8], device: Arc<Mutex<dyn VirtioDevice>>) {
        assert!(data.len() <= 8);

        match data.len() {
            1 => self.write_common_config_byte(offset, data[0]),
            2 => self.write_common_config_word(
                offset,
                LittleEndian::read_u16(data),
                device.lock().unwrap().queues_mut(),
            ),
            4 => self.write_common_config_dword(offset, LittleEndian::read_u32(data), device),
            8 => self.write_common_config_qword(
                offset,
                LittleEndian::read_u64(data),
                device.lock().unwrap().queues_mut(),
            ),
            _ => error!("invalid data length for virtio write: len {}", data.len()),
        }
    }

    fn read_common_config_byte(&self, offset: u64) -> u8 {
        debug!("read_common_config_byte: offset 0x{:x}", offset);
        // The driver is only allowed to do aligned, properly sized access.
        match offset {
            0x14 => self.driver_status,
            0x15 => self.config_generation,
            _ => {
                warn!("invalid virtio config byte read: 0x{:x}", offset);
                0
            }
        }
    }

    fn write_common_config_byte(&mut self, offset: u64, value: u8) {
        debug!("write_common_config_byte: offset 0x{offset:x}: {value:x}");
        match offset {
            0x14 => self.driver_status = value,
            _ => {
                warn!("invalid virtio config byte write: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_word(&self, offset: u64, queues: &[Queue]) -> u16 {
        debug!("read_common_config_word: offset 0x{:x}", offset);
        match offset {
            0x10 => self.msix_config.load(Ordering::Acquire),
            0x12 => queues.len().try_into().unwrap(), // num_queues
            0x16 => self.queue_select,
            0x18 => self.with_queue(queues, |q| q.size).unwrap_or(0),
            // If `queue_select` points to an invalid queue we should return NO_VECTOR.
            // Reading from here
            // https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-1280005:
            //
            // > The device MUST return vector mapped to a given event, (NO_VECTOR if unmapped) on
            // > read of config_msix_vector/queue_msix_vector.
            0x1a => self
                .msix_queues
                .lock()
                .unwrap()
                .get(self.queue_select as usize)
                .copied()
                .unwrap_or(VIRTQ_MSI_NO_VECTOR),
            0x1c => u16::from(self.with_queue(queues, |q| q.ready).unwrap_or(false)),
            0x1e => self.queue_select, // notify_off
            _ => {
                warn!("invalid virtio register word read: 0x{:x}", offset);
                0
            }
        }
    }

    fn write_common_config_word(&mut self, offset: u64, value: u16, queues: &mut [Queue]) {
        debug!("write_common_config_word: offset 0x{:x}", offset);
        match offset {
            0x10 => {
                // Make sure that the guest doesn't select an invalid vector. We are offering
                // `num_queues + 1` vectors (plus one for configuration updates). If an invalid
                // vector has been selected, we just store the `NO_VECTOR` value.
                let mut msix_queues = self.msix_queues.lock().expect("Poisoned lock");
                let nr_vectors = msix_queues.len() + 1;

                if (value as usize) < nr_vectors {
                    self.msix_config.store(value, Ordering::Release);
                } else {
                    self.msix_config
                        .store(VIRTQ_MSI_NO_VECTOR, Ordering::Release);
                }
            }
            0x16 => self.queue_select = value,
            0x18 => self.with_queue_mut(queues, |q| q.size = value),
            0x1a => {
                let mut msix_queues = self.msix_queues.lock().expect("Poisoned lock");
                let nr_vectors = msix_queues.len() + 1;
                // Make sure that `queue_select` points to a valid queue. If not, we won't do
                // anything here and subsequent reads at 0x1a will return `NO_VECTOR`.
                if let Some(queue) = msix_queues.get_mut(self.queue_select as usize) {
                    // Make sure that the guest doesn't select an invalid vector. We are offering
                    // `num_queues + 1` vectors (plus one for configuration updates). If an invalid
                    // vector has been selected, we just store the `NO_VECTOR` value.
                    if (value as usize) < nr_vectors {
                        *queue = value;
                    } else {
                        *queue = VIRTQ_MSI_NO_VECTOR;
                    }
                }
            }
            0x1c => self.with_queue_mut(queues, |q| {
                q.ready = value == 1;
            }),
            _ => {
                warn!("invalid virtio register word write: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_dword(&self, offset: u64, device: Arc<Mutex<dyn VirtioDevice>>) -> u32 {
        debug!("read_common_config_dword: offset 0x{:x}", offset);
        match offset {
            0x00 => self.device_feature_select,
            0x04 => {
                let locked_device = device.lock().unwrap();
                // Only 64 bits of features (2 pages) are defined for now, so limit
                // device_feature_select to avoid shifting by 64 or more bits.
                if self.device_feature_select < 2 {
                    ((locked_device.avail_features() >> (self.device_feature_select * 32))
                        & 0xffff_ffff) as u32
                } else {
                    0
                }
            }
            0x08 => self.driver_feature_select,
            _ => {
                warn!("invalid virtio register dword read: 0x{:x}", offset);
                0
            }
        }
    }

    fn write_common_config_dword(
        &mut self,
        offset: u64,
        value: u32,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) {
        debug!("write_common_config_dword: offset 0x{:x}", offset);
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffff_ffff) | (u64::from(x) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | u64::from(x)
        }

        let mut locked_device = device.lock().unwrap();

        match offset {
            0x00 => self.device_feature_select = value,
            0x08 => self.driver_feature_select = value,
            0x0c => locked_device.ack_features_by_page(self.driver_feature_select, value),
            0x20 => self.with_queue_mut(locked_device.queues_mut(), |q| {
                lo(&mut q.desc_table_address, value)
            }),
            0x24 => self.with_queue_mut(locked_device.queues_mut(), |q| {
                hi(&mut q.desc_table_address, value)
            }),
            0x28 => self.with_queue_mut(locked_device.queues_mut(), |q| {
                lo(&mut q.avail_ring_address, value)
            }),
            0x2c => self.with_queue_mut(locked_device.queues_mut(), |q| {
                hi(&mut q.avail_ring_address, value)
            }),
            0x30 => self.with_queue_mut(locked_device.queues_mut(), |q| {
                lo(&mut q.used_ring_address, value)
            }),
            0x34 => self.with_queue_mut(locked_device.queues_mut(), |q| {
                hi(&mut q.used_ring_address, value)
            }),
            _ => {
                warn!("invalid virtio register dword write: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_qword(&self, _offset: u64) -> u64 {
        debug!("read_common_config_qword: offset 0x{:x}", _offset);
        0 // Assume the guest has no reason to read write-only registers.
    }

    fn write_common_config_qword(&mut self, offset: u64, value: u64, queues: &mut [Queue]) {
        debug!("write_common_config_qword: offset 0x{:x}", offset);

        let low = Some((value & 0xffff_ffff) as u32);
        let high = Some((value >> 32) as u32);

        match offset {
            0x20 => self.with_queue_mut(queues, |q| q.desc_table_address.0 = value),
            0x28 => self.with_queue_mut(queues, |q| q.avail_ring_address.0 = value),
            0x30 => self.with_queue_mut(queues, |q| q.used_ring_address.0 = value),
            _ => {
                warn!("invalid virtio register qword write: 0x{:x}", offset);
            }
        }
    }

    fn with_queue<U, F>(&self, queues: &[Queue], f: F) -> Option<U>
    where
        F: FnOnce(&Queue) -> U,
    {
        queues.get(self.queue_select as usize).map(f)
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&self, queues: &mut [Queue], f: F) {
        if let Some(queue) = queues.get_mut(self.queue_select as usize) {
            f(queue);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::transport::mmio::tests::DummyDevice;

    #[test]
    fn write_base_regs() {
        let mut regs = VirtioPciCommonConfig {
            driver_status: 0xaa,
            config_generation: 0x55,
            device_feature_select: 0x0,
            driver_feature_select: 0x0,
            queue_select: 0xff,
            msix_config: Arc::new(AtomicU16::new(0)),
            msix_queues: Arc::new(Mutex::new(vec![0; 3])),
        };

        let dev = Arc::new(Mutex::new(DummyDevice::new()));
        // Can set all bits of driver_status.
        regs.write(0x14, &[0x55], dev.clone());
        let mut read_back = vec![0x00];
        regs.read(0x14, &mut read_back, dev.clone());
        assert_eq!(read_back[0], 0x55);

        // The config generation register is read only.
        regs.write(0x15, &[0xaa], dev.clone());
        let mut read_back = vec![0x00];
        regs.read(0x15, &mut read_back, dev.clone());
        assert_eq!(read_back[0], 0x55);

        // Device features is read-only and passed through from the device.
        regs.write(0x04, &[0, 0, 0, 0], dev.clone());
        let mut read_back = vec![0, 0, 0, 0];
        regs.read(0x04, &mut read_back, dev.clone());
        assert_eq!(LittleEndian::read_u32(&read_back), 0u32);

        // Feature select registers are read/write.
        regs.write(0x00, &[1, 2, 3, 4], dev.clone());
        let mut read_back = vec![0, 0, 0, 0];
        regs.read(0x00, &mut read_back, dev.clone());
        assert_eq!(LittleEndian::read_u32(&read_back), 0x0403_0201);
        regs.write(0x08, &[1, 2, 3, 4], dev.clone());
        let mut read_back = vec![0, 0, 0, 0];
        regs.read(0x08, &mut read_back, dev.clone());
        assert_eq!(LittleEndian::read_u32(&read_back), 0x0403_0201);

        // 'queue_select' can be read and written.
        regs.write(0x16, &[0xaa, 0x55], dev.clone());
        let mut read_back = vec![0x00, 0x00];
        regs.read(0x16, &mut read_back, dev.clone());
        assert_eq!(read_back[0], 0xaa);
        assert_eq!(read_back[1], 0x55);

        // Getting the MSI vector when `queue_select` points to an invalid queue should return
        // NO_VECTOR (0xffff)
        regs.read(0x1a, &mut read_back, dev.clone());
        assert_eq!(read_back, [0xff, 0xff]);

        // Writing the MSI vector of an invalid `queue_select` does not have any effect.
        regs.write(0x1a, &[0x12, 0x13], dev.clone());
        assert_eq!(read_back, [0xff, 0xff]);
        // Valid `queue_select` though should setup the corresponding MSI-X queue.
        regs.write(0x16, &[0x1, 0x0], dev.clone());
        assert_eq!(regs.queue_select, 1);
        regs.write(0x1a, &[0x1, 0x0], dev.clone());
        regs.read(0x1a, &mut read_back, dev);
        assert_eq!(LittleEndian::read_u16(&read_back[..2]), 0x1);
    }
}
