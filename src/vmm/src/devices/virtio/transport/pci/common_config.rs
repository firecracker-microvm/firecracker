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
use crate::logger::warn;

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
            _ => warn!(
                "pci: invalid data length for virtio read: len {}",
                data.len()
            ),
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
            _ => warn!(
                "pci: invalid data length for virtio write: len {}",
                data.len()
            ),
        }
    }

    fn read_common_config_byte(&self, offset: u64) -> u8 {
        // The driver is only allowed to do aligned, properly sized access.
        match offset {
            0x14 => self.driver_status,
            0x15 => self.config_generation,
            _ => {
                warn!("pci: invalid virtio config byte read: 0x{:x}", offset);
                0
            }
        }
    }

    fn write_common_config_byte(&mut self, offset: u64, value: u8) {
        match offset {
            0x14 => self.driver_status = value,
            _ => {
                warn!("pci: invalid virtio config byte write: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_word(&self, offset: u64, queues: &[Queue]) -> u16 {
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
                warn!("pci: invalid virtio register word read: 0x{:x}", offset);
                0
            }
        }
    }

    fn write_common_config_word(&mut self, offset: u64, value: u16, queues: &mut [Queue]) {
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
                if value != 0 {
                    q.ready = value == 1;
                }
            }),
            _ => {
                warn!("pci: invalid virtio register word write: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_dword(&self, offset: u64, device: Arc<Mutex<dyn VirtioDevice>>) -> u32 {
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
            0x20 => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.desc_table_address.0 & 0xffff_ffff) as u32
                })
                .unwrap_or_default()
            }
            0x24 => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.desc_table_address.0 >> 32) as u32
                })
                .unwrap_or_default()
            }
            0x28 => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.avail_ring_address.0 & 0xffff_ffff) as u32
                })
                .unwrap_or_default()
            }
            0x2c => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.avail_ring_address.0 >> 32) as u32
                })
                .unwrap_or_default()
            }
            0x30 => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.used_ring_address.0 & 0xffff_ffff) as u32
                })
                .unwrap_or_default()
            }
            0x34 => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.used_ring_address.0 >> 32) as u32
                })
                .unwrap_or_default()
            }
            _ => {
                warn!("pci: invalid virtio register dword read: 0x{:x}", offset);
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
                warn!("pci: invalid virtio register dword write: 0x{:x}", offset);
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
    use vm_memory::ByteValued;

    use super::*;
    use crate::devices::virtio::transport::mmio::tests::DummyDevice;

    fn default_device() -> Arc<Mutex<DummyDevice>> {
        Arc::new(Mutex::new(DummyDevice::new()))
    }

    fn default_pci_common_config() -> VirtioPciCommonConfig {
        VirtioPciCommonConfig {
            driver_status: 0,
            config_generation: 0,
            device_feature_select: 0,
            driver_feature_select: 0,
            queue_select: 0,
            msix_config: Arc::new(AtomicU16::new(0)),
            msix_queues: Arc::new(Mutex::new(vec![0u16; 2])),
        }
    }

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

    #[test]
    fn test_device_feature() {
        let mut config = default_pci_common_config();
        let mut device = default_device();
        let mut features = 0u32;

        device
            .lock()
            .unwrap()
            .set_avail_features(0x0000_1312_0000_1110);

        config.read(0x04, features.as_mut_slice(), device.clone());
        assert_eq!(features, 0x1110);
        // select second page
        config.write(0x0, 1u32.as_slice(), device.clone());
        config.read(0x04, features.as_mut_slice(), device.clone());
        assert_eq!(features, 0x1312);
        // Try a third page. It doesn't exist so we should get all 0s
        config.write(0x0, 2u32.as_slice(), device.clone());
        config.read(0x04, features.as_mut_slice(), device.clone());
        assert_eq!(features, 0x0);
    }

    #[test]
    fn test_driver_feature() {
        let mut config = default_pci_common_config();
        let mut device = default_device();
        device
            .lock()
            .unwrap()
            .set_avail_features(0x0000_1312_0000_1110);

        // ACK some features of the first page
        config.write(0x0c, 0x1100u32.as_slice(), device.clone());
        assert_eq!(device.lock().unwrap().acked_features(), 0x1100);
        // ACK some features of the second page
        config.write(0x08, 1u32.as_slice(), device.clone());
        config.write(0x0c, 0x0000_1310u32.as_slice(), device.clone());
        assert_eq!(
            device.lock().unwrap().acked_features(),
            0x0000_1310_0000_1100
        );
    }

    #[test]
    fn test_num_queues() {
        let mut config = default_pci_common_config();
        let mut device = default_device();
        let mut num_queues = 0u16;

        config.read(0x12, num_queues.as_mut_slice(), device.clone());
        assert_eq!(num_queues, 2);
        // `num_queues` is read-only
        config.write(0x12, 4u16.as_slice(), device.clone());
        config.read(0x12, num_queues.as_mut_slice(), device.clone());
        assert_eq!(num_queues, 2);
    }

    #[test]
    fn test_device_status() {
        let mut config = default_pci_common_config();
        let mut device = default_device();
        let mut status = 0u8;

        config.read(0x14, status.as_mut_slice(), device.clone());
        assert_eq!(status, 0);
        config.write(0x14, 0x42u8.as_slice(), device.clone());
        config.read(0x14, status.as_mut_slice(), device.clone());
        assert_eq!(status, 0x42);
    }

    #[test]
    fn test_config_msix_vector() {
        let mut config = default_pci_common_config();
        let device = default_device();
        let mut vector: u16 = 0;

        // Our device has 2 queues, so we should be using 3 vectors in total.
        // Trying to set a vector bigger than that should fail. Observing the
        // failure happens through a subsequent read that should return NO_VECTOR.
        config.write(0x10, 3u16.as_slice(), device.clone());
        config.read(0x10, vector.as_mut_slice(), device.clone());
        assert_eq!(vector, VIRTQ_MSI_NO_VECTOR);

        // Any of the 3 valid values should work
        for i in 0u16..3 {
            config.write(0x10, i.as_slice(), device.clone());
            config.read(0x10, vector.as_mut_slice(), device.clone());
            assert_eq!(vector, i);
        }
    }

    #[test]
    fn test_queue_size() {
        let mut config = default_pci_common_config();
        let device = default_device();
        let mut len = 0u16;
        let mut max_size = [0u16; 2];

        for queue_id in 0u16..2 {
            config.write(0x16, queue_id.as_slice(), device.clone());
            config.read(0x18, len.as_mut_slice(), device.clone());
            assert_eq!(
                len,
                device.lock().unwrap().queues()[queue_id as usize].max_size
            );
            max_size[queue_id as usize] = len;
        }

        config.write(0x16, 2u16.as_slice(), device.clone());
        config.read(0x18, len.as_mut_slice(), device.clone());
        assert_eq!(len, 0);

        // Setup size smaller than what is the maximum offered
        for queue_id in 0u16..2 {
            config.write(0x16, queue_id.as_slice(), device.clone());
            config.write(
                0x18,
                (max_size[queue_id as usize] - 1).as_slice(),
                device.clone(),
            );
            config.read(0x18, len.as_mut_slice(), device.clone());
            assert_eq!(len, max_size[queue_id as usize] - 1);
        }
    }

    #[test]
    fn test_queue_msix_vector() {
        let mut config = default_pci_common_config();
        let device = default_device();
        let mut vector = 0u16;

        // Our device has 2 queues, so we should be using 3 vectors in total.
        // Trying to set a vector bigger than that should fail. Observing the
        // failure happens through a subsequent read that should return NO_VECTOR.
        for queue_id in 0u16..2 {
            // Select queue
            config.write(0x16, queue_id.as_slice(), device.clone());

            config.write(0x1a, 3u16.as_slice(), device.clone());
            config.read(0x1a, vector.as_mut_slice(), device.clone());
            assert_eq!(vector, VIRTQ_MSI_NO_VECTOR);

            // Any of the 3 valid values should work
            for vector_id in 0u16..3 {
                config.write(0x1a, vector_id.as_slice(), device.clone());
                config.read(0x1a, vector.as_mut_slice(), device.clone());
                assert_eq!(vector, vector_id);
            }
        }
    }

    #[test]
    fn test_queue_enable() {
        let mut config = default_pci_common_config();
        let device = default_device();
        let mut enabled = 0u16;

        for queue_id in 0u16..2 {
            config.write(0x16, queue_id.as_slice(), device.clone());

            // Initially queue should be disabled
            config.read(0x1c, enabled.as_mut_slice(), device.clone());
            assert_eq!(enabled, 0);

            // Enable queue
            config.write(0x1c, 1u16.as_slice(), device.clone());
            config.read(0x1c, enabled.as_mut_slice(), device.clone());
            assert_eq!(enabled, 1);

            // According to the specification "The driver MUST NOT write a 0 to queue_enable."
            config.write(0x1c, 0u16.as_slice(), device.clone());
            config.read(0x1c, enabled.as_mut_slice(), device.clone());
            assert_eq!(enabled, 1);
        }
    }

    #[test]
    fn test_queue_notify_off() {
        let mut config = default_pci_common_config();
        let device = default_device();
        let mut offset = 0u16;

        // `queue_notify_off` is an offset (index not bytes) from the notification structure
        // that helps locate the address of the queue notify within the device's BAR. This is
        // a field setup by the device and should be read-only for the driver

        for queue_id in 0u16..2 {
            config.write(0x16, queue_id.as_slice(), device.clone());
            config.read(0x1e, offset.as_mut_slice(), device.clone());
            assert_eq!(offset, queue_id);

            // Writing to it should not have any effect
            config.write(0x1e, 0x42.as_slice(), device.clone());
            config.read(0x1e, offset.as_mut_slice(), device.clone());
            assert_eq!(offset, queue_id);
        }
    }

    fn write_64bit_field(
        config: &mut VirtioPciCommonConfig,
        device: Arc<Mutex<DummyDevice>>,
        offset: u64,
        value: u64,
    ) {
        let lo32 = (value & 0xffff_ffff) as u32;
        let hi32 = (value >> 32) as u32;

        config.write(offset, lo32.as_slice(), device.clone());
        config.write(offset + 4, hi32.as_slice(), device.clone());
    }

    fn read_64bit_field(
        config: &mut VirtioPciCommonConfig,
        device: Arc<Mutex<DummyDevice>>,
        offset: u64,
    ) -> u64 {
        let mut lo32 = 0u32;
        let mut hi32 = 0u32;

        config.read(offset, lo32.as_mut_slice(), device.clone());
        config.read(offset + 4, hi32.as_mut_slice(), device.clone());

        (lo32 as u64) | ((hi32 as u64) << 32)
    }

    #[test]
    fn test_queue_addresses() {
        let mut config = default_pci_common_config();
        let device = default_device();
        let mut reg64bit = 0;

        for queue_id in 0u16..2 {
            config.write(0x16, queue_id.as_slice(), device.clone());

            for offset in [0x20, 0x28, 0x30] {
                write_64bit_field(&mut config, device.clone(), offset, 0x0000_1312_0000_1110);
                assert_eq!(
                    read_64bit_field(&mut config, device.clone(), offset),
                    0x0000_1312_0000_1110
                );
            }
        }
    }

    #[test]
    fn test_bad_width_reads() {
        let mut config = default_pci_common_config();
        let mut device = default_device();

        // According to the VirtIO specification (section 4.1.3.1)
        //
        // > For device configuration access, the driver MUST use 8-bit wide accesses for 8-bit
        // > wide fields, 16-bit wide and aligned accesses for 16-bit wide fields and 32-bit wide
        // > and aligned accesses for 32-bit and 64-bit wide fields. For 64-bit fields, the driver
        // > MAY access each of the high and low 32-bit parts of the field independently.

        // 64-bit fields
        device.lock().unwrap().queues_mut()[0].desc_table_address =
            GuestAddress(0x0000_1312_0000_1110);
        let mut buffer = [0u8; 8];
        config.read(0x20, &mut buffer[..1], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0x20, &mut buffer[..2], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0x20, &mut buffer[..8], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0x20, &mut buffer[..4], device.clone());
        assert_eq!(LittleEndian::read_u32(&buffer[..4]), 0x1110);
        config.read(0x24, &mut buffer[..4], device.clone());
        assert_eq!(LittleEndian::read_u32(&buffer[..4]), 0x1312);

        // 32-bit fields
        config.device_feature_select = 0x42;
        let mut buffer = [0u8; 8];
        config.read(0, &mut buffer[..1], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0, &mut buffer[..2], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0, &mut buffer[..8], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0, &mut buffer[..4], device.clone());
        assert_eq!(LittleEndian::read_u32(&buffer[..4]), 0x42);

        // 16-bit fields
        let mut buffer = [0u8; 8];
        config.queue_select = 0x42;
        config.read(0x16, &mut buffer[..1], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0x16, &mut buffer[..4], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0x16, &mut buffer[..8], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0x16, &mut buffer[..2], device.clone());
        assert_eq!(LittleEndian::read_u16(&buffer[..2]), 0x42);

        // 8-bit fields
        let mut buffer = [0u8; 8];
        config.driver_status = 0x42;
        config.read(0x14, &mut buffer[..2], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0x14, &mut buffer[..4], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0x14, &mut buffer[..8], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(0x14, &mut buffer[..1], device.clone());
        assert_eq!(buffer[0], 0x42);
    }
}
