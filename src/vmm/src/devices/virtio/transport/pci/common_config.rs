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
use crate::devices::virtio::transport::pci::common_config_offset::*;
use crate::devices::virtio::transport::pci::device::VIRTQ_MSI_NO_VECTOR;
use crate::devices::virtio::transport::pci::device_status::*;
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

    pub fn write(
        &mut self,
        offset: u64,
        data: &[u8],
        device: Arc<Mutex<dyn VirtioDevice>>,
        device_activated: bool,
    ) {
        assert!(data.len() <= 8);

        match data.len() {
            1 => self.write_common_config_byte(offset, data[0], device_activated),
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
            DEVICE_STATUS => self.driver_status,
            CONFIG_GENERATION => self.config_generation,
            _ => {
                warn!("pci: invalid virtio config byte read: 0x{:x}", offset);
                0
            }
        }
    }

    fn write_common_config_byte(&mut self, offset: u64, value: u8, device_activated: bool) {
        match offset {
            DEVICE_STATUS => self.set_device_status(value, device_activated),
            _ => {
                warn!("pci: invalid virtio config byte write: 0x{:x}", offset);
            }
        }
    }

    fn set_device_status(&mut self, status: u8, device_activated: bool) {
        /// Enforce the device status state machine per the virtio spec:
        ///   INIT -> ACKNOWLEDGE -> DRIVER -> FEATURES_OK -> DRIVER_OK
        /// https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1220001
        ///
        /// Each step sets exactly one new bit while preserving all previous bits.
        const VALID_TRANSITIONS: &[(u8, u8)] = &[
            (INIT, ACKNOWLEDGE),
            (ACKNOWLEDGE, ACKNOWLEDGE | DRIVER),
            (ACKNOWLEDGE | DRIVER, ACKNOWLEDGE | DRIVER | FEATURES_OK),
            (
                ACKNOWLEDGE | DRIVER | FEATURES_OK,
                ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
            ),
        ];

        if (status & FAILED) != 0 {
            // Something went wrong in the guest.
            //
            // https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-110001
            // > FAILED (128)
            // >     Indicates that something went wrong in the guest, and it has given up on the
            // >     device.
            self.driver_status |= FAILED;
        } else if status == INIT {
            // Reset requested by the driver.
            //
            // https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1430001
            // > The device MUST reset when 0 is written to device_status, and present a 0 in
            // > device_status once that is done.
            //
            // https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1440002
            // > After writing 0 to device_status, the driver MUST wait for a read of device_status
            // > to return 0 before reinitializing the device.
            //
            // https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-200001
            // > 2.4.1 Device Requirements: Device Reset
            // > A device MUST reinitialize device status to 0 after receiving a reset.
            //
            // Setting INIT (0) here before the actual reset completes in write_bar() may appear
            // racy - the driver could read 0 before the device is fully torn down.  But concurrent
            // access is serialized since VirtioPciDevice is accessed through Arc<Mutex<>>.
            self.driver_status = INIT;
        } else if VALID_TRANSITIONS
            .iter()
            .any(|&(from, to)| self.driver_status == from && status == to)
        {
            if !device_activated {
                self.driver_status = status;
            } else {
                // If the device doesn't implement reset(), the device is left activated.
                // Re-initialization against a still-live backend device MUST be rejected.
                warn!(
                    "pci: rejecting device status transition {:#x} -> {:#x}: \
                     previous reset did not complete successfully and device is still active",
                    self.driver_status, status
                );
            }
        } else {
            warn!(
                "pci: invalid virtio device status transition: {:#x} -> {:#x}",
                self.driver_status, status
            );
        }
    }

    fn read_common_config_word(&self, offset: u64, queues: &[Queue]) -> u16 {
        match offset {
            MSIX_CONFIG => self.msix_config.load(Ordering::Acquire),
            NUM_QUEUES => queues.len().try_into().unwrap(),
            QUEUE_SELECT => self.queue_select,
            QUEUE_SIZE => self.with_queue(queues, |q| q.size).unwrap_or(0),
            // If `queue_select` points to an invalid queue we should return NO_VECTOR.
            // Reading from here
            // https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-1280005:
            //
            // > The device MUST return vector mapped to a given event, (NO_VECTOR if unmapped) on
            // > read of config_msix_vector/queue_msix_vector.
            QUEUE_MSIX_VECTOR => self
                .msix_queues
                .lock()
                .unwrap()
                .get(self.queue_select as usize)
                .copied()
                .unwrap_or(VIRTQ_MSI_NO_VECTOR),
            QUEUE_ENABLE => u16::from(self.with_queue(queues, |q| q.ready).unwrap_or(false)),
            QUEUE_NOTIFY_OFF => self.queue_select,
            _ => {
                warn!("pci: invalid virtio register word read: 0x{:x}", offset);
                0
            }
        }
    }

    /// Guard queue configuration field writes based on device status.
    ///
    /// Per the virtio spec, the driver SHALL follow this sequence:
    ///   INIT -> ACKNOWLEDGE -> DRIVER -> FEATURES_OK -> DRIVER_OK
    /// https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1220001
    ///
    /// Queue configuration must only be done between FEATURES_OK and DRIVER_OK.
    fn update_queue_field<F: FnOnce(&mut Queue)>(&mut self, queues: &mut [Queue], f: F) {
        let status = self.driver_status;
        if status == (ACKNOWLEDGE | DRIVER | FEATURES_OK) {
            self.with_queue_mut(queues, f);
        } else {
            warn!(
                "pci: queue config write not allowed in device status {:#x}",
                status
            );
        }
    }

    fn write_common_config_word(&mut self, offset: u64, value: u16, queues: &mut [Queue]) {
        match offset {
            MSIX_CONFIG => {
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
            QUEUE_SELECT => self.queue_select = value,
            QUEUE_SIZE => self.update_queue_field(queues, |q| q.size = value),
            QUEUE_MSIX_VECTOR => {
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
            QUEUE_ENABLE => self.update_queue_field(queues, |q| {
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
            DEVICE_FEATURE_SELECT => self.device_feature_select,
            DEVICE_FEATURE => {
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
            DRIVER_FEATURE_SELECT => self.driver_feature_select,
            QUEUE_DESC_LO => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.desc_table_address.0 & 0xffff_ffff) as u32
                })
                .unwrap_or_default()
            }
            QUEUE_DESC_HI => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.desc_table_address.0 >> 32) as u32
                })
                .unwrap_or_default()
            }
            QUEUE_AVAIL_LO => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.avail_ring_address.0 & 0xffff_ffff) as u32
                })
                .unwrap_or_default()
            }
            QUEUE_AVAIL_HI => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.avail_ring_address.0 >> 32) as u32
                })
                .unwrap_or_default()
            }
            QUEUE_USED_LO => {
                let locked_device = device.lock().unwrap();
                self.with_queue(locked_device.queues(), |q| {
                    (q.used_ring_address.0 & 0xffff_ffff) as u32
                })
                .unwrap_or_default()
            }
            QUEUE_USED_HI => {
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
            DEVICE_FEATURE_SELECT => self.device_feature_select = value,
            DRIVER_FEATURE_SELECT => self.driver_feature_select = value,
            DRIVER_FEATURE => {
                // Feature negotiation is only allowed in DRIVER state.
                // https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1220001
                if self.driver_status == (ACKNOWLEDGE | DRIVER) {
                    locked_device.ack_features_by_page(self.driver_feature_select, value);
                } else {
                    warn!(
                        "pci: feature negotiation not allowed in device state {:#x}",
                        self.driver_status
                    );
                }
            }
            QUEUE_DESC_LO => self.update_queue_field(locked_device.queues_mut(), |q| {
                lo(&mut q.desc_table_address, value)
            }),
            QUEUE_DESC_HI => self.update_queue_field(locked_device.queues_mut(), |q| {
                hi(&mut q.desc_table_address, value)
            }),
            QUEUE_AVAIL_LO => self.update_queue_field(locked_device.queues_mut(), |q| {
                lo(&mut q.avail_ring_address, value)
            }),
            QUEUE_AVAIL_HI => self.update_queue_field(locked_device.queues_mut(), |q| {
                hi(&mut q.avail_ring_address, value)
            }),
            QUEUE_USED_LO => self.update_queue_field(locked_device.queues_mut(), |q| {
                lo(&mut q.used_ring_address, value)
            }),
            QUEUE_USED_HI => self.update_queue_field(locked_device.queues_mut(), |q| {
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
    use crate::devices::virtio::transport::pci::common_config_offset::*;

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

        // The config generation register is read only.
        regs.write(CONFIG_GENERATION, &[0xaa], dev.clone(), false);
        let mut read_back = vec![0x00];
        regs.read(CONFIG_GENERATION, &mut read_back, dev.clone());
        assert_eq!(read_back[0], 0x55);

        // Device features is read-only and passed through from the device.
        regs.write(DEVICE_FEATURE, &[1, 2, 3, 4], dev.clone(), false);
        let mut read_back = vec![0, 0, 0, 0];
        regs.read(DEVICE_FEATURE, &mut read_back, dev.clone());
        assert_eq!(LittleEndian::read_u32(&read_back), 0u32);

        // Feature select registers are read/write.
        regs.write(DEVICE_FEATURE_SELECT, &[1, 2, 3, 4], dev.clone(), false);
        let mut read_back = vec![0, 0, 0, 0];
        regs.read(DEVICE_FEATURE_SELECT, &mut read_back, dev.clone());
        assert_eq!(LittleEndian::read_u32(&read_back), 0x0403_0201);
        regs.write(DRIVER_FEATURE_SELECT, &[1, 2, 3, 4], dev.clone(), false);
        let mut read_back = vec![0, 0, 0, 0];
        regs.read(DRIVER_FEATURE_SELECT, &mut read_back, dev.clone());
        assert_eq!(LittleEndian::read_u32(&read_back), 0x0403_0201);

        // 'queue_select' can be read and written.
        regs.write(QUEUE_SELECT, &[0xaa, 0x55], dev.clone(), false);
        let mut read_back = vec![0x00, 0x00];
        regs.read(QUEUE_SELECT, &mut read_back, dev.clone());
        assert_eq!(read_back[0], 0xaa);
        assert_eq!(read_back[1], 0x55);

        // Getting the MSI vector when `queue_select` points to an invalid queue should return
        // NO_VECTOR (0xffff)
        regs.read(QUEUE_MSIX_VECTOR, &mut read_back, dev.clone());
        assert_eq!(read_back, [0xff, 0xff]);

        // Writing the MSI vector of an invalid `queue_select` does not have any effect.
        regs.write(QUEUE_MSIX_VECTOR, &[0x12, 0x13], dev.clone(), false);
        assert_eq!(read_back, [0xff, 0xff]);
        // Valid `queue_select` though should setup the corresponding MSI-X queue.
        regs.write(QUEUE_SELECT, &[0x1, 0x0], dev.clone(), false);
        assert_eq!(regs.queue_select, 1);
        regs.write(QUEUE_MSIX_VECTOR, &[0x1, 0x0], dev.clone(), false);
        regs.read(QUEUE_MSIX_VECTOR, &mut read_back, dev);
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

        config.read(DEVICE_FEATURE, features.as_mut_slice(), device.clone());
        assert_eq!(features, 0x1110);
        // select second page
        config.write(
            DEVICE_FEATURE_SELECT,
            1u32.as_slice(),
            device.clone(),
            false,
        );
        config.read(DEVICE_FEATURE, features.as_mut_slice(), device.clone());
        assert_eq!(features, 0x1312);
        // Try a third page. It doesn't exist so we should get all 0s
        config.write(
            DEVICE_FEATURE_SELECT,
            2u32.as_slice(),
            device.clone(),
            false,
        );
        config.read(DEVICE_FEATURE, features.as_mut_slice(), device.clone());
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

        // Feature negotiation requires DRIVER state (ACKNOWLEDGE | DRIVER).
        config.set_device_status(ACKNOWLEDGE, false);
        config.set_device_status(ACKNOWLEDGE | DRIVER, false);

        // ACK some features of the first page
        config.write(DRIVER_FEATURE, 0x1100u32.as_slice(), device.clone(), false);
        assert_eq!(device.lock().unwrap().acked_features(), 0x1100);
        // ACK some features of the second page
        config.write(
            DRIVER_FEATURE_SELECT,
            1u32.as_slice(),
            device.clone(),
            false,
        );
        config.write(
            DRIVER_FEATURE,
            0x0000_1310u32.as_slice(),
            device.clone(),
            false,
        );
        assert_eq!(
            device.lock().unwrap().acked_features(),
            0x0000_1310_0000_1100
        );

        // After FEATURES_OK, further feature writes should be rejected.
        config.set_device_status(ACKNOWLEDGE | DRIVER | FEATURES_OK, false);
        config.write(
            DRIVER_FEATURE_SELECT,
            0u32.as_slice(),
            device.clone(),
            false,
        );
        config.write(
            DRIVER_FEATURE,
            0xFFFF_FFFFu32.as_slice(),
            device.clone(),
            false,
        );
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

        config.read(NUM_QUEUES, num_queues.as_mut_slice(), device.clone());
        assert_eq!(num_queues, 2);
        // `num_queues` is read-only
        config.write(NUM_QUEUES, 4u16.as_slice(), device.clone(), false);
        config.read(NUM_QUEUES, num_queues.as_mut_slice(), device.clone());
        assert_eq!(num_queues, 2);
    }

    #[test]
    fn test_device_status() {
        let mut config = default_pci_common_config();
        let device = default_device();
        let mut status = 0u8;

        // Initial status should be INIT (0)
        config.read(DEVICE_STATUS, status.as_mut_slice(), device.clone());
        assert_eq!(status, 0);

        // Valid state transitions
        config.write(DEVICE_STATUS, ACKNOWLEDGE.as_slice(), device.clone(), false);
        config.read(DEVICE_STATUS, status.as_mut_slice(), device.clone());
        assert_eq!(status, ACKNOWLEDGE);

        config.write(
            DEVICE_STATUS,
            (ACKNOWLEDGE | DRIVER).as_slice(),
            device.clone(),
            false,
        );
        config.read(DEVICE_STATUS, status.as_mut_slice(), device.clone());
        assert_eq!(status, ACKNOWLEDGE | DRIVER);

        config.write(
            DEVICE_STATUS,
            (ACKNOWLEDGE | DRIVER | FEATURES_OK).as_slice(),
            device.clone(),
            false,
        );
        config.read(DEVICE_STATUS, status.as_mut_slice(), device.clone());
        assert_eq!(status, ACKNOWLEDGE | DRIVER | FEATURES_OK);

        config.write(
            DEVICE_STATUS,
            (ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK).as_slice(),
            device.clone(),
            false,
        );
        config.read(DEVICE_STATUS, status.as_mut_slice(), device.clone());
        assert_eq!(status, ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);

        // Reset should always work
        config.write(DEVICE_STATUS, INIT.as_slice(), device.clone(), true);
        config.read(DEVICE_STATUS, status.as_mut_slice(), device.clone());
        assert_eq!(status, INIT);
    }

    #[test]
    fn test_device_status_invalid_transitions() {
        let mut config = default_pci_common_config();
        let device = default_device();

        // Helper to attempt a transition and verify it was rejected.
        let mut assert_rejected = |config: &mut VirtioPciCommonConfig, new: u8, expected: u8| {
            config.write(DEVICE_STATUS, new.as_slice(), device.clone(), false);
            let mut s = 0u8;
            config.read(DEVICE_STATUS, s.as_mut_slice(), device.clone());
            assert_eq!(s, expected, "transition to {new:#x} should be rejected");
        };

        // Check the initial state is INIT (0)
        let mut status = 0;
        config.read(DEVICE_STATUS, status.as_mut_slice(), device.clone());
        assert_eq!(status, INIT);

        // Skip ACKNOWLEDGE: INIT -> ACKNOWLEDGE | DRIVER
        assert_rejected(&mut config, ACKNOWLEDGE | DRIVER, INIT);
        // Arbitrary value from INIT
        assert_rejected(&mut config, 0x42, INIT);

        // Advance to ACKNOWLEDGE | DRIVER | FEATURES_OK
        config.write(DEVICE_STATUS, ACKNOWLEDGE.as_slice(), device.clone(), false);
        config.write(
            DEVICE_STATUS,
            (ACKNOWLEDGE | DRIVER).as_slice(),
            device.clone(),
            false,
        );
        config.write(
            DEVICE_STATUS,
            (ACKNOWLEDGE | DRIVER | FEATURES_OK).as_slice(),
            device.clone(),
            false,
        );
        let expected = ACKNOWLEDGE | DRIVER | FEATURES_OK;

        // Go back: FEATURES_OK -> DRIVER
        assert_rejected(&mut config, ACKNOWLEDGE | DRIVER, expected);
        // Valid transition FEATURES_OK -> DRIVER_OK but without cumulative bits
        assert_rejected(&mut config, DRIVER_OK, expected);

        // Advance to FEATURES_OK
        config.write(
            DEVICE_STATUS,
            (ACKNOWLEDGE | DRIVER | FEATURES_OK).as_slice(),
            device.clone(),
            false,
        );
        let expected = ACKNOWLEDGE | DRIVER | FEATURES_OK;

        // Go back from FEATURES_OK
        assert_rejected(&mut config, ACKNOWLEDGE | DRIVER, expected);
    }

    #[test]
    fn test_device_activated_blocks_transitions() {
        let mut config = default_pci_common_config();
        let device = default_device();
        let mut status = 0u8;

        // Simulate a failed reset: driver_status is INIT but device is still activated.
        config.read(DEVICE_STATUS, status.as_mut_slice(), device.clone());
        assert_eq!(status, INIT);

        // Every transition should be rejected when device_activated is true at INIT.
        for &value in &[
            ACKNOWLEDGE,
            ACKNOWLEDGE | DRIVER,
            ACKNOWLEDGE | DRIVER | FEATURES_OK,
            ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
        ] {
            config.write(DEVICE_STATUS, value.as_slice(), device.clone(), true);
            config.read(DEVICE_STATUS, status.as_mut_slice(), device.clone());
            assert_eq!(
                status, INIT,
                "transition to {value:#x} should be blocked while device is activated"
            );
        }
    }

    #[test]
    fn test_config_msix_vector() {
        let mut config = default_pci_common_config();
        let device = default_device();
        let mut vector: u16 = 0;

        // Our device has 2 queues, so we should be using 3 vectors in total.
        // Trying to set a vector bigger than that should fail. Observing the
        // failure happens through a subsequent read that should return NO_VECTOR.
        config.write(MSIX_CONFIG, 3u16.as_slice(), device.clone(), false);
        config.read(MSIX_CONFIG, vector.as_mut_slice(), device.clone());
        assert_eq!(vector, VIRTQ_MSI_NO_VECTOR);

        // Any of the 3 valid values should work
        for i in 0u16..3 {
            config.write(MSIX_CONFIG, i.as_slice(), device.clone(), false);
            config.read(MSIX_CONFIG, vector.as_mut_slice(), device.clone());
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
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);
            config.read(QUEUE_SIZE, len.as_mut_slice(), device.clone());
            assert_eq!(
                len,
                device.lock().unwrap().queues()[queue_id as usize].max_size
            );
            max_size[queue_id as usize] = len;
        }

        // Before FEATURES_OK is set, the driver should not be able to change the queue size.
        config.driver_status = ACKNOWLEDGE | DRIVER;
        for queue_id in 0u16..2 {
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);
            config.write(QUEUE_SIZE, 0u16.as_slice(), device.clone(), false);
            config.read(QUEUE_SIZE, len.as_mut_slice(), device.clone());
            assert_eq!(len, max_size[queue_id as usize]);
        }

        // Verify writing a queue size to a non-existent queue is ignored.
        config.write(QUEUE_SELECT, 2u16.as_slice(), device.clone(), false);
        config.read(QUEUE_SIZE, len.as_mut_slice(), device.clone());
        assert_eq!(len, 0);

        // Set FEATURES_OK so that the driver can change the queue size.
        config.driver_status |= FEATURES_OK;

        // Setup size smaller than what is the maximum offered
        for queue_id in 0u16..2 {
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);
            config.write(
                QUEUE_SIZE,
                (max_size[queue_id as usize] - 1).as_slice(),
                device.clone(),
                false,
            );
            config.read(QUEUE_SIZE, len.as_mut_slice(), device.clone());
            assert_eq!(len, max_size[queue_id as usize] - 1);
        }

        // Verify writes are rejected after DRIVER_OK is set.
        config.driver_status |= DRIVER_OK;
        config.write(QUEUE_SELECT, 0u16.as_slice(), device.clone(), false);
        config.write(QUEUE_SIZE, 0u16.as_slice(), device.clone(), false);
        config.read(QUEUE_SIZE, len.as_mut_slice(), device.clone());
        assert_eq!(len, max_size[0] - 1);
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
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);

            config.write(QUEUE_MSIX_VECTOR, 3u16.as_slice(), device.clone(), false);
            config.read(QUEUE_MSIX_VECTOR, vector.as_mut_slice(), device.clone());
            assert_eq!(vector, VIRTQ_MSI_NO_VECTOR);

            // Any of the 3 valid values should work
            for vector_id in 0u16..3 {
                config.write(
                    QUEUE_MSIX_VECTOR,
                    vector_id.as_slice(),
                    device.clone(),
                    false,
                );
                config.read(QUEUE_MSIX_VECTOR, vector.as_mut_slice(), device.clone());
                assert_eq!(vector, vector_id);
            }
        }
    }

    #[test]
    fn test_queue_enable() {
        let mut config = default_pci_common_config();
        let device = default_device();
        let mut enabled = 0u16;

        // Initially queue should be disabled
        for queue_id in 0u16..2 {
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);
            config.read(QUEUE_ENABLE, enabled.as_mut_slice(), device.clone());
            assert_eq!(enabled, 0);
        }

        // Enabling a queue before FEATURES_OK should be ignored.
        config.driver_status = ACKNOWLEDGE | DRIVER;
        for queue_id in 0u16..2 {
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);
            config.write(QUEUE_ENABLE, 1u16.as_slice(), device.clone(), false);
            config.read(QUEUE_ENABLE, enabled.as_mut_slice(), device.clone());
            assert_eq!(enabled, 0);
        }

        // Set FEATURES_OK so that the driver can enable the queue.
        config.driver_status |= FEATURES_OK;
        for queue_id in 0u16..2 {
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);
            config.write(QUEUE_ENABLE, 1u16.as_slice(), device.clone(), false);
            config.read(QUEUE_ENABLE, enabled.as_mut_slice(), device.clone());
            assert_eq!(enabled, 1);

            // The driver MUST NOT write a 0 to queue_enable.
            config.write(QUEUE_ENABLE, 0u16.as_slice(), device.clone(), false);
            config.read(QUEUE_ENABLE, enabled.as_mut_slice(), device.clone());
            assert_eq!(enabled, 1);
        }

        // Verify writes are rejected after DRIVER_OK
        config.driver_status |= DRIVER_OK;
        for queue_id in 0u16..2 {
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);
            config.write(QUEUE_ENABLE, 0u16.as_slice(), device.clone(), false);
            config.read(QUEUE_ENABLE, enabled.as_mut_slice(), device.clone());
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
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);
            config.read(QUEUE_NOTIFY_OFF, offset.as_mut_slice(), device.clone());
            assert_eq!(offset, queue_id);

            // Writing to it should not have any effect
            config.write(QUEUE_NOTIFY_OFF, 0x42.as_slice(), device.clone(), false);
            config.read(QUEUE_NOTIFY_OFF, offset.as_mut_slice(), device.clone());
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

        config.write(offset, lo32.as_slice(), device.clone(), false);
        config.write(offset + 4, hi32.as_slice(), device.clone(), false);
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

        // Before FEATURES_OK is set, the driver should not be able to change the queue addresses.
        config.driver_status = ACKNOWLEDGE | DRIVER;
        for queue_id in 0u16..2 {
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);

            for offset in [QUEUE_DESC_LO, QUEUE_AVAIL_LO, QUEUE_USED_LO] {
                write_64bit_field(&mut config, device.clone(), offset, 0x0000_1312_0000_1110);
                assert_eq!(read_64bit_field(&mut config, device.clone(), offset), 0);
            }
        }

        // Set status so queue fields can be modified
        config.driver_status |= FEATURES_OK;
        for queue_id in 0u16..2 {
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);

            for offset in [QUEUE_DESC_LO, QUEUE_AVAIL_LO, QUEUE_USED_LO] {
                write_64bit_field(&mut config, device.clone(), offset, 0x0000_1312_0000_1110);
                assert_eq!(
                    read_64bit_field(&mut config, device.clone(), offset),
                    0x0000_1312_0000_1110
                );
            }
        }

        // Verify writes are rejected after DRIVER_OK
        config.driver_status |= DRIVER_OK;
        for queue_id in 0u16..2 {
            config.write(QUEUE_SELECT, queue_id.as_slice(), device.clone(), false);

            for offset in [QUEUE_DESC_LO, QUEUE_AVAIL_LO, QUEUE_USED_LO] {
                write_64bit_field(&mut config, device.clone(), offset, 0xDEAD_BEEF);
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
        config.read(QUEUE_DESC_LO, &mut buffer[..1], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(QUEUE_DESC_LO, &mut buffer[..2], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(QUEUE_DESC_LO, &mut buffer[..8], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(QUEUE_DESC_LO, &mut buffer[..4], device.clone());
        assert_eq!(LittleEndian::read_u32(&buffer[..4]), 0x1110);
        config.read(QUEUE_DESC_HI, &mut buffer[..4], device.clone());
        assert_eq!(LittleEndian::read_u32(&buffer[..4]), 0x1312);

        // 32-bit fields
        config.device_feature_select = 0x42;
        let mut buffer = [0u8; 8];
        config.read(DEVICE_FEATURE_SELECT, &mut buffer[..1], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(DEVICE_FEATURE_SELECT, &mut buffer[..2], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(DEVICE_FEATURE_SELECT, &mut buffer[..8], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(DEVICE_FEATURE_SELECT, &mut buffer[..4], device.clone());
        assert_eq!(LittleEndian::read_u32(&buffer[..4]), 0x42);

        // 16-bit fields
        let mut buffer = [0u8; 8];
        config.queue_select = 0x42;
        config.read(QUEUE_SELECT, &mut buffer[..1], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(QUEUE_SELECT, &mut buffer[..4], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(QUEUE_SELECT, &mut buffer[..8], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(QUEUE_SELECT, &mut buffer[..2], device.clone());
        assert_eq!(LittleEndian::read_u16(&buffer[..2]), 0x42);

        // 8-bit fields
        let mut buffer = [0u8; 8];
        config.driver_status = 0x42;
        config.read(DEVICE_STATUS, &mut buffer[..2], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(DEVICE_STATUS, &mut buffer[..4], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(DEVICE_STATUS, &mut buffer[..8], device.clone());
        assert_eq!(buffer, [0u8; 8]);
        config.read(DEVICE_STATUS, &mut buffer[..1], device.clone());
        assert_eq!(buffer[0], 0x42);
    }
}
