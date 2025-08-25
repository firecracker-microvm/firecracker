// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::{Arc, Barrier, Mutex};

use byteorder::{ByteOrder, LittleEndian};
use vm_device::BusDevice;

use crate::configuration::{PciBridgeSubclass, PciClassCode, PciConfiguration, PciHeaderType};
use crate::device::{DeviceRelocation, Error as PciDeviceError, PciDevice};

const VENDOR_ID_INTEL: u16 = 0x8086;
const DEVICE_ID_INTEL_VIRT_PCIE_HOST: u16 = 0x0d57;
const NUM_DEVICE_IDS: usize = 32;

/// Errors for device manager.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PciRootError {
    /// Could not allocate device address space for the device.
    AllocateDeviceAddrs(PciDeviceError),
    /// Could not allocate an IRQ number.
    AllocateIrq,
    /// Could not add a device to the port io bus.
    PioInsert(vm_device::BusError),
    /// Could not add a device to the mmio bus.
    MmioInsert(vm_device::BusError),
    /// Could not find an available device slot on the PCI bus.
    NoPciDeviceSlotAvailable,
    /// Invalid PCI device identifier provided.
    InvalidPciDeviceSlot(usize),
    /// Valid PCI device identifier but already used.
    AlreadyInUsePciDeviceSlot(usize),
}
pub type Result<T> = std::result::Result<T, PciRootError>;

/// Emulates the PCI Root bridge device.
pub struct PciRoot {
    /// Configuration space.
    config: PciConfiguration,
}

impl PciRoot {
    /// Create an empty PCI root bridge.
    pub fn new(config: Option<PciConfiguration>) -> Self {
        if let Some(config) = config {
            PciRoot { config }
        } else {
            PciRoot {
                config: PciConfiguration::new(
                    VENDOR_ID_INTEL,
                    DEVICE_ID_INTEL_VIRT_PCIE_HOST,
                    0,
                    PciClassCode::BridgeDevice,
                    &PciBridgeSubclass::HostBridge,
                    None,
                    PciHeaderType::Device,
                    0,
                    0,
                    None,
                    None,
                ),
            }
        }
    }
}

impl BusDevice for PciRoot {}

impl PciDevice for PciRoot {
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        self.config.write_config_register(reg_idx, offset, data);
        None
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.config.read_reg(reg_idx)
    }
}

pub struct PciBus {
    /// Devices attached to this bus.
    /// Device 0 is host bridge.
    pub devices: HashMap<u32, Arc<Mutex<dyn PciDevice>>>,
    device_reloc: Arc<dyn DeviceRelocation>,
    device_ids: Vec<bool>,
}

impl PciBus {
    pub fn new(pci_root: PciRoot, device_reloc: Arc<dyn DeviceRelocation>) -> Self {
        let mut devices: HashMap<u32, Arc<Mutex<dyn PciDevice>>> = HashMap::new();
        let mut device_ids: Vec<bool> = vec![false; NUM_DEVICE_IDS];

        devices.insert(0, Arc::new(Mutex::new(pci_root)));
        device_ids[0] = true;

        PciBus {
            devices,
            device_reloc,
            device_ids,
        }
    }

    pub fn add_device(&mut self, device_id: u32, device: Arc<Mutex<dyn PciDevice>>) -> Result<()> {
        self.devices.insert(device_id, device);
        Ok(())
    }

    pub fn next_device_id(&mut self) -> Result<u32> {
        for (idx, device_id) in self.device_ids.iter_mut().enumerate() {
            if !(*device_id) {
                *device_id = true;
                return Ok(idx as u32);
            }
        }

        Err(PciRootError::NoPciDeviceSlotAvailable)
    }
}

pub struct PciConfigIo {
    /// Config space register.
    config_address: u32,
    pci_bus: Arc<Mutex<PciBus>>,
}

impl PciConfigIo {
    pub fn new(pci_bus: Arc<Mutex<PciBus>>) -> Self {
        PciConfigIo {
            config_address: 0,
            pci_bus,
        }
    }

    pub fn config_space_read(&self) -> u32 {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return 0xffff_ffff;
        }

        let (bus, device, function, register) =
            parse_io_config_address(self.config_address & !0x8000_0000);

        // Only support one bus.
        if bus != 0 {
            return 0xffff_ffff;
        }

        // Don't support multi-function devices.
        if function > 0 {
            return 0xffff_ffff;
        }

        // NOTE: Potential contention among vCPU threads on this lock. This should not
        // be a problem currently, since we mainly access this when we are setting up devices.
        // We might want to do some profiling to ensure this does not become a bottleneck.
        self.pci_bus
            .as_ref()
            .lock()
            .unwrap()
            .devices
            .get(&(device as u32))
            .map_or(0xffff_ffff, |d| {
                d.lock().unwrap().read_config_register(register)
            })
    }

    pub fn config_space_write(&mut self, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if offset as usize + data.len() > 4 {
            return None;
        }

        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return None;
        }

        let (bus, device, function, register) =
            parse_io_config_address(self.config_address & !0x8000_0000);

        // Only support one bus.
        if bus != 0 {
            return None;
        }

        // Don't support multi-function devices.
        if function > 0 {
            return None;
        }

        // NOTE: Potential contention among vCPU threads on this lock. This should not
        // be a problem currently, since we mainly access this when we are setting up devices.
        // We might want to do some profiling to ensure this does not become a bottleneck.
        let pci_bus = self.pci_bus.as_ref().lock().unwrap();
        if let Some(d) = pci_bus.devices.get(&(device as u32)) {
            let mut device = d.lock().unwrap();

            // Find out if one of the device's BAR is being reprogrammed, and
            // reprogram it if needed.
            if let Some(params) = device.detect_bar_reprogramming(register, data) {
                if let Err(e) = pci_bus.device_reloc.move_bar(
                    params.old_base,
                    params.new_base,
                    params.len,
                    device.deref_mut(),
                    params.region_type,
                ) {
                    error!(
                        "Failed moving device BAR: {}: 0x{:x}->0x{:x}(0x{:x})",
                        e, params.old_base, params.new_base, params.len
                    );
                }
            }

            // Update the register value
            device.write_config_register(register, offset, data)
        } else {
            None
        }
    }

    fn set_config_address(&mut self, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }
        let (mask, value): (u32, u32) = match data.len() {
            1 => (
                0x0000_00ff << (offset * 8),
                u32::from(data[0]) << (offset * 8),
            ),
            2 => (
                0x0000_ffff << (offset * 8),
                ((u32::from(data[1]) << 8) | u32::from(data[0])) << (offset * 8),
            ),
            4 => (0xffff_ffff, LittleEndian::read_u32(data)),
            _ => return,
        };
        self.config_address = (self.config_address & !mask) | value;
    }
}

impl BusDevice for PciConfigIo {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        // Only allow reads to the register boundary.
        let start = offset as usize % 4;
        let end = start + data.len();
        if end > 4 {
            for d in data.iter_mut() {
                *d = 0xff;
            }
            return;
        }

        // `offset` is relative to 0xcf8
        let value = match offset {
            0..=3 => self.config_address,
            4..=7 => self.config_space_read(),
            _ => 0xffff_ffff,
        };

        for i in start..end {
            data[i - start] = (value >> (i * 8)) as u8;
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        // `offset` is relative to 0xcf8
        match offset {
            o @ 0..=3 => {
                self.set_config_address(o, data);
                None
            }
            o @ 4..=7 => self.config_space_write(o - 4, data),
            _ => None,
        }
    }
}

/// Emulates PCI memory-mapped configuration access mechanism.
pub struct PciConfigMmio {
    pci_bus: Arc<Mutex<PciBus>>,
}

impl PciConfigMmio {
    pub fn new(pci_bus: Arc<Mutex<PciBus>>) -> Self {
        PciConfigMmio { pci_bus }
    }

    fn config_space_read(&self, config_address: u32) -> u32 {
        let (bus, device, function, register) = parse_mmio_config_address(config_address);

        // Only support one bus.
        if bus != 0 {
            return 0xffff_ffff;
        }

        // Don't support multi-function devices.
        if function > 0 {
            return 0xffff_ffff;
        }

        self.pci_bus
            .lock()
            .unwrap()
            .devices
            .get(&(device as u32))
            .map_or(0xffff_ffff, |d| {
                d.lock().unwrap().read_config_register(register)
            })
    }

    fn config_space_write(&mut self, config_address: u32, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }

        let (bus, device, function, register) = parse_mmio_config_address(config_address);

        // Only support one bus.
        if bus != 0 {
            return;
        }

        // Don't support multi-function devices.
        if function > 0 {
            return;
        }

        let pci_bus = self.pci_bus.lock().unwrap();
        if let Some(d) = pci_bus.devices.get(&(device as u32)) {
            let mut device = d.lock().unwrap();

            // Find out if one of the device's BAR is being reprogrammed, and
            // reprogram it if needed.
            if let Some(params) = device.detect_bar_reprogramming(register, data) {
                if let Err(e) = pci_bus.device_reloc.move_bar(
                    params.old_base,
                    params.new_base,
                    params.len,
                    device.deref_mut(),
                    params.region_type,
                ) {
                    error!(
                        "Failed moving device BAR: {}: 0x{:x}->0x{:x}(0x{:x})",
                        e, params.old_base, params.new_base, params.len
                    );
                }
            }

            // Update the register value
            device.write_config_register(register, offset, data);
        }
    }
}

impl BusDevice for PciConfigMmio {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        // Only allow reads to the register boundary.
        let start = offset as usize % 4;
        let end = start + data.len();
        if end > 4 || offset > u64::from(u32::MAX) {
            for d in data {
                *d = 0xff;
            }
            return;
        }

        let value = self.config_space_read(offset as u32);
        for i in start..end {
            data[i - start] = (value >> (i * 8)) as u8;
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if offset > u64::from(u32::MAX) {
            return None;
        }
        self.config_space_write(offset as u32, offset % 4, data);

        None
    }
}

fn shift_and_mask(value: u32, offset: usize, mask: u32) -> usize {
    ((value >> offset) & mask) as usize
}

// Parse the MMIO address offset to a (bus, device, function, register) tuple.
// See section 7.2.2 PCI Express Enhanced Configuration Access Mechanism (ECAM)
// from the Pci Express Base Specification Revision 5.0 Version 1.0.
fn parse_mmio_config_address(config_address: u32) -> (usize, usize, usize, usize) {
    const BUS_NUMBER_OFFSET: usize = 20;
    const BUS_NUMBER_MASK: u32 = 0x00ff;
    const DEVICE_NUMBER_OFFSET: usize = 15;
    const DEVICE_NUMBER_MASK: u32 = 0x1f;
    const FUNCTION_NUMBER_OFFSET: usize = 12;
    const FUNCTION_NUMBER_MASK: u32 = 0x07;
    const REGISTER_NUMBER_OFFSET: usize = 2;
    const REGISTER_NUMBER_MASK: u32 = 0x3ff;

    (
        shift_and_mask(config_address, BUS_NUMBER_OFFSET, BUS_NUMBER_MASK),
        shift_and_mask(config_address, DEVICE_NUMBER_OFFSET, DEVICE_NUMBER_MASK),
        shift_and_mask(config_address, FUNCTION_NUMBER_OFFSET, FUNCTION_NUMBER_MASK),
        shift_and_mask(config_address, REGISTER_NUMBER_OFFSET, REGISTER_NUMBER_MASK),
    )
}

// Parse the CONFIG_ADDRESS register to a (bus, device, function, register) tuple.
fn parse_io_config_address(config_address: u32) -> (usize, usize, usize, usize) {
    const BUS_NUMBER_OFFSET: usize = 16;
    const BUS_NUMBER_MASK: u32 = 0x00ff;
    const DEVICE_NUMBER_OFFSET: usize = 11;
    const DEVICE_NUMBER_MASK: u32 = 0x1f;
    const FUNCTION_NUMBER_OFFSET: usize = 8;
    const FUNCTION_NUMBER_MASK: u32 = 0x07;
    const REGISTER_NUMBER_OFFSET: usize = 2;
    const REGISTER_NUMBER_MASK: u32 = 0x3f;

    (
        shift_and_mask(config_address, BUS_NUMBER_OFFSET, BUS_NUMBER_MASK),
        shift_and_mask(config_address, DEVICE_NUMBER_OFFSET, DEVICE_NUMBER_MASK),
        shift_and_mask(config_address, FUNCTION_NUMBER_OFFSET, FUNCTION_NUMBER_MASK),
        shift_and_mask(config_address, REGISTER_NUMBER_OFFSET, REGISTER_NUMBER_MASK),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};

    use vm_device::BusDevice;

    use super::{PciBus, PciConfigIo, PciConfigMmio, PciRoot};
    use crate::bus::{DEVICE_ID_INTEL_VIRT_PCIE_HOST, VENDOR_ID_INTEL};
    use crate::{
        DeviceRelocation, PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciClassCode,
        PciConfiguration, PciDevice, PciHeaderType, PciMassStorageSubclass,
    };

    #[derive(Debug, Default)]
    struct RelocationMock {
        reloc_cnt: AtomicUsize,
    }

    impl RelocationMock {
        fn cnt(&self) -> usize {
            self.reloc_cnt.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DeviceRelocation for RelocationMock {
        fn move_bar(
            &self,
            _old_base: u64,
            _new_base: u64,
            _len: u64,
            _pci_dev: &mut dyn crate::PciDevice,
            _region_type: crate::PciBarRegionType,
        ) -> std::result::Result<(), std::io::Error> {
            self.reloc_cnt
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    struct PciDevMock(PciConfiguration);

    impl PciDevMock {
        fn new() -> Self {
            let mut config = PciConfiguration::new(
                0x42,
                0x0,
                0x0,
                PciClassCode::MassStorage,
                &PciMassStorageSubclass::SerialScsiController,
                None,
                PciHeaderType::Device,
                0x13,
                0x12,
                None,
                None,
            );

            config
                .add_pci_bar(&PciBarConfiguration {
                    addr: 0x1000,
                    size: 0x1000,
                    idx: 0,
                    region_type: PciBarRegionType::Memory32BitRegion,
                    prefetchable: PciBarPrefetchable::Prefetchable,
                })
                .unwrap();

            PciDevMock(config)
        }
    }

    impl PciDevice for PciDevMock {
        fn write_config_register(
            &mut self,
            reg_idx: usize,
            offset: u64,
            data: &[u8],
        ) -> Option<Arc<std::sync::Barrier>> {
            self.0.write_config_register(reg_idx, offset, data);
            None
        }

        fn read_config_register(&mut self, reg_idx: usize) -> u32 {
            self.0.read_reg(reg_idx)
        }

        fn detect_bar_reprogramming(
            &mut self,
            reg_idx: usize,
            data: &[u8],
        ) -> Option<crate::BarReprogrammingParams> {
            self.0.detect_bar_reprogramming(reg_idx, data)
        }
    }

    #[test]
    fn test_writing_io_config_address() {
        let mock = Arc::new(RelocationMock::default());
        let root = PciRoot::new(None);
        let mut bus = PciConfigIo::new(Arc::new(Mutex::new(PciBus::new(root, mock))));

        assert_eq!(bus.config_address, 0);
        // Writing more than 32 bits will should fail
        bus.write(0, 0, &[0x42; 8]);
        assert_eq!(bus.config_address, 0);
        // Write all the address at once
        bus.write(0, 0, &[0x13, 0x12, 0x11, 0x10]);
        assert_eq!(bus.config_address, 0x10111213);
        // Not writing 32bits at offset 0 should have no effect
        bus.write(0, 1, &[0x0; 4]);
        assert_eq!(bus.config_address, 0x10111213);

        // Write two bytes at a time
        bus.write(0, 0, &[0x42, 0x42]);
        assert_eq!(bus.config_address, 0x10114242);
        bus.write(0, 1, &[0x43, 0x43]);
        assert_eq!(bus.config_address, 0x10434342);
        bus.write(0, 2, &[0x44, 0x44]);
        assert_eq!(bus.config_address, 0x44444342);
        // Writing two bytes at offset 3 should overflow, so it shouldn't have any effect
        bus.write(0, 3, &[0x45, 0x45]);
        assert_eq!(bus.config_address, 0x44444342);

        // Write one byte at a time
        bus.write(0, 0, &[0x0]);
        assert_eq!(bus.config_address, 0x44444300);
        bus.write(0, 1, &[0x0]);
        assert_eq!(bus.config_address, 0x44440000);
        bus.write(0, 2, &[0x0]);
        assert_eq!(bus.config_address, 0x44000000);
        bus.write(0, 3, &[0x0]);
        assert_eq!(bus.config_address, 0x00000000);
        // Writing past 4 bytes should have no effect
        bus.write(0, 4, &[0x13]);
        assert_eq!(bus.config_address, 0x0);
    }

    #[test]
    fn test_reading_io_config_address() {
        let mock = Arc::new(RelocationMock::default());
        let root = PciRoot::new(None);
        let mut bus = PciConfigIo::new(Arc::new(Mutex::new(PciBus::new(root, mock))));

        let mut buffer = [0u8; 4];

        bus.config_address = 0x13121110;

        // First 4 bytes are the config address
        // Next 4 bytes are the values read from the configuration space.
        //
        // Reading past offset 7 should not return nothing (all 1s)
        bus.read(0, 8, &mut buffer);
        assert_eq!(buffer, [0xff; 4]);

        // offset + buffer.len() needs to be smaller or equal than 4
        bus.read(0, 1, &mut buffer);
        assert_eq!(buffer, [0xff; 4]);
        bus.read(0, 2, &mut buffer[..3]);
        assert_eq!(buffer, [0xff; 4]);
        bus.read(0, 3, &mut buffer[..2]);
        assert_eq!(buffer, [0xff; 4]);

        // reading one byte at a time
        bus.read(0, 0, &mut buffer[0..1]);
        assert_eq!(buffer, [0x10, 0xff, 0xff, 0xff]);
        bus.read(0, 1, &mut buffer[1..2]);
        assert_eq!(buffer, [0x10, 0x11, 0xff, 0xff]);
        bus.read(0, 2, &mut buffer[2..3]);
        assert_eq!(buffer, [0x10, 0x11, 0x12, 0xff]);
        bus.read(0, 3, &mut buffer[3..4]);
        assert_eq!(buffer, [0x10, 0x11, 0x12, 0x13]);

        // reading two bytes at a time
        bus.config_address = 0x42434445;
        bus.read(0, 0, &mut buffer[..2]);
        assert_eq!(buffer, [0x45, 0x44, 0x12, 0x13]);
        bus.read(0, 1, &mut buffer[..2]);
        assert_eq!(buffer, [0x44, 0x43, 0x12, 0x13]);
        bus.read(0, 2, &mut buffer[..2]);
        assert_eq!(buffer, [0x43, 0x42, 0x12, 0x13]);

        // reading all of it at once
        bus.read(0, 0, &mut buffer);
        assert_eq!(buffer, [0x45, 0x44, 0x43, 0x42]);
    }

    fn initialize_bus() -> (PciConfigMmio, PciConfigIo, Arc<RelocationMock>) {
        let mock = Arc::new(RelocationMock::default());
        let root = PciRoot::new(None);
        let mut bus = PciBus::new(root, mock.clone());
        bus.add_device(1, Arc::new(Mutex::new(PciDevMock::new())))
            .unwrap();
        let bus = Arc::new(Mutex::new(bus));
        (PciConfigMmio::new(bus.clone()), PciConfigIo::new(bus), mock)
    }

    #[test]
    fn test_invalid_register_boundary_reads() {
        let (mut mmio_config, mut io_config, _) = initialize_bus();

        // Read crossing register boundaries
        let mut buffer = [0u8; 4];
        mmio_config.read(0, 1, &mut buffer);
        assert_eq!(0xffff_ffff, u32::from_le_bytes(buffer));

        let mut buffer = [0u8; 4];
        io_config.read(0, 1, &mut buffer);
        assert_eq!(0xffff_ffff, u32::from_le_bytes(buffer));

        // As well in the config space
        let mut buffer = [0u8; 4];
        io_config.read(0, 5, &mut buffer);
        assert_eq!(0xffff_ffff, u32::from_le_bytes(buffer));
    }

    // MMIO config addresses are of the form
    //
    // | Base address upper bits | Bus Number | Device Number | Function Number | Register number | Byte offset |
    // |         31-28           |    27-20   |     19-15     |      14-12      |      11-2       |     0-1     |
    //
    // Meaning that the offset is built using:
    //
    // `bus << 20 | device << 15 | function << 12 | register << 2 | byte`
    fn mmio_offset(bus: u8, device: u8, function: u8, register: u16, byte: u8) -> u32 {
        assert!(device < 32);
        assert!(function < 8);
        assert!(register < 1024);
        assert!(byte < 4);

        (bus as u32) << 20
            | (device as u32) << 15
            | (function as u32) << 12
            | (register as u32) << 2
            | (byte as u32)
    }

    fn read_mmio_config(
        config: &mut PciConfigMmio,
        bus: u8,
        device: u8,
        function: u8,
        register: u16,
        byte: u8,
        data: &mut [u8],
    ) {
        config.read(
            0,
            mmio_offset(bus, device, function, register, byte) as u64,
            data,
        );
    }

    fn write_mmio_config(
        config: &mut PciConfigMmio,
        bus: u8,
        device: u8,
        function: u8,
        register: u16,
        byte: u8,
        data: &[u8],
    ) {
        config.write(
            0,
            mmio_offset(bus, device, function, register, byte) as u64,
            data,
        );
    }

    // Similarly, when using the IO mechanism the config addresses have the following format
    //
    // | Enabled | zeros | Bus Number | Device Number | Function Number | Register number | zeros |
    // |    31   | 30-24 |   23-16    |     15-11     |      10-8       |       7-2       |  1-0  |
    //
    //
    // Meaning that the address is built using:
    //
    // 0x8000_0000 | bus << 16 | device << 11 | function << 8 | register << 2;
    //
    // Only 32-bit aligned accesses are allowed here.
    fn pio_offset(enabled: bool, bus: u8, device: u8, function: u8, register: u8) -> u32 {
        assert!(device < 32);
        assert!(function < 8);
        assert!(register < 64);

        let offset = if enabled { 0x8000_0000 } else { 0u32 };

        offset
            | (bus as u32) << 16
            | (device as u32) << 11
            | (function as u32) << 8
            | (register as u32) << 2
    }

    fn set_io_address(
        config: &mut PciConfigIo,
        enabled: bool,
        bus: u8,
        device: u8,
        function: u8,
        register: u8,
    ) {
        let address = u32::to_le_bytes(pio_offset(enabled, bus, device, function, register));
        config.write(0, 0, &address);
    }

    fn read_io_config(
        config: &mut PciConfigIo,
        enabled: bool,
        bus: u8,
        device: u8,
        function: u8,
        register: u8,
        data: &mut [u8],
    ) {
        set_io_address(config, enabled, bus, device, function, register);
        config.read(0, 4, data);
    }

    fn write_io_config(
        config: &mut PciConfigIo,
        enabled: bool,
        bus: u8,
        device: u8,
        function: u8,
        register: u8,
        data: &[u8],
    ) {
        set_io_address(config, enabled, bus, device, function, register);
        config.write(0, 4, data);
    }

    #[test]
    fn test_mmio_invalid_bus_number() {
        let (mut mmio_config, _, _) = initialize_bus();
        let mut buffer = [0u8; 4];

        // Asking for Bus 1 should return all 1s
        read_mmio_config(&mut mmio_config, 1, 0, 0, 0, 0, &mut buffer);
        assert_eq!(buffer, u32::to_le_bytes(0xffff_ffff));
        // Writing the same
        buffer[0] = 0x42;
        write_mmio_config(&mut mmio_config, 1, 0, 0, 15, 0, &buffer);
        read_mmio_config(&mut mmio_config, 1, 0, 0, 15, 0, &mut buffer);
        assert_eq!(buffer, u32::to_le_bytes(0xffff_ffff));
        read_mmio_config(&mut mmio_config, 0, 0, 0, 15, 0, &mut buffer);
        assert_eq!(buffer, u32::to_le_bytes(0x0));

        // Asking for Bus 0 should work
        read_mmio_config(&mut mmio_config, 0, 0, 0, 0, 0, &mut buffer);
        assert_eq!(&buffer[..2], &u16::to_le_bytes(VENDOR_ID_INTEL));
        assert_eq!(
            &buffer[2..],
            &u16::to_le_bytes(DEVICE_ID_INTEL_VIRT_PCIE_HOST)
        );
    }

    #[test]
    fn test_io_invalid_bus_number() {
        let (_, mut pio_config, _) = initialize_bus();
        let mut buffer = [0u8; 4];

        // Asking for Bus 1 should return all 1s
        read_io_config(&mut pio_config, true, 1, 0, 0, 0, &mut buffer);
        assert_eq!(buffer, u32::to_le_bytes(0xffff_ffff));

        // Asking for Bus 0 should work
        read_io_config(&mut pio_config, true, 0, 0, 0, 0, &mut buffer);
        assert_eq!(&buffer[..2], &u16::to_le_bytes(VENDOR_ID_INTEL));
        assert_eq!(
            &buffer[2..],
            &u16::to_le_bytes(DEVICE_ID_INTEL_VIRT_PCIE_HOST)
        );
    }

    #[test]
    fn test_mmio_invalid_function() {
        let (mut mmio_config, _, _) = initialize_bus();
        let mut buffer = [0u8; 4];

        // Asking for Bus 1 should return all 1s
        read_mmio_config(&mut mmio_config, 0, 0, 1, 0, 0, &mut buffer);
        assert_eq!(buffer, u32::to_le_bytes(0xffff_ffff));
        // Writing the same
        buffer[0] = 0x42;
        write_mmio_config(&mut mmio_config, 0, 0, 1, 15, 0, &buffer);
        read_mmio_config(&mut mmio_config, 0, 0, 1, 15, 0, &mut buffer);
        assert_eq!(buffer, u32::to_le_bytes(0xffff_ffff));
        read_mmio_config(&mut mmio_config, 0, 0, 0, 15, 0, &mut buffer);
        assert_eq!(buffer, u32::to_le_bytes(0x0));

        // Asking for Bus 0 should work
        read_mmio_config(&mut mmio_config, 0, 0, 0, 0, 0, &mut buffer);
        assert_eq!(&buffer[..2], &u16::to_le_bytes(VENDOR_ID_INTEL));
        assert_eq!(
            &buffer[2..],
            &u16::to_le_bytes(DEVICE_ID_INTEL_VIRT_PCIE_HOST)
        );
    }

    #[test]
    fn test_io_invalid_function() {
        let (_, mut pio_config, _) = initialize_bus();
        let mut buffer = [0u8; 4];

        // Asking for Bus 1 should return all 1s
        read_io_config(&mut pio_config, true, 0, 0, 1, 0, &mut buffer);
        assert_eq!(buffer, u32::to_le_bytes(0xffff_ffff));

        // Asking for Bus 0 should work
        read_io_config(&mut pio_config, true, 0, 0, 0, 0, &mut buffer);
        assert_eq!(&buffer[..2], &u16::to_le_bytes(VENDOR_ID_INTEL));
        assert_eq!(
            &buffer[2..],
            &u16::to_le_bytes(DEVICE_ID_INTEL_VIRT_PCIE_HOST)
        );
    }

    #[test]
    fn test_io_disabled_reads() {
        let (_, mut pio_config, _) = initialize_bus();
        let mut buffer = [0u8; 4];

        // Trying to read without enabling should return all 1s
        read_io_config(&mut pio_config, false, 0, 0, 0, 0, &mut buffer);
        assert_eq!(buffer, u32::to_le_bytes(0xffff_ffff));

        // Asking for Bus 0 should work
        read_io_config(&mut pio_config, true, 0, 0, 0, 0, &mut buffer);
        assert_eq!(&buffer[..2], &u16::to_le_bytes(VENDOR_ID_INTEL));
        assert_eq!(
            &buffer[2..],
            &u16::to_le_bytes(DEVICE_ID_INTEL_VIRT_PCIE_HOST)
        );
    }

    #[test]
    fn test_io_disabled_writes() {
        let (_, mut pio_config, _) = initialize_bus();

        // Try to write the IRQ line used for the root port.
        let mut buffer = [0u8; 4];

        // First read the current value (use `enabled` bit)
        read_io_config(&mut pio_config, true, 0, 0, 0, 15, &mut buffer);
        let irq_line = buffer[0];

        // Write without setting the `enabled` bit.
        buffer[0] = 0x42;
        write_io_config(&mut pio_config, false, 0, 0, 0, 15, &buffer);

        // IRQ line shouldn't have changed
        read_io_config(&mut pio_config, true, 0, 0, 0, 15, &mut buffer);
        assert_eq!(buffer[0], irq_line);

        // Write with `enabled` bit set.
        buffer[0] = 0x42;
        write_io_config(&mut pio_config, true, 0, 0, 0, 15, &buffer);

        // IRQ line should change
        read_io_config(&mut pio_config, true, 0, 0, 0, 15, &mut buffer);
        assert_eq!(buffer[0], 0x42);
    }

    #[test]
    fn test_mmio_writes() {
        let (mut mmio_config, _, _) = initialize_bus();
        let mut buffer = [0u8; 4];

        read_mmio_config(&mut mmio_config, 0, 0, 0, 15, 0, &mut buffer);
        assert_eq!(buffer[0], 0x0);
        write_mmio_config(&mut mmio_config, 0, 0, 0, 15, 0, &[0x42]);
        read_mmio_config(&mut mmio_config, 0, 0, 0, 15, 0, &mut buffer);
        assert_eq!(buffer[0], 0x42);
    }

    #[test]
    fn test_bar_reprogramming() {
        let (mut mmio_config, _, mock) = initialize_bus();
        let mut buffer = [0u8; 4];
        assert_eq!(mock.cnt(), 0);

        read_mmio_config(&mut mmio_config, 0, 1, 0, 0x4, 0, &mut buffer);
        let old_addr = u32::from_le_bytes(buffer) & 0xffff_fff0;
        assert_eq!(old_addr, 0x1000);
        write_mmio_config(
            &mut mmio_config,
            0,
            1,
            0,
            0x4,
            0,
            &u32::to_le_bytes(0x1312_1110),
        );

        read_mmio_config(&mut mmio_config, 0, 1, 0, 0x4, 0, &mut buffer);
        let new_addr = u32::from_le_bytes(buffer) & 0xffff_fff0;
        assert_eq!(new_addr, 0x1312_1110);
        assert_eq!(mock.cnt(), 1);

        // BAR1 should not be used, so reading its address should return all 0s
        read_mmio_config(&mut mmio_config, 0, 1, 0, 0x5, 0, &mut buffer);
        assert_eq!(buffer, [0x0, 0x0, 0x0, 0x0]);

        // and reprogramming shouldn't have any effect
        write_mmio_config(
            &mut mmio_config,
            0,
            1,
            0,
            0x5,
            0,
            &u32::to_le_bytes(0x1312_1110),
        );

        read_mmio_config(&mut mmio_config, 0, 1, 0, 0x5, 0, &mut buffer);
        assert_eq!(buffer, [0x0, 0x0, 0x0, 0x0]);
    }
}
