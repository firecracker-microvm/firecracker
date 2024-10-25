// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Handles routing to devices in an address space.

use std::any::Any;
use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::collections::btree_map::BTreeMap;
use std::result::Result;
use std::sync::{Arc, Barrier, Mutex, RwLock};

/// Errors triggered during bus operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BusError {
    /// The insertion failed because the new device overlapped with an old device.
    Overlap,
    /// The relocation failed because no device was mapped at the address
    MissingAddressRange,
}

#[derive(Debug, Copy, Clone)]
struct BusRange(u64, u64);

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.0 == other.0
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for BusRange {
    fn partial_cmp(&self, other: &BusRange) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
#[derive(Debug, Clone, Default)]
pub struct Bus {
    devices: Arc<RwLock<BTreeMap<BusRange, Arc<Mutex<BusDevice>>>>>,
}

use event_manager::{EventOps, Events, MutEventSubscriber};
use pci::{BarReprogrammingParams, PciBarConfiguration, PciDevice, VfioPciDevice};
use pci::device::Error as PciDeviceError;
use vm_device::Resource;
use vm_system_allocator::{AddressAllocator, SystemAllocator};

#[cfg(target_arch = "aarch64")]
use super::legacy::RTCDevice;
use super::legacy::{I8042Device, SerialDevice};
use pci::{PciConfigIo, PciConfigMmio, PciRoot};
use super::pseudo::BootTimer;
use super::virtio::mmio::MmioTransport;

#[derive(Debug)]
pub enum BusDevice {
    I8042Device(I8042Device),
    #[cfg(target_arch = "aarch64")]
    RTCDevice(RTCDevice),
    BootTimer(BootTimer),
    MmioTransport(MmioTransport),
    Serial(SerialDevice<std::io::Stdin>),
    PioPciBus(PciConfigIo),
    MmioPciBus(PciConfigMmio),
    VfioPciDevice(VfioPciDevice),
    #[cfg(test)]
    Dummy(DummyDevice),
    #[cfg(test)]
    Constant(ConstantDevice),
}

#[cfg(test)]
#[derive(Debug)]
pub struct DummyDevice;

#[cfg(test)]
impl DummyDevice {
    pub fn bus_write(&mut self, _offset: u64, _data: &[u8]) {}
    pub fn bus_read(&mut self, _offset: u64, _data: &[u8]) {}
}

#[cfg(test)]
#[derive(Debug)]
pub struct ConstantDevice;

#[cfg(test)]
impl ConstantDevice {
    pub fn bus_read(&mut self, offset: u64, data: &mut [u8]) {
        for (i, v) in data.iter_mut().enumerate() {
            *v = ((offset + i as u64) & 0xff) as u8;
        }
    }

    fn bus_write(&mut self, offset: u64, data: &[u8]) {
        for (i, v) in data.iter().enumerate() {
            assert_eq!(*v, ((offset + i as u64) & 0xff) as u8)
        }
    }
}

impl BusDevice {
    pub fn i8042_device_ref(&self) -> Option<&I8042Device> {
        match self {
            Self::I8042Device(x) => Some(x),
            _ => None,
        }
    }
    #[cfg(target_arch = "aarch64")]
    pub fn rtc_device_ref(&self) -> Option<&RTCDevice> {
        match self {
            Self::RTCDevice(x) => Some(x),
            _ => None,
        }
    }
    pub fn boot_timer_ref(&self) -> Option<&BootTimer> {
        match self {
            Self::BootTimer(x) => Some(x),
            _ => None,
        }
    }
    pub fn mmio_transport_ref(&self) -> Option<&MmioTransport> {
        match self {
            Self::MmioTransport(x) => Some(x),
            _ => None,
        }
    }
    pub fn serial_ref(&self) -> Option<&SerialDevice<std::io::Stdin>> {
        match self {
            Self::Serial(x) => Some(x),
            _ => None,
        }
    }

    pub fn i8042_device_mut(&mut self) -> Option<&mut I8042Device> {
        match self {
            Self::I8042Device(x) => Some(x),
            _ => None,
        }
    }
    #[cfg(target_arch = "aarch64")]
    pub fn rtc_device_mut(&mut self) -> Option<&mut RTCDevice> {
        match self {
            Self::RTCDevice(x) => Some(x),
            _ => None,
        }
    }
    pub fn boot_timer_mut(&mut self) -> Option<&mut BootTimer> {
        match self {
            Self::BootTimer(x) => Some(x),
            _ => None,
        }
    }
    pub fn mmio_transport_mut(&mut self) -> Option<&mut MmioTransport> {
        match self {
            Self::MmioTransport(x) => Some(x),
            _ => None,
        }
    }
    pub fn serial_mut(&mut self) -> Option<&mut SerialDevice<std::io::Stdin>> {
        match self {
            Self::Serial(x) => Some(x),
            _ => None,
        }
    }
    pub fn vfio_pci_device_ref(&self) -> Option<&VfioPciDevice> {
        match self {
            Self::VfioPciDevice(x) => Some(x),
            _ => None,
        }
    }
    pub fn vfio_pci_device_mut(&mut self) -> Option<&mut VfioPciDevice> {
        match self {
            Self::VfioPciDevice(x) => Some(x),
            _ => None,
        }
    }
    pub fn pci_device_ref(&self) -> Option<&dyn PciDevice> {
        match self {
            Self::VfioPciDevice(x) => Some(x),
            _ => None,
        }
    }
    pub fn pci_device_mut(&mut self) -> Option<&mut dyn PciDevice> {
        match self {
            Self::VfioPciDevice(x) => Some(x),
            _ => None,
        }
    }
    pub fn pci_config_io_ref(&self) -> Option<&PciConfigIo> {
        match self {
            Self::PioPciBus(x) => Some(x),
            _ => None,
        }
    }
    pub fn pci_config_io_mut(&mut self) -> Option<&mut PciConfigIo> {
        match self {
            Self::PioPciBus(x) => Some(x),
            _ => None,
        }
    }
    pub fn pci_config_mmio_ref(&self) -> Option<&PciConfigMmio> {
        match self {
            Self::MmioPciBus(x) => Some(x),
            _ => None,
        }
    }
    pub fn pci_config_mmio_mut(&mut self) -> Option<&mut PciConfigMmio> {
        match self {
            Self::MmioPciBus(x) => Some(x),
            _ => None,
        }
    }

    pub fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        match self {
            Self::I8042Device(x) => x.bus_read(offset, data),
            #[cfg(target_arch = "aarch64")]
            Self::RTCDevice(x) => x.bus_read(offset, data),
            Self::BootTimer(x) => x.bus_read(offset, data),
            Self::MmioTransport(x) => x.bus_read(offset, data),
            Self::Serial(x) => x.bus_read(offset, data),
            Self::VfioPciDevice(x) => x.bus_read(base, offset, data),
            Self::MmioPciBus(x) => x.bus_read(base, offset, data),
            Self::PioPciBus(x) => x.bus_read(base, offset, data),
            #[cfg(test)]
            Self::Dummy(x) => x.bus_read(offset, data),
            #[cfg(test)]
            Self::Constant(x) => x.bus_read(offset, data),
        }
    }

    pub fn write(&mut self, base: u64, offset: u64, data: &[u8]) {
        match self {
            Self::I8042Device(x) => x.bus_write(offset, data),
            #[cfg(target_arch = "aarch64")]
            Self::RTCDevice(x) => x.bus_write(offset, data),
            Self::BootTimer(x) => x.bus_write(offset, data),
            Self::MmioTransport(x) => x.bus_write(offset, data),
            Self::Serial(x) => x.bus_write(offset, data),
            Self::VfioPciDevice(x) => x.bus_write(base, offset, data),
            Self::MmioPciBus(x) => x.bus_write(base, offset, data),
            Self::PioPciBus(x) => x.bus_write(base, offset, data),
            #[cfg(test)]
            Self::Dummy(x) => x.bus_write(offset, data),
            #[cfg(test)]
            Self::Constant(x) => x.bus_write(offset, data),
        }
    }
}

// TODO: hack to make pci crate compatible with firecracker BusDevices
type PciDeviceResult<T> = Result<T, PciDeviceError>;
impl PciDevice for BusDevice {
    fn allocate_bars(
        &mut self,
        allocator: &Arc<Mutex<SystemAllocator>>,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
        resources: Option<Vec<Resource>>,
    ) -> PciDeviceResult<Vec<PciBarConfiguration>> {
        self.pci_device_mut()
            .unwrap()
            .allocate_bars(allocator, mmio32_allocator, mmio64_allocator, resources)
    }

    fn free_bars(
        &mut self,
        allocator: &mut SystemAllocator,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
    ) -> PciDeviceResult<()> {
        self.pci_device_mut()
            .unwrap()
            .free_bars(allocator, mmio32_allocator, mmio64_allocator)
    }

    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        self.pci_device_mut()
            .unwrap()
            .write_config_register(reg_idx, offset, data)
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.pci_device_mut()
            .unwrap()
            .read_config_register(reg_idx)
    }

    fn detect_bar_reprogramming(
        &mut self,
        reg_idx: usize,
        data: &[u8],
    ) -> Option<BarReprogrammingParams> {
        self.pci_device_mut()
            .unwrap()
            .detect_bar_reprogramming(reg_idx, data)
    }

    fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.pci_device_mut()
            .unwrap()
            .read_bar(base, offset, data)
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.pci_device_mut()
            .unwrap()
            .write_bar(base, offset, data)
    }

    fn move_bar(&mut self, old_base: u64, new_base: u64) -> std::result::Result<(), std::io::Error> {
        self.pci_device_mut()
            .unwrap()
            .move_bar(old_base, new_base)
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self.pci_device_mut()
            .unwrap()
            .as_any()
    }

    fn id(&self) -> Option<String> {
        self.pci_device_ref()
            .unwrap()
            .id()
    }
}

impl MutEventSubscriber for BusDevice {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        match self {
            Self::Serial(serial) => serial.process(event, ops),
            _ => panic!(),
        }
    }
    fn init(&mut self, ops: &mut EventOps) {
        match self {
            Self::Serial(serial) => serial.init(ops),
            _ => panic!(),
        }
    }
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, Arc<Mutex<BusDevice>>)> {
        // for when we switch to rustc 1.17: self.devices.range(..addr).iter().rev().next()
        for (range, dev) in self.devices.read().unwrap().iter().rev() {
            if range.0 <= addr {
                return Some((*range, dev.clone()));
            }
        }
        None
    }

    pub fn get_device(&self, addr: u64) -> Option<(u64, u64, Arc<Mutex<BusDevice>>)> {
        if let Some((BusRange(start, len), dev)) = self.first_before(addr) {
            let offset = addr - start;
            if offset < len {
                return Some((start, offset, dev));
            }
        }
        None
    }

    /// Puts the given device at the given address space.
    pub fn insert(
        &self,
        device: Arc<Mutex<BusDevice>>,
        base: u64,
        len: u64,
    ) -> Result<(), BusError> {
        if len == 0 {
            return Err(BusError::Overlap);
        }

        // Reject all cases where the new device's base is within an old device's range.
        if self.get_device(base).is_some() {
            return Err(BusError::Overlap);
        }

        // The above check will miss an overlap in which the new device's base address is before the
        // range of another device. To catch that case, we search for a device with a range before
        // the new device's range's end. If there is no existing device in that range that starts
        // after the new device, then there will be no overlap.
        if let Some((BusRange(start, _), _)) = self.first_before(base + len - 1) {
            // Such a device only conflicts with the new device if it also starts after the new
            // device because of our initial `get_device` check above.
            if start >= base {
                return Err(BusError::Overlap);
            }
        }

        if self.devices.write().unwrap().insert(BusRange(base, len), device).is_some() {
            return Err(BusError::Overlap);
        }

        Ok(())
    }

    pub fn remove(&self, base: u64, len: u64) -> Result<(), BusError> {
        let range = BusRange(base, len);
        if self.devices.write().unwrap().remove(&range).is_none() {
            return Err(BusError::MissingAddressRange);
        }
        Ok(())
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
        if let Some((base, offset, dev)) = self.get_device(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            dev.lock()
                .expect("Failed to acquire device lock")
                .read(base, offset, data);
            true
        } else {
            false
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        if let Some((base, offset, dev)) = self.get_device(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            dev.lock()
                .expect("Failed to acquire device lock")
                .write(base, offset, data);
            true
        } else {
            false
        }
    }
    
    /// Updates the address range for an existing device.
    pub fn update_range(
        &self,
        old_base: u64,
        old_len: u64,
        new_base: u64,
        new_len: u64,
    ) -> Result<(), BusError> {
        // Retrieve the device corresponding to the range
        let device = if let Some((_, _, dev)) = self.get_device(old_base) {
            dev.clone()
        } else {
            return Err(BusError::MissingAddressRange);
        };

        // Remove the old address range
        self.remove(old_base, old_len)?;

        // Insert the new address range
        self.insert(device, new_base, new_len)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_insert() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(BusDevice::Dummy(DummyDevice)));
        // Insert len should not be 0.
        bus.insert(dummy.clone(), 0x10, 0).unwrap_err();
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();

        let result = bus.insert(dummy.clone(), 0x0f, 0x10);
        // This overlaps the address space of the existing bus device at 0x10.
        assert!(matches!(result, Err(BusError::Overlap)), "{:?}", result);

        // This overlaps the address space of the existing bus device at 0x10.
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap_err();
        // This overlaps the address space of the existing bus device at 0x10.
        bus.insert(dummy.clone(), 0x10, 0x15).unwrap_err();
        // This overlaps the address space of the existing bus device at 0x10.
        bus.insert(dummy.clone(), 0x12, 0x15).unwrap_err();
        // This overlaps the address space of the existing bus device at 0x10.
        bus.insert(dummy.clone(), 0x12, 0x01).unwrap_err();
        // This overlaps the address space of the existing bus device at 0x10.
        bus.insert(dummy.clone(), 0x0, 0x20).unwrap_err();
        bus.insert(dummy.clone(), 0x20, 0x05).unwrap();
        bus.insert(dummy.clone(), 0x25, 0x05).unwrap();
        bus.insert(dummy, 0x0, 0x10).unwrap();
    }

    #[test]
    fn bus_read_write() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(BusDevice::Dummy(DummyDevice)));
        bus.insert(dummy, 0x10, 0x10).unwrap();
        assert!(bus.read(0x10, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x10, &[0, 0, 0, 0]));
        assert!(bus.read(0x11, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x11, &[0, 0, 0, 0]));
        assert!(bus.read(0x16, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x16, &[0, 0, 0, 0]));
        assert!(!bus.read(0x20, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x20, &[0, 0, 0, 0]));
        assert!(!bus.read(0x06, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x06, &[0, 0, 0, 0]));
    }

    #[test]
    fn bus_read_write_values() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(BusDevice::Constant(ConstantDevice)));
        bus.insert(dummy, 0x10, 0x10).unwrap();

        let mut values = [0, 1, 2, 3];
        assert!(bus.read(0x10, &mut values));
        assert_eq!(values, [0, 1, 2, 3]);
        assert!(bus.write(0x10, &values));
        assert!(bus.read(0x15, &mut values));
        assert_eq!(values, [5, 6, 7, 8]);
        assert!(bus.write(0x15, &values));
    }

    #[test]
    fn busrange_cmp_and_clone() {
        assert_eq!(BusRange(0x10, 2), BusRange(0x10, 3));
        assert_eq!(BusRange(0x10, 2), BusRange(0x10, 2));

        assert!(BusRange(0x10, 2) < BusRange(0x12, 1));
        assert!(BusRange(0x10, 2) < BusRange(0x12, 3));

        let mut bus = Bus::new();
        let mut data = [1, 2, 3, 4];
        bus.insert(
            Arc::new(Mutex::new(BusDevice::Dummy(DummyDevice))),
            0x10,
            0x10,
        )
        .unwrap();
        assert!(bus.write(0x10, &data));
        let bus_clone = bus.clone();
        assert!(bus.read(0x10, &mut data));
        assert_eq!(data, [1, 2, 3, 4]);
        assert!(bus_clone.read(0x10, &mut data));
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn test_display_error() {
        assert_eq!(
            format!("{}", BusError::Overlap),
            "New device overlaps with an old device."
        );
    }
}
