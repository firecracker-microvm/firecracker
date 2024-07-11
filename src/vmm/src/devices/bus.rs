// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Handles routing to devices in an address space.

use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::collections::btree_map::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// Errors triggered during bus operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BusError {
    /// New device overlaps with an old device.
    Overlap,
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
    devices: BTreeMap<BusRange, BusDevice>,
}

use event_manager::{EventOps, Events, MutEventSubscriber};

#[cfg(target_arch = "x86_64")]
use super::acpi::cpu_container::CpuContainer;
#[cfg(target_arch = "aarch64")]
use super::legacy::RTCDevice;
use super::legacy::{I8042Device, SerialDevice};
use super::pseudo::BootTimer;
use super::virtio::mmio::MmioTransport;

#[derive(Debug, Clone)]
pub enum BusDevice {
    I8042Device(Arc<Mutex<I8042Device>>),
    #[cfg(target_arch = "aarch64")]
    RTCDevice(Arc<Mutex<RTCDevice>>),
    BootTimer(Arc<Mutex<BootTimer>>),
    MmioTransport(Arc<Mutex<MmioTransport>>),
    Serial(Arc<Mutex<SerialDevice<std::io::Stdin>>>),
    #[cfg(test)]
    Dummy(Arc<Mutex<DummyDevice>>),
    #[cfg(test)]
    Constant(Arc<Mutex<ConstantDevice>>),
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
    #[cfg(target_arch = "aarch64")]
    pub fn rtc_device_ref(&self) -> Option<MutexGuard<RTCDevice>> {
        match self {
            Self::RTCDevice(x) => Some(x.lock().expect("Poisoned lock")),
            _ => None,
        }
    }
    pub fn mmio_transport_ref(&self) -> Option<MutexGuard<MmioTransport>> {
        match self {
            Self::MmioTransport(x) => Some(x.lock().expect("Poisoned lock")),
            _ => None,
        }
    }
    pub fn serial_ref(&self) -> Option<MutexGuard<SerialDevice<std::io::Stdin>>> {
        match self {
            Self::Serial(x) => Some(x.lock().expect("Poisoned lock")),
            _ => None,
        }
    }

    pub fn read(&self, offset: u64, data: &mut [u8]) {
        match self {
            Self::I8042Device(x) => x.lock().expect("Poisoned lock").bus_read(offset, data),
            #[cfg(target_arch = "aarch64")]
            Self::RTCDevice(x) => x.lock().expect("Poisoned lock").bus_read(offset, data),
            Self::BootTimer(x) => x.lock().expect("Poisoned lock").bus_read(offset, data),
            Self::MmioTransport(x) => x.lock().expect("Poisoned lock").bus_read(offset, data),
            Self::Serial(x) => x.lock().expect("Poisoned lock").bus_read(offset, data),
            #[cfg(test)]
            Self::Dummy(x) => x.lock().expect("Poisoned lock").bus_read(offset, data),
            #[cfg(test)]
            Self::Constant(x) => x.lock().expect("Poisoned lock").bus_read(offset, data),
        }
    }

    pub fn write(&self, offset: u64, data: &[u8]) {
        match self {
            Self::I8042Device(x) => x.lock().expect("Poisoned lock").bus_write(offset, data),
            #[cfg(target_arch = "aarch64")]
            Self::RTCDevice(x) => x.lock().expect("Poisoned lock").bus_write(offset, data),
            Self::BootTimer(x) => x.lock().expect("Poisoned lock").bus_write(offset, data),
            Self::MmioTransport(x) => x.lock().expect("Poisoned lock").bus_write(offset, data),
            Self::Serial(x) => x.lock().expect("Poisoned lock").bus_write(offset, data),
            #[cfg(test)]
            Self::Dummy(x) => x.lock().expect("Poisoned lock").bus_write(offset, data),
            #[cfg(test)]
            Self::Constant(x) => x.lock().expect("Poisoned lock").bus_write(offset, data),
        }
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
            devices: BTreeMap::new(),
        }
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, &BusDevice)> {
        for (range, dev) in self.devices.iter().rev() {
            if range.0 <= addr {
                return Some((*range, dev));
            }
        }
        None
    }

    /// Returns the device found at some address.
    pub fn get_device(&self, addr: u64) -> Option<(u64, &BusDevice)> {
        if let Some((BusRange(start, len), dev)) = self.first_before(addr) {
            let offset = addr - start;
            if offset < len {
                return Some((offset, dev));
            }
        }
        None
    }

    /// Puts the given device at the given address space.
    pub fn insert(&mut self, device: BusDevice, base: u64, len: u64) -> Result<(), BusError> {
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

        if self.devices.insert(BusRange(base, len), device).is_some() {
            return Err(BusError::Overlap);
        }

        Ok(())
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
        if let Some((offset, dev)) = self.get_device(addr) {
            dev.read(offset, data);
            true
        } else {
            false
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        if let Some((offset, dev)) = self.get_device(addr) {
            dev.write(offset, data);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_insert() {
        let mut bus = Bus::new();
        let dummy = BusDevice::Dummy(Arc::new(Mutex::new(DummyDevice)));
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
        let dummy = BusDevice::Dummy(Arc::new(Mutex::new(DummyDevice)));
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
        let dummy = BusDevice::Constant(Arc::new(Mutex::new(ConstantDevice)));
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
            BusDevice::Dummy(Arc::new(Mutex::new(DummyDevice))),
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
