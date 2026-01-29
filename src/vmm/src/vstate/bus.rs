// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Handles routing to devices in an address space.

use std::cmp::Ordering;
use std::collections::btree_map::BTreeMap;
use std::sync::{Arc, Barrier, Mutex, RwLock, Weak};
use std::{error, fmt, result};

/// Trait for devices that respond to reads or writes in an arbitrary address space.
///
/// The device does not care where it exists in address space as each method is only given an offset
/// into its allocated portion of address space.
#[allow(unused_variables)]
pub trait BusDevice: Send {
    /// Reads at `offset` from this device
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        None
    }
}

/// Trait similar to [`BusDevice`] with the extra requirement that a device is `Send` and `Sync`.
#[allow(unused_variables)]
pub trait BusDeviceSync: Send + Sync {
    /// Reads at `offset` from this device
    fn read(&self, base: u64, offset: u64, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        None
    }
}

impl<B: BusDevice> BusDeviceSync for Mutex<B> {
    /// Reads at `offset` from this device
    fn read(&self, base: u64, offset: u64, data: &mut [u8]) {
        self.lock()
            .expect("Failed to acquire device lock")
            .read(base, offset, data)
    }
    /// Writes at `offset` into this device
    fn write(&self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.lock()
            .expect("Failed to acquire device lock")
            .write(base, offset, data)
    }
}

/// Error type for [`Bus`]-related operations.
#[derive(Debug)]
pub enum BusError {
    /// The insertion failed because the new device overlapped with an old device.
    Overlap,
    /// Failed to operate on zero sized range.
    ZeroSizedRange,
    /// Failed to find address range.
    MissingAddressRange,
}

/// Result type for [`Bus`]-related operations.
pub type Result<T> = result::Result<T, BusError>;

impl fmt::Display for BusError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bus_error: {self:?}")
    }
}

impl error::Error for BusError {}

/// Holds a base and length representing the address space occupied by a `BusDevice`.
///
/// * base - The address at which the range start.
/// * len - The length of the range in bytes.
#[derive(Debug, Copy, Clone)]
pub struct BusRange {
    /// base address of a range within a [`Bus`]
    pub base: u64,
    /// length of a range within a [`Bus`]
    pub len: u64,
}

impl BusRange {
    /// Returns true if there is overlap with the given range.
    pub fn overlaps(&self, base: u64, len: u64) -> bool {
        self.base < (base + len) && base < self.base + self.len
    }
}

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.base == other.base
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.base.cmp(&other.base)
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
#[derive(Default, Debug)]
pub struct Bus {
    devices: RwLock<BTreeMap<BusRange, Weak<dyn BusDeviceSync>>>,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: RwLock::new(BTreeMap::new()),
        }
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, Arc<dyn BusDeviceSync>)> {
        let devices = self.devices.read().unwrap();
        let (range, dev) = devices
            .range(..=BusRange { base: addr, len: 1 })
            .next_back()?;
        dev.upgrade().map(|d| (*range, d.clone()))
    }

    #[allow(clippy::type_complexity)]
    /// Get a reference to a device residing inside the bus at address [`addr`].
    pub fn resolve(&self, addr: u64) -> Option<(u64, u64, Arc<dyn BusDeviceSync>)> {
        if let Some((range, dev)) = self.first_before(addr) {
            let offset = addr - range.base;
            if offset < range.len {
                return Some((range.base, offset, dev));
            }
        }
        None
    }

    /// Insert a device into the [`Bus`] in the range [`addr`, `addr` + `len`].
    pub fn insert(&self, device: Arc<dyn BusDeviceSync>, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(BusError::ZeroSizedRange);
        }

        // Reject all cases where the new device's range overlaps with an existing device.
        if self
            .devices
            .read()
            .unwrap()
            .iter()
            .any(|(range, _dev)| range.overlaps(base, len))
        {
            return Err(BusError::Overlap);
        }

        if self
            .devices
            .write()
            .unwrap()
            .insert(BusRange { base, len }, Arc::downgrade(&device))
            .is_some()
        {
            return Err(BusError::Overlap);
        }

        Ok(())
    }

    /// Removes the device at the given address space range.
    pub fn remove(&self, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(BusError::ZeroSizedRange);
        }

        let bus_range = BusRange { base, len };

        if self.devices.write().unwrap().remove(&bus_range).is_none() {
            return Err(BusError::MissingAddressRange);
        }

        Ok(())
    }

    /// Removes all entries referencing the given device.
    pub fn remove_by_device(&self, device: &Arc<dyn BusDeviceSync>) -> Result<()> {
        let mut device_list = self.devices.write().unwrap();
        let mut remove_key_list = Vec::new();

        for (key, value) in device_list.iter() {
            if Arc::ptr_eq(&value.upgrade().unwrap(), device) {
                remove_key_list.push(*key);
            }
        }

        for key in remove_key_list.iter() {
            device_list.remove(key);
        }

        Ok(())
    }

    /// Updates the address range for an existing device.
    pub fn update_range(
        &self,
        old_base: u64,
        old_len: u64,
        new_base: u64,
        new_len: u64,
    ) -> Result<()> {
        // Retrieve the device corresponding to the range
        let device = if let Some((_, _, dev)) = self.resolve(old_base) {
            dev.clone()
        } else {
            return Err(BusError::MissingAddressRange);
        };

        // Remove the old address range
        self.remove(old_base, old_len)?;

        // Insert the new address range
        self.insert(device, new_base, new_len)
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> Result<()> {
        if let Some((base, offset, dev)) = self.resolve(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            dev.read(base, offset, data);
            Ok(())
        } else {
            Err(BusError::MissingAddressRange)
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<Option<Arc<Barrier>>> {
        if let Some((base, offset, dev)) = self.resolve(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            Ok(dev.write(base, offset, data))
        } else {
            Err(BusError::MissingAddressRange)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDevice;
    impl BusDeviceSync for DummyDevice {}

    struct ConstantDevice;
    impl BusDeviceSync for ConstantDevice {
        #[allow(clippy::cast_possible_truncation)]
        fn read(&self, _base: u64, offset: u64, data: &mut [u8]) {
            for (i, v) in data.iter_mut().enumerate() {
                *v = (offset as u8) + (i as u8);
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        fn write(&self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (offset as u8) + (i as u8))
            }

            None
        }
    }

    #[test]
    fn bus_insert() {
        let bus = Bus::new();
        let dummy = Arc::new(DummyDevice);
        bus.insert(dummy.clone(), 0x10, 0).unwrap_err();
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();

        let result = bus.insert(dummy.clone(), 0x0f, 0x10);
        assert_eq!(format!("{result:?}"), "Err(Overlap)");

        bus.insert(dummy.clone(), 0x10, 0x10).unwrap_err();
        bus.insert(dummy.clone(), 0x10, 0x15).unwrap_err();
        bus.insert(dummy.clone(), 0x12, 0x15).unwrap_err();
        bus.insert(dummy.clone(), 0x12, 0x01).unwrap_err();
        bus.insert(dummy.clone(), 0x0, 0x20).unwrap_err();
        bus.insert(dummy.clone(), 0x20, 0x05).unwrap();
        bus.insert(dummy.clone(), 0x25, 0x05).unwrap();
        bus.insert(dummy, 0x0, 0x10).unwrap();
    }

    #[test]
    fn bus_remove() {
        let bus = Bus::new();
        let dummy: Arc<dyn BusDeviceSync> = Arc::new(DummyDevice);

        bus.remove(0x42, 0x0).unwrap_err();

        bus.remove(0x13, 0x12).unwrap_err();

        bus.insert(dummy.clone(), 0x13, 0x12).unwrap();
        bus.remove(0x42, 0x42).unwrap_err();
        bus.remove(0x13, 0x12).unwrap();

        bus.insert(dummy.clone(), 0x16, 0x1).unwrap();
        bus.remove_by_device(&dummy).unwrap();
        bus.remove(0x16, 0x1).unwrap_err();
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn bus_read_write() {
        let bus = Bus::new();
        let dummy = Arc::new(DummyDevice);
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();
        bus.read(0x10, &mut [0, 0, 0, 0]).unwrap();
        bus.write(0x10, &[0, 0, 0, 0]).unwrap();
        bus.read(0x11, &mut [0, 0, 0, 0]).unwrap();
        bus.write(0x11, &[0, 0, 0, 0]).unwrap();
        bus.read(0x16, &mut [0, 0, 0, 0]).unwrap();
        bus.write(0x16, &[0, 0, 0, 0]).unwrap();
        bus.read(0x20, &mut [0, 0, 0, 0]).unwrap_err();
        bus.write(0x20, &[0, 0, 0, 0]).unwrap_err();
        bus.read(0x06, &mut [0, 0, 0, 0]).unwrap_err();
        bus.write(0x06, &[0, 0, 0, 0]).unwrap_err();
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn bus_read_write_values() {
        let bus = Bus::new();
        let dummy = Arc::new(ConstantDevice);
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();

        let mut values = [0, 1, 2, 3];
        bus.read(0x10, &mut values).unwrap();
        assert_eq!(values, [0, 1, 2, 3]);
        bus.write(0x10, &values).unwrap();
        bus.read(0x15, &mut values).unwrap();
        assert_eq!(values, [5, 6, 7, 8]);
        bus.write(0x15, &values).unwrap();
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn busrange_cmp() {
        let range = BusRange { base: 0x10, len: 2 };
        assert_eq!(range, BusRange { base: 0x10, len: 3 });
        assert_eq!(range, BusRange { base: 0x10, len: 2 });

        assert!(range < BusRange { base: 0x12, len: 1 });
        assert!(range < BusRange { base: 0x12, len: 3 });

        assert_eq!(range, range.clone());

        let bus = Bus::new();
        let mut data = [1, 2, 3, 4];
        let device = Arc::new(DummyDevice);
        bus.insert(device.clone(), 0x10, 0x10).unwrap();
        bus.write(0x10, &data).unwrap();
        bus.read(0x10, &mut data).unwrap();
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn bus_range_overlap() {
        let a = BusRange {
            base: 0x1000,
            len: 0x400,
        };
        assert!(a.overlaps(0x1000, 0x400));
        assert!(a.overlaps(0xf00, 0x400));
        assert!(a.overlaps(0x1000, 0x01));
        assert!(a.overlaps(0xfff, 0x02));
        assert!(a.overlaps(0x1100, 0x100));
        assert!(a.overlaps(0x13ff, 0x100));
        assert!(!a.overlaps(0x1400, 0x100));
        assert!(!a.overlaps(0xf00, 0x100));
    }

    #[test]
    fn bus_update_range() {
        let bus = Bus::new();
        let dummy = Arc::new(DummyDevice);

        bus.update_range(0x13, 0x12, 0x16, 0x1).unwrap_err();
        bus.insert(dummy.clone(), 0x13, 12).unwrap();

        bus.update_range(0x16, 0x1, 0x13, 0x12).unwrap_err();
        bus.update_range(0x13, 0x12, 0x16, 0x1).unwrap();
    }
}
