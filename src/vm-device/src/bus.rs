// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Handles routing to devices in an address space.

use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::collections::btree_map::BTreeMap;
use std::sync::{Arc, Barrier, Mutex, RwLock, Weak};
use std::{convert, error, fmt, io, result};

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
    /// Triggers the `irq_mask` interrupt on this device
    fn interrupt(&self, irq_mask: u32) {}
}

#[derive(Debug)]
pub enum Error {
    /// The insertion failed because the new device overlapped with an old device.
    Overlap,
    /// Failed to operate on zero sized range.
    ZeroSizedRange,
    /// Failed to find address range.
    MissingAddressRange,
}

pub type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bus_error: {:?}", self)
    }
}

impl error::Error for Error {}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

/// Holds a base and length representing the address space occupied by a `BusDevice`.
///
/// * base - The address at which the range start.
/// * len - The length of the range in bytes.
#[derive(Debug, Copy, Clone)]
pub struct BusRange {
    pub base: u64,
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
        self.base.partial_cmp(&other.base)
    }
}

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
#[derive(Default)]
pub struct Bus {
    devices: RwLock<BTreeMap<BusRange, Weak<Mutex<dyn BusDevice>>>>,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: RwLock::new(BTreeMap::new()),
        }
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, Arc<Mutex<dyn BusDevice>>)> {
        let devices = self.devices.read().unwrap();
        let (range, dev) = devices
            .range(..=BusRange { base: addr, len: 1 })
            .rev()
            .next()?;
        dev.upgrade().map(|d| (*range, d.clone()))
    }

    #[allow(clippy::type_complexity)]
    pub fn resolve(&self, addr: u64) -> Option<(u64, u64, Arc<Mutex<dyn BusDevice>>)> {
        if let Some((range, dev)) = self.first_before(addr) {
            let offset = addr - range.base;
            if offset < range.len {
                return Some((range.base, offset, dev));
            }
        }
        None
    }

    /// Puts the given device at the given address space.
    pub fn insert(&self, device: Arc<Mutex<dyn BusDevice>>, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::ZeroSizedRange);
        }

        // Reject all cases where the new device's range overlaps with an existing device.
        if self
            .devices
            .read()
            .unwrap()
            .iter()
            .any(|(range, _dev)| range.overlaps(base, len))
        {
            return Err(Error::Overlap);
        }

        if self
            .devices
            .write()
            .unwrap()
            .insert(BusRange { base, len }, Arc::downgrade(&device))
            .is_some()
        {
            return Err(Error::Overlap);
        }

        Ok(())
    }

    /// Removes the device at the given address space range.
    pub fn remove(&self, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::ZeroSizedRange);
        }

        let bus_range = BusRange { base, len };

        if self.devices.write().unwrap().remove(&bus_range).is_none() {
            return Err(Error::MissingAddressRange);
        }

        Ok(())
    }

    /// Removes all entries referencing the given device.
    pub fn remove_by_device(&self, device: &Arc<Mutex<dyn BusDevice>>) -> Result<()> {
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
            return Err(Error::MissingAddressRange);
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
            dev.lock()
                .expect("Failed to acquire device lock")
                .read(base, offset, data);
            Ok(())
        } else {
            Err(Error::MissingAddressRange)
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<Option<Arc<Barrier>>> {
        if let Some((base, offset, dev)) = self.resolve(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            Ok(dev
                .lock()
                .expect("Failed to acquire device lock")
                .write(base, offset, data))
        } else {
            Err(Error::MissingAddressRange)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDevice;
    impl BusDevice for DummyDevice {}

    struct ConstantDevice;
    impl BusDevice for ConstantDevice {
        fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
            for (i, v) in data.iter_mut().enumerate() {
                *v = (offset as u8) + (i as u8);
            }
        }

        fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (offset as u8) + (i as u8))
            }

            None
        }
    }

    #[test]
    fn bus_insert() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());

        let result = bus.insert(dummy.clone(), 0x0f, 0x10);
        assert!(result.is_err());
        assert_eq!(format!("{:?}", result), "Err(Overlap)");

        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x01).is_err());
        assert!(bus.insert(dummy.clone(), 0x0, 0x20).is_err());
        assert!(bus.insert(dummy.clone(), 0x20, 0x05).is_ok());
        assert!(bus.insert(dummy.clone(), 0x25, 0x05).is_ok());
        assert!(bus.insert(dummy, 0x0, 0x10).is_ok());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn bus_read_write() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());
        assert!(bus.read(0x10, &mut [0, 0, 0, 0]).is_ok());
        assert!(bus.write(0x10, &[0, 0, 0, 0]).is_ok());
        assert!(bus.read(0x11, &mut [0, 0, 0, 0]).is_ok());
        assert!(bus.write(0x11, &[0, 0, 0, 0]).is_ok());
        assert!(bus.read(0x16, &mut [0, 0, 0, 0]).is_ok());
        assert!(bus.write(0x16, &[0, 0, 0, 0]).is_ok());
        assert!(bus.read(0x20, &mut [0, 0, 0, 0]).is_err());
        assert!(bus.write(0x20, &[0, 0, 0, 0]).is_err());
        assert!(bus.read(0x06, &mut [0, 0, 0, 0]).is_err());
        assert!(bus.write(0x06, &[0, 0, 0, 0]).is_err());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn bus_read_write_values() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(ConstantDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());

        let mut values = [0, 1, 2, 3];
        assert!(bus.read(0x10, &mut values).is_ok());
        assert_eq!(values, [0, 1, 2, 3]);
        assert!(bus.write(0x10, &values).is_ok());
        assert!(bus.read(0x15, &mut values).is_ok());
        assert_eq!(values, [5, 6, 7, 8]);
        assert!(bus.write(0x15, &values).is_ok());
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
        let device = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(device.clone(), 0x10, 0x10).is_ok());
        assert!(bus.write(0x10, &data).is_ok());
        assert!(bus.read(0x10, &mut data).is_ok());
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
}
