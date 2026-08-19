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

use slab::Slab;

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

/// Error type for [`Bus`]-related operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BusError {
    /// The insertion failed because the new device overlapped with an old device.
    Overlap,
    /// Failed to operate on zero sized range.
    ZeroSizedRange,
    /// Failed to find address range.
    MissingAddressRange,
    /// The supplied range is invalid.
    InvalidRange,
}

/// Holds a base and end representing the address space occupied by a `BusDevice`.
///
/// * base - The address at which the range start.
/// * end - The last address of the range (inclusive).
#[derive(Debug, Copy, Clone)]
pub struct BusRange {
    /// base address of a range within a [`Bus`]
    base: u64,
    /// last address of a range within a [`Bus`] (inclusive)
    end: u64,
}

#[allow(missing_docs)]
impl BusRange {
    pub fn new(base: u64, len: u64) -> Result<Self, BusError> {
        if len == 0 {
            return Err(BusError::ZeroSizedRange);
        }
        let end = base.checked_add(len - 1).ok_or(BusError::InvalidRange)?;
        Ok(BusRange { base, end })
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    /// Returns true if there is overlap with the given range.
    pub fn overlaps(&self, other: &BusRange) -> bool {
        self.base <= other.end && other.base <= self.end
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
///
/// The address ranges and the device handles are held behind two separate
/// locks. `ranges` maps an address range to the slot holding the owning
/// device, while `devices` holds the device handles themselves. Decoupling
/// them lets a bus access - which holds the `devices` read lock - mutate
/// `ranges` (for example to relocate a device) without needing the `devices`
/// write lock.
///
/// Lock ordering: whenever both locks are taken, `devices` MUST be acquired
/// before `ranges`. A bus access holds `devices` (read) and then reaches into
/// `ranges` (read to resolve the address, or write to relocate a mapping), so
/// every other path that takes both must use the same order.
#[derive(Default, Debug)]
pub struct Bus {
    /// Device handles keyed by an opaque slot. Held (read) for the duration of
    /// an access so that [`Bus::remove`] blocks until any in-flight access to
    /// the device has finished.
    ///
    /// Lock ordering: acquire this *before* `ranges`.
    devices: RwLock<Slab<Weak<Mutex<dyn BusDevice>>>>,

    /// Maps each occupied address range to the slot in `devices` holding the
    /// owning device.
    ///
    /// Lock ordering: acquire this *after* `devices`.
    ranges: RwLock<BTreeMap<BusRange, usize>>,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: RwLock::new(Slab::new()),
            ranges: RwLock::new(BTreeMap::new()),
        }
    }

    /// Insert a device into the [`Bus`] in the range [`addr`, `addr` + `len`].
    pub fn insert(
        &self,
        device: Arc<Mutex<dyn BusDevice>>,
        base: u64,
        len: u64,
    ) -> Result<(), BusError> {
        let new_range = BusRange::new(base, len)?;

        // Acquire both write locks in the right order, to register the device
        // in both maps atomically.
        let mut devices = self.devices.write().unwrap();
        let mut ranges = self.ranges.write().unwrap();

        // Reject all cases where the new device's range overlaps with an existing device.
        if ranges.keys().any(|range| range.overlaps(&new_range)) {
            return Err(BusError::Overlap);
        }

        let slot = devices.insert(Arc::downgrade(&device));
        ranges.insert(new_range, slot);

        Ok(())
    }

    /// Removes the device at the given address space range.
    pub fn remove(&self, base: u64, len: u64) -> Result<(), BusError> {
        let bus_range = BusRange::new(base, len)?;

        // Acquire both write locks in the right order, to remove the device
        // from both maps atomically.
        let mut devices = self.devices.write().unwrap();
        let mut ranges = self.ranges.write().unwrap();

        let slot = ranges
            .remove(&bus_range)
            .ok_or(BusError::MissingAddressRange)?;
        devices.remove(slot);

        Ok(())
    }

    // Perform an operation on the device with the devices read lock held.
    // The ranges read lock is only held for resolving the address and is
    // dropped before performing the operation on the device.
    fn with_device<T>(
        &self,
        addr: u64,
        f: impl FnOnce(&mut dyn BusDevice, u64, u64) -> T,
    ) -> Result<T, BusError> {
        let devices = self.devices.read().unwrap();
        let (base, slot) = {
            let ranges = self.ranges.read().unwrap();
            match ranges.range(..=BusRange::new(addr, 1).unwrap()).next_back() {
                Some((range, &slot)) if addr <= range.end() => (range.base(), slot),
                _ => return Err(BusError::MissingAddressRange),
            }
        };

        let device = devices
            .get(slot)
            .expect("Bus ranges and devices out of sync");

        let Some(device) = device.upgrade() else {
            return Err(BusError::MissingAddressRange);
        };

        let mut locked = device.lock().unwrap();
        let offset = addr - base;
        Ok(f(&mut *locked, base, offset))
    }

    /// Relocate an existing device mapping from `old_base` to `new_base`.
    /// Only the `ranges` lock is taken, not the `devices` lock.
    pub fn move_range(&self, old_base: u64, new_base: u64, len: u64) -> Result<(), BusError> {
        let old_range = BusRange::new(old_base, len)?;
        let new_range = BusRange::new(new_base, len)?;

        let mut ranges = self.ranges.write().unwrap();

        // Remove first because the new range might overlap the old range
        let (registered, slot) = ranges
            .remove_entry(&old_range)
            .ok_or(BusError::MissingAddressRange)?;

        assert_eq!(
            registered.end(),
            old_range.end(),
            "Bus mapping at {old_base:#x} is registered with length {}, not {len}",
            registered.end() - registered.base() + 1
        );

        // Reject if the destination overlaps another device
        if ranges.keys().any(|range| range.overlaps(&new_range)) {
            ranges.insert(old_range, slot);
            return Err(BusError::Overlap);
        }

        ranges.insert(new_range, slot);
        Ok(())
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> Result<(), BusError> {
        self.with_device(addr, |dev, base, offset| dev.read(base, offset, data))
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<Option<Arc<Barrier>>, BusError> {
        self.with_device(addr, |dev, base, offset| dev.write(base, offset, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDevice;
    impl BusDevice for DummyDevice {}

    struct ConstantDevice;
    impl BusDevice for ConstantDevice {
        #[allow(clippy::cast_possible_truncation)]
        fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
            for (i, v) in data.iter_mut().enumerate() {
                *v = (offset as u8) + (i as u8);
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (offset as u8) + (i as u8))
            }

            None
        }
    }

    #[test]
    fn bus_range_new() {
        // Zero length is invalid.
        assert!(matches!(BusRange::new(0, 0), Err(BusError::ZeroSizedRange)));
        assert!(matches!(
            BusRange::new(u64::MAX, 0),
            Err(BusError::ZeroSizedRange)
        ));

        // Overflow is invalid.
        assert!(matches!(
            BusRange::new(u64::MAX, 2),
            Err(BusError::InvalidRange)
        ));
        assert!(matches!(
            BusRange::new(2, u64::MAX),
            Err(BusError::InvalidRange)
        ));

        // Ranges that exactly reach u64::MAX are valid.
        let r = BusRange::new(u64::MAX, 1).unwrap();
        assert_eq!(r.base(), u64::MAX);
        assert_eq!(r.end(), u64::MAX);

        let r = BusRange::new(1, u64::MAX).unwrap();
        assert_eq!(r.base(), 1);
        assert_eq!(r.end(), u64::MAX);

        let r = BusRange::new(u64::MAX - 4095, 4096).unwrap();
        assert_eq!(r.base(), u64::MAX - 4095);
        assert_eq!(r.end(), u64::MAX);

        // One sized valid range.
        let r = BusRange::new(0, 1).unwrap();
        assert_eq!(r.base(), 0);
        assert_eq!(r.end(), 0);

        // Normal valid range.
        let r = BusRange::new(0x1000, 0x400).unwrap();
        assert_eq!(r.base(), 0x1000);
        assert_eq!(r.end(), 0x13ff);
    }

    /// A device that answers every read with its own id, so that a test can
    /// tell which device an access was routed to.
    struct IdDevice(u8);
    impl BusDevice for IdDevice {
        fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
            data.fill(self.0);
        }
    }

    #[test]
    fn bus_multiple_devices() {
        let bus = Bus::new();
        let dev_a = Arc::new(Mutex::new(IdDevice(0xa)));
        let dev_b = Arc::new(Mutex::new(IdDevice(0xb)));
        let dev_c = Arc::new(Mutex::new(IdDevice(0xc)));
        let dev_d = Arc::new(Mutex::new(IdDevice(0xd)));
        let dev_e = Arc::new(Mutex::new(IdDevice(0xe)));

        let read = |addr| {
            let mut data = [0u8; 1];
            bus.read(addr, &mut data).unwrap();
            data[0]
        };
        let slot_of = |base| {
            *bus.ranges
                .read()
                .unwrap()
                .get(&BusRange::new(base, 0x100).unwrap())
                .unwrap()
        };

        bus.insert(dev_a.clone(), 0x1000, 0x100).unwrap();
        bus.insert(dev_b.clone(), 0x2000, 0x100).unwrap();
        bus.insert(dev_c.clone(), 0x3000, 0x100).unwrap();

        // Every range decodes to the device that owns it, at both ends.
        assert_eq!(read(0x1000), 0xa);
        assert_eq!(read(0x10ff), 0xa);
        assert_eq!(read(0x2000), 0xb);
        assert_eq!(read(0x20ff), 0xb);
        assert_eq!(read(0x3000), 0xc);
        assert_eq!(read(0x30ff), 0xc);

        // Removing the middle device leaves its range undecoded and does not
        // disturb the routing of the others.
        let slot_b = slot_of(0x2000);
        bus.remove(0x2000, 0x100).unwrap();
        bus.read(0x2000, &mut [0; 1]).unwrap_err();
        assert_eq!(read(0x1000), 0xa);
        assert_eq!(read(0x3000), 0xc);

        // The next insertion recycles the slot freed above. The new device
        // must only answer within its own range, and the removed range must
        // stay dead.
        bus.insert(dev_d.clone(), 0x4000, 0x100).unwrap();
        assert_eq!(slot_of(0x4000), slot_b);
        assert_eq!(read(0x4000), 0xd);
        bus.read(0x2000, &mut [0; 1]).unwrap_err();
        assert_eq!(read(0x1000), 0xa);
        assert_eq!(read(0x3000), 0xc);

        // Reusing the freed range rebinds it to the new device
        bus.insert(dev_e.clone(), 0x2000, 0x100).unwrap();
        assert_eq!(read(0x2000), 0xe);
    }

    #[test]
    fn bus_insert() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
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
        let dummy = Arc::new(Mutex::new(DummyDevice));

        bus.remove(0x42, 0x0).unwrap_err();

        bus.remove(0x13, 0x12).unwrap_err();

        bus.insert(dummy.clone(), 0x13, 0x12).unwrap();
        bus.remove(0x42, 0x42).unwrap_err();
        bus.remove(0x13, 0x12).unwrap();
    }

    #[test]
    fn bus_move_range() {
        let bus = Bus::new();
        let dev = Arc::new(Mutex::new(ConstantDevice));
        bus.insert(dev.clone(), 0x10, 0x10).unwrap();

        // A zero length is rejected before the mapping is touched.
        assert!(matches!(
            bus.move_range(0x10, 0x30, 0),
            Err(BusError::ZeroSizedRange)
        ));

        // Moving a range that is not registered fails and leaves the bus untouched.
        assert!(matches!(
            bus.move_range(0x2000, 0x3000, 0x10),
            Err(BusError::MissingAddressRange)
        ));

        // The device is reachable at its original base but not at the target.
        bus.read(0x10, &mut [0; 4]).unwrap();
        bus.read(0x30, &mut [0; 4]).unwrap_err();

        // Relocate the mapping; reads now resolve at the new base and the
        // ConstantDevice still answers relative to the (new) range base.
        bus.move_range(0x10, 0x30, 0x10).unwrap();
        bus.read(0x10, &mut [0; 4]).unwrap_err();
        let mut values = [0, 1, 2, 3];
        bus.read(0x35, &mut values).unwrap();
        assert_eq!(values, [5, 6, 7, 8]);

        // Moving a mapping onto its own base is a no-op.
        bus.move_range(0x30, 0x30, 0x10).unwrap();
        bus.read(0x35, &mut [0; 4]).unwrap();

        // A destination overlapping the source is accepted, because the old
        // range is removed before the overlap check runs.
        bus.move_range(0x30, 0x38, 0x10).unwrap();
        bus.read(0x30, &mut [0; 4]).unwrap_err();
        let mut values = [0, 1, 2, 3];
        bus.read(0x3d, &mut values).unwrap();
        assert_eq!(values, [5, 6, 7, 8]);

        // A move onto a range occupied by another device is rejected, and the
        // source mapping is left in place so nothing is lost.
        bus.insert(dev.clone(), 0x10, 0x10).unwrap();
        assert!(matches!(
            bus.move_range(0x38, 0x18, 0x10),
            Err(BusError::Overlap)
        ));
        bus.read(0x3d, &mut [0; 4]).unwrap();
        bus.read(0x15, &mut [0; 4]).unwrap();
    }

    #[test]
    #[should_panic(expected = "is registered with length")]
    fn bus_move_range_wrong_len() {
        let bus = Bus::new();
        let dev = Arc::new(Mutex::new(DummyDevice));
        bus.insert(dev, 0x10, 0x10).unwrap();
        let _ = bus.move_range(0x10, 0x30, 0x20);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn bus_read_write() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
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
        let dummy = Arc::new(Mutex::new(ConstantDevice));
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
        let range = BusRange::new(0x10, 2).unwrap();
        assert_eq!(range, BusRange::new(0x10, 3).unwrap());
        assert_eq!(range, BusRange::new(0x10, 2).unwrap());

        assert!(range < BusRange::new(0x12, 1).unwrap());
        assert!(range < BusRange::new(0x12, 3).unwrap());

        assert_eq!(range, range.clone());

        let bus = Bus::new();
        let mut data = [1, 2, 3, 4];
        let device = Arc::new(Mutex::new(DummyDevice));
        bus.insert(device.clone(), 0x10, 0x10).unwrap();
        bus.write(0x10, &data).unwrap();
        bus.read(0x10, &mut data).unwrap();
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn bus_range_overlap() {
        let a = BusRange::new(0x1000, 0x400).unwrap();
        assert!(a.overlaps(&BusRange::new(0x1000, 0x400).unwrap()));
        assert!(a.overlaps(&BusRange::new(0xf00, 0x400).unwrap()));
        assert!(a.overlaps(&BusRange::new(0x1000, 0x01).unwrap()));
        assert!(a.overlaps(&BusRange::new(0xfff, 0x02).unwrap()));
        assert!(a.overlaps(&BusRange::new(0x1100, 0x100).unwrap()));
        assert!(a.overlaps(&BusRange::new(0x13ff, 0x100).unwrap()));
        assert!(!a.overlaps(&BusRange::new(0x1400, 0x100).unwrap()));
        assert!(!a.overlaps(&BusRange::new(0xf00, 0x100).unwrap()));
    }
}
