// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::btree_map::BTreeMap;
use std::result;
use vm_memory::{Address, GuestAddress, GuestUsize};

#[derive(Debug)]
pub enum Error {
    Overflow,
    Overlap,
    UnalignedAddress,
}

pub type Result<T> = result::Result<T, Error>;

/// Manages allocating address ranges.
/// Use `AddressAllocator` whenever an address range needs to be allocated to different users.
///
/// # Examples
///
/// ```
/// # use vm_allocator::AddressAllocator;
/// # use vm_memory::{Address, GuestAddress, GuestUsize};
///   AddressAllocator::new(GuestAddress(0x1000), 0x10000).map(|mut pool| {
///       assert_eq!(pool.allocate(None, 0x110, Some(0x100)), Some(GuestAddress(0x10e00)));
///       assert_eq!(pool.allocate(None, 0x100, Some(0x100)), Some(GuestAddress(0x10d00)));
///   });
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct AddressAllocator {
    base: GuestAddress,
    end: GuestAddress,
    ranges: BTreeMap<GuestAddress, GuestUsize>,
}

impl AddressAllocator {
    /// Creates a new `AddressAllocator` for managing a range of addresses.
    /// Can return `None` if `base` + `size` overflows a u64.
    ///
    /// * `base` - The starting address of the range to manage.
    /// * `size` - The size of the address range in bytes.
    pub fn new(base: GuestAddress, size: GuestUsize) -> Option<Self> {
        if size == 0 {
            return None;
        }

        let end = base.checked_add(size - 1)?;

        let mut allocator = AddressAllocator {
            base,
            end,
            ranges: BTreeMap::new(),
        };

        // Insert the last address as a zero size range.
        // This is our end of address space marker.
        allocator.ranges.insert(base.checked_add(size)?, 0);

        Some(allocator)
    }

    fn align_address(&self, address: GuestAddress, alignment: GuestUsize) -> GuestAddress {
        let align_adjust = if address.raw_value() % alignment != 0 {
            alignment - (address.raw_value() % alignment)
        } else {
            0
        };

        address.unchecked_add(align_adjust)
    }

    fn available_range(
        &self,
        req_address: GuestAddress,
        req_size: GuestUsize,
        alignment: GuestUsize,
    ) -> Result<GuestAddress> {
        let aligned_address = self.align_address(req_address, alignment);

        // The requested address should be aligned.
        if aligned_address != req_address {
            return Err(Error::UnalignedAddress);
        }

        // The aligned address should be within the address space range.
        if aligned_address >= self.end || aligned_address < self.base {
            return Err(Error::Overflow);
        }

        let mut prev_end_address = self.base;
        for (address, size) in self.ranges.iter() {
            if aligned_address <= *address {
                // Do we overlap with the previous range?
                if prev_end_address > aligned_address {
                    return Err(Error::Overlap);
                }

                // Do we have enough space?
                if address
                    .unchecked_sub(aligned_address.raw_value())
                    .raw_value()
                    < req_size
                {
                    return Err(Error::Overlap);
                }

                return Ok(aligned_address);
            }

            prev_end_address = address.unchecked_add(*size);
        }

        // We have not found a range that starts after the requested address,
        // despite having a marker at the end of our range.
        Err(Error::Overflow)
    }

    fn first_available_range(
        &self,
        req_size: GuestUsize,
        alignment: GuestUsize,
    ) -> Option<GuestAddress> {
        let reversed_ranges: Vec<(&GuestAddress, &GuestUsize)> = self.ranges.iter().rev().collect();

        for (idx, (address, _size)) in reversed_ranges.iter().enumerate() {
            let next_range_idx = idx + 1;
            let prev_end_address = if next_range_idx >= reversed_ranges.len() {
                self.base
            } else {
                reversed_ranges[next_range_idx]
                    .0
                    .unchecked_add(*(reversed_ranges[next_range_idx].1))
            };

            // If we have enough space between this range and the previous one,
            // we return the start of this range minus the requested size.
            // As each new range is allocated at the end of the available address space,
            // we will tend to always allocate new ranges there as well. In other words,
            // ranges accumulate at the end of the address space.
            if let Some(size_delta) =
                address.checked_sub(self.align_address(prev_end_address, alignment).raw_value())
            {
                let adjust = if alignment > 1 { alignment - 1 } else { 0 };
                if size_delta.raw_value() >= req_size {
                    return Some(
                        self.align_address(address.unchecked_sub(req_size + adjust), alignment),
                    );
                }
            }
        }

        None
    }

    /// Allocates a range of addresses from the managed region. Returns `Some(allocated_address)`
    /// when successful, or `None` if an area of `size` can't be allocated or if alignment isn't
    /// a power of two.
    pub fn allocate(
        &mut self,
        address: Option<GuestAddress>,
        size: GuestUsize,
        align_size: Option<GuestUsize>,
    ) -> Option<GuestAddress> {
        if size == 0 {
            return None;
        }

        let alignment = align_size.unwrap_or(4);
        if !alignment.is_power_of_two() || alignment == 0 {
            return None;
        }

        let new_addr = match address {
            Some(req_address) => match self.available_range(req_address, size, alignment) {
                Ok(addr) => addr,
                Err(_) => {
                    return None;
                }
            },
            None => self.first_available_range(size, alignment)?,
        };

        self.ranges.insert(new_addr, size);

        Some(new_addr)
    }

    /// Free an already allocated address range.
    /// We can only free a range if it matches exactly an already allocated range.
    pub fn free(&mut self, address: GuestAddress, size: GuestUsize) {
        if let Some(&range_size) = self.ranges.get(&address) {
            if size == range_size {
                self.ranges.remove(&address);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_fails_overflow() {
        assert_eq!(
            AddressAllocator::new(GuestAddress(u64::max_value()), 0x100),
            None
        );
    }

    #[test]
    fn new_fails_size_zero() {
        assert_eq!(AddressAllocator::new(GuestAddress(0x1000), 0), None);
    }

    #[test]
    fn allocate_fails_alignment_zero() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x10000).unwrap();
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1000)), 0x100, Some(0)),
            None
        );
    }

    #[test]
    fn allocate_fails_alignment_non_power_of_two() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x10000).unwrap();
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1000)), 0x100, Some(200)),
            None
        );
    }

    #[test]
    fn allocate_fails_not_enough_space() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000).unwrap();
        assert_eq!(
            pool.allocate(None, 0x800, Some(0x100)),
            Some(GuestAddress(0x1800))
        );
        assert_eq!(pool.allocate(None, 0x900, Some(0x100)), None);
        assert_eq!(
            pool.allocate(None, 0x400, Some(0x100)),
            Some(GuestAddress(0x1400))
        );
    }

    #[test]
    fn allocate_alignment() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x10000).unwrap();
        assert_eq!(
            pool.allocate(None, 0x110, Some(0x100)),
            Some(GuestAddress(0x10e00))
        );
        assert_eq!(
            pool.allocate(None, 0x100, Some(0x100)),
            Some(GuestAddress(0x10d00))
        );
        assert_eq!(
            pool.allocate(None, 0x10, Some(0x100)),
            Some(GuestAddress(0x10c00))
        );
    }

    #[test]
    fn allocate_address() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000).unwrap();
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800, None),
            Some(GuestAddress(0x1200))
        );

        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1a00)), 0x100, None),
            Some(GuestAddress(0x1a00))
        );
    }

    #[test]
    fn allocate_address_alignment() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000).unwrap();
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800, Some(0x100)),
            Some(GuestAddress(0x1200))
        );

        // Unaligned request
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1210)), 0x800, Some(0x100)),
            None
        );

        // Aligned request
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1b00)), 0x100, Some(0x100)),
            Some(GuestAddress(0x1b00))
        );
    }

    #[test]
    fn allocate_address_not_enough_space() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000).unwrap();

        // First range is [0x1200:0x1a00]
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800, Some(0x100)),
            Some(GuestAddress(0x1200))
        );

        // Second range is [0x1c00:0x1e00]
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1c00)), 0x200, Some(0x100)),
            Some(GuestAddress(0x1c00))
        );

        // There is 0x200 between the first 2 ranges.
        // We ask for an available address but the range is too big
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1b00)), 0x800, Some(0x100)),
            None
        );

        // We ask for an available address, with a small enough range
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1b00)), 0x100, Some(0x100)),
            Some(GuestAddress(0x1b00))
        );
    }

    #[test]
    fn allocate_address_free_and_realloc() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000).unwrap();

        // First range is [0x1200:0x1a00]
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800, Some(0x100)),
            Some(GuestAddress(0x1200))
        );

        pool.free(GuestAddress(0x1200), 0x800);

        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800, Some(0x100)),
            Some(GuestAddress(0x1200))
        );
    }

    #[test]
    fn allocate_address_free_fail_and_realloc() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000).unwrap();

        // First range is [0x1200:0x1a00]
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800, Some(0x100)),
            Some(GuestAddress(0x1200))
        );

        // We try to free a range smaller than the allocated one.
        pool.free(GuestAddress(0x1200), 0x100);

        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800, Some(0x100)),
            None
        );
    }

    #[test]
    fn allocate_address_fail_free_and_realloc() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000).unwrap();

        // First allocation fails
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x2000, Some(0x100)),
            None
        );

        // We try to free a range that was not allocated.
        pool.free(GuestAddress(0x1200), 0x2000);

        // Now we try an allocation that should succeed.
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800, Some(0x100)),
            Some(GuestAddress(0x1200))
        );
    }
}
