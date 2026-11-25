// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Errors of the address and id allocators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum AllocatorError {
    /// Management operations on desired resource resulted in overflow.
    Overflow,
    /// Specified id: {0} is not in the range.
    OutOfRange(u32),
    /// Specified id: {0} was never allocated, can't release it.
    NeverAllocated(u32),
    /// The requested resource is not available.
    ResourceNotAvailable,
    /// The range specified: {0}-{1} is not valid.
    InvalidRange(u64, u64),
    /// Alignment value is invalid.
    InvalidAlignment,
    /// The address is not aligned.
    UnalignedAddress,
    /// The specified size: {0} is not valid.
    InvalidSize(u64),
}

/// Where [`AddressAllocator::allocate`] places a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocPolicy {
    /// At the lowest free address that fits.
    FirstMatch,
    /// At the highest free address that fits.
    LastMatch,
    /// At the given address.
    ExactMatch(u64),
}

/// Maximum number of ranges an [`AddressAllocator`] can have allocated at once.
///
/// The busiest allocator is the 32-bit MMIO one, with one range per MMIO device (at most one per
/// legacy GSI, so 96) and up to two per PCI device (at most 63 devices and 31 root ports). The
/// rest is room for BAR relocations, which allocate the new BAR before freeing the old one.
#[cfg(not(kani))]
pub const ALLOCATED_RANGES_MAX: usize = 256;
/// Three ranges are enough for a range to be allocated or freed before, between and after others,
/// and for the proofs to cover full allocators.
#[cfg(kani)]
pub const ALLOCATED_RANGES_MAX: usize = 3;

/// Range of addresses from `start` to `end`, both included.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Range {
    start: u64,
    end: u64,
}

/// Allocator of ranges from the address space `[base, end]`.
///
/// Allocated ranges are kept sorted by address in an array, so the free ranges are the gaps
/// between them. Allocation scans the gaps in address order, exact allocation and free binary
/// search the first addresses. The array has a static size, so the allocator never allocates
/// memory.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AddressAllocator {
    /// First address of the address space.
    pub base: u64,
    /// Last address of the address space.
    pub end: u64,
    /// Number of allocated ranges.
    count: u32,
    /// Allocated ranges, in increasing order. Zero past `count`.
    ranges: [Range; ALLOCATED_RANGES_MAX],
}

/// Try to calculate the first address at which `size` bytes aligned to `alignment` fit in the free
/// range, following `policy`.
fn try_fit_into_range(range: Range, size: u64, alignment: u64, policy: AllocPolicy) -> Option<u64> {
    assert!(range.start <= range.end);
    assert!(0 < size);
    assert!(alignment.is_power_of_two());

    // `range.end - range.start` and `size - 1` are the sizes minus one, so they cannot overflow.
    if range.end - range.start < size - 1 {
        return None;
    }
    let start = match policy {
        AllocPolicy::FirstMatch => range.start.checked_next_multiple_of(alignment)?,
        AllocPolicy::LastMatch => (range.end - (size - 1)) & !(alignment - 1),
        AllocPolicy::ExactMatch(start) => start,
    };
    if start < range.start || range.end < start {
        return None;
    }
    (size - 1 <= range.end - start).then_some(start)
}

impl AddressAllocator {
    /// Creates an allocator of the `size` bytes of address space starting at `base`.
    pub fn new(base: u64, size: u64) -> Self {
        assert!(0 < size);
        let end = base
            .checked_add(size - 1)
            .expect("address space end overflows");
        Self {
            base,
            end,
            count: 0,
            ranges: [Range::default(); ALLOCATED_RANGES_MAX],
        }
    }

    /// Whether the address space is valid and the allocated ranges are disjoint ranges of it,
    /// sorted by address.
    fn is_valid(&self) -> bool {
        let count = self.count as usize;
        if self.end < self.base || ALLOCATED_RANGES_MAX < count {
            return false;
        }
        // Lowest address the next allocated range can start at.
        let mut start_min = self.base;
        for index in 0..count {
            let range = self.ranges[index];
            if range.start < start_min || range.end < range.start || self.end < range.end {
                return false;
            }
            match range.end.checked_add(1) {
                Some(start) => start_min = start,
                None => return index + 1 == count,
            }
        }
        true
    }

    /// Allocates `size` bytes aligned to `alignment` and returns their first address.
    pub fn allocate(
        &mut self,
        size: u64,
        alignment: u64,
        policy: AllocPolicy,
    ) -> Result<u64, AllocatorError> {
        if size == 0 {
            return Err(AllocatorError::InvalidSize(size));
        }
        if !alignment.is_power_of_two() {
            return Err(AllocatorError::InvalidAlignment);
        }
        let count = self.count as usize;
        if count == ALLOCATED_RANGES_MAX {
            return Err(AllocatorError::ResourceNotAvailable);
        }

        // Index and first address at which the range fits in the free range before the allocated
        // range at `index`. A closure rather than a method, as only then the compiler inlines it
        // into the scans, which then take half the instructions.
        let fits_before_index = |index: usize| {
            let start = match index {
                0 => self.base,
                _ => self.ranges[index - 1].end.checked_add(1)?,
            };
            let end = match index == count {
                true => self.end,
                false => self.ranges[index].start.checked_sub(1)?,
            };
            // In most cases there is no space between allocated ranges, so reject empty gaps early.
            if end < start {
                return None;
            }
            let fit = try_fit_into_range(Range { start, end }, size, alignment, policy)?;
            Some((index, fit))
        };
        let found = match policy {
            AllocPolicy::FirstMatch => (0..=count).find_map(fits_before_index),
            AllocPolicy::LastMatch => (0..=count).rev().find_map(fits_before_index),
            AllocPolicy::ExactMatch(start) => {
                if !start.is_multiple_of(alignment) {
                    return Err(AllocatorError::UnalignedAddress);
                }
                // The only gap that can contain `start` is the one before the first allocated
                // range starting after it.
                let index = self.ranges[..count].partition_point(|range| range.start <= start);
                fits_before_index(index)
            }
        };
        let (index, start) = found.ok_or(AllocatorError::ResourceNotAvailable)?;

        self.ranges.copy_within(index..count, index + 1);
        self.ranges[index] = Range {
            start,
            end: start + (size - 1),
        };
        self.count += 1;

        assert!(self.is_valid());
        Ok(start)
    }

    /// Frees the `size` bytes at `start`, which must have been allocated with that size.
    pub fn free(&mut self, start: u64, size: u64) -> Result<(), AllocatorError> {
        let count = self.count as usize;
        let index = self.ranges[..count]
            .binary_search_by_key(&start, |range| range.start)
            .map_err(|_| AllocatorError::ResourceNotAvailable)?;
        if size.checked_sub(1) != Some(self.ranges[index].end - start) {
            return Err(AllocatorError::ResourceNotAvailable);
        }

        self.ranges.copy_within(index + 1..count, index);
        self.ranges[count - 1] = Range::default();
        self.count -= 1;

        assert!(self.is_valid());
        Ok(())
    }
}

impl fmt::Debug for AddressAllocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AddressAllocator")
            .field("base", &self.base)
            .field("end", &self.end)
            .field("ranges", &&self.ranges[..self.count as usize])
            .finish()
    }
}

/// Serialized as a sequence of the address space bounds followed by the bounds of each allocated
/// range, so only the allocated ranges take space.
impl Serialize for AddressAllocator {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ranges = &self.ranges[..self.count as usize];
        let mut seq = serializer.serialize_seq(Some(2 + 2 * ranges.len()))?;
        seq.serialize_element(&self.base)?;
        seq.serialize_element(&self.end)?;
        for range in ranges {
            seq.serialize_element(&range.start)?;
            seq.serialize_element(&range.end)?;
        }
        seq.end()
    }
}

/// Fills an [`AddressAllocator`] in place from its serialized sequence and rejects it unless its
/// allocated ranges are valid.
struct AddressAllocatorVisitor;

impl<'de> Visitor<'de> for AddressAllocatorVisitor {
    type Value = AddressAllocator;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("address space bounds followed by allocated range bounds")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        fn missing<E: Error>() -> E {
            E::custom("missing address allocator bound")
        }

        let mut allocator = AddressAllocator {
            base: seq.next_element()?.ok_or_else(missing)?,
            end: seq.next_element()?.ok_or_else(missing)?,
            count: 0,
            ranges: [Range::default(); ALLOCATED_RANGES_MAX],
        };
        while let Some(start) = seq.next_element()? {
            let count = allocator.count as usize;
            if count == ALLOCATED_RANGES_MAX {
                return Err(A::Error::custom("too many allocated ranges"));
            }
            allocator.ranges[count] = Range {
                start,
                end: seq.next_element()?.ok_or_else(missing)?,
            };
            allocator.count += 1;
        }
        if !allocator.is_valid() {
            return Err(A::Error::custom("invalid allocated ranges"));
        }
        Ok(allocator)
    }
}

impl<'de> Deserialize<'de> for AddressAllocator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(AddressAllocatorVisitor)
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    fn any_allocator() -> AddressAllocator {
        let mut allocator = AddressAllocator {
            base: kani::any(),
            end: kani::any(),
            count: kani::any_where(|&count| count as usize <= ALLOCATED_RANGES_MAX),
            ranges: [Range::default(); ALLOCATED_RANGES_MAX],
        };
        for index in 0..allocator.count as usize {
            allocator.ranges[index] = Range {
                start: kani::any(),
                end: kani::any(),
            };
        }
        kani::assume(allocator.is_valid());
        allocator
    }

    fn is_range_free(allocator: &AddressAllocator, start: u64, size: u64) -> bool {
        let Some(end) = start.checked_add(size - 1) else {
            return false;
        };
        allocator.base <= start
            && end <= allocator.end
            && allocator.ranges[..allocator.count as usize]
                .iter()
                .all(|range| end < range.start || range.end < start)
    }

    /// Allocation fails with an error for each invalid argument, when the allocator is full or when
    /// no free aligned address fits the range, leaving the allocator unchanged. Otherwise it
    /// allocates the range at the address the policy selects among all that fit, keeping the other
    /// ranges.
    fn verify_allocate(policy: AllocPolicy) {
        let mut allocator = any_allocator();
        let old = allocator;
        let size: u64 = kani::any();
        let alignment: u64 = kani::any();
        let result = allocator.allocate(size, alignment, policy);

        if size == 0 {
            assert_eq!(result, Err(AllocatorError::InvalidSize(0)));
        } else if !alignment.is_power_of_two() {
            assert_eq!(result, Err(AllocatorError::InvalidAlignment));
        } else if old.count as usize == ALLOCATED_RANGES_MAX {
            assert_eq!(result, Err(AllocatorError::ResourceNotAvailable));
        } else if let AllocPolicy::ExactMatch(start) = policy
            && start & (alignment - 1) != 0
        {
            assert_eq!(result, Err(AllocatorError::UnalignedAddress));
        } else {
            // Any address the range fits at. Kani covers all of them.
            let address: u64 = kani::any();
            let fits = address & (alignment - 1) == 0
                && is_range_free(&old, address, size)
                && !matches!(policy, AllocPolicy::ExactMatch(start) if start != address);
            match result {
                Ok(start) => {
                    assert_eq!(start & (alignment - 1), 0);
                    assert!(is_range_free(&old, start, size));
                    match policy {
                        AllocPolicy::FirstMatch => assert!(!fits || start <= address),
                        AllocPolicy::LastMatch => assert!(!fits || address <= start),
                        AllocPolicy::ExactMatch(exact) => assert_eq!(start, exact),
                    }
                    assert!(allocator.is_valid());
                    // Freeing the range restores the old ranges, so allocation kept them.
                    assert_eq!(allocator.free(start, size), Ok(()));
                }
                Err(err) => {
                    assert_eq!(err, AllocatorError::ResourceNotAvailable);
                    assert!(!fits);
                }
            }
        }
        assert!(allocator == old);
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn verify_allocate_first_match() {
        verify_allocate(AllocPolicy::FirstMatch);
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn verify_allocate_last_match() {
        verify_allocate(AllocPolicy::LastMatch);
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn verify_allocate_exact_match() {
        verify_allocate(AllocPolicy::ExactMatch(kani::any()));
    }

    /// Freeing succeeds only for an allocated range of the given size, and removes only it,
    /// clearing its slot. Otherwise it fails leaving the allocator unchanged.
    #[kani::proof]
    #[kani::unwind(4)]
    fn verify_free() {
        let mut allocator = any_allocator();
        let old = allocator;
        let start: u64 = kani::any();
        let size: u64 = kani::any();
        let result = allocator.free(start, size);

        let freed = old.ranges[..old.count as usize].iter().position(|range| {
            range.start == start && size.checked_sub(1) == Some(range.end - start)
        });
        match freed {
            Some(freed) => {
                assert_eq!(result, Ok(()));
                assert_eq!(allocator.count + 1, old.count);
                assert!(allocator.is_valid());
                // The ranges after the freed one move down, and the last slot is cleared, as
                // slots past the allocated ranges are.
                for index in 0..ALLOCATED_RANGES_MAX {
                    let shift = usize::from(freed <= index);
                    let range = old.ranges.get(index + shift).copied();
                    assert_eq!(allocator.ranges[index], range.unwrap_or_default());
                }
            }
            None => {
                assert_eq!(result, Err(AllocatorError::ResourceNotAvailable));
                assert!(allocator == old);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(allocator: &AddressAllocator) -> Vec<(u64, u64)> {
        let count = allocator.count as usize;
        allocator.ranges[..count]
            .iter()
            .map(|range| (range.start, range.end))
            .collect()
    }

    #[test]
    fn test_new() {
        let allocator = AddressAllocator::new(0x1000, 0x1000);
        assert_eq!(allocator.base, 0x1000);
        assert_eq!(allocator.end, 0x1fff);
        assert!(ranges(&allocator).is_empty());

        let allocator = AddressAllocator::new(0, u64::MAX);
        assert_eq!(allocator.end, u64::MAX - 1);
        let allocator = AddressAllocator::new(1, u64::MAX);
        assert_eq!(allocator.end, u64::MAX);
    }

    #[test]
    #[should_panic(expected = "address space end overflows")]
    fn test_new_overflow() {
        AddressAllocator::new(2, u64::MAX);
    }

    #[test]
    #[should_panic]
    fn test_new_size_zero() {
        AddressAllocator::new(0x1000, 0);
    }

    #[test]
    fn test_allocate_invalid_arguments() {
        let mut allocator = AddressAllocator::new(0x1000, 0x10000);
        assert_eq!(
            allocator.allocate(0, 1, AllocPolicy::FirstMatch),
            Err(AllocatorError::InvalidSize(0))
        );
        for alignment in [0, 3, 0x1001] {
            assert_eq!(
                allocator.allocate(0x100, alignment, AllocPolicy::FirstMatch),
                Err(AllocatorError::InvalidAlignment)
            );
        }
        assert_eq!(
            allocator.allocate(0x100, 0x100, AllocPolicy::ExactMatch(0x1010)),
            Err(AllocatorError::UnalignedAddress)
        );
        assert!(ranges(&allocator).is_empty());
    }

    #[test]
    fn test_allocate_first_match() {
        let mut allocator = AddressAllocator::new(0x1001, 0x10000);
        assert_eq!(
            allocator.allocate(0x100, 0x1000, AllocPolicy::FirstMatch),
            Ok(0x2000)
        );
        // Fits before the first range.
        assert_eq!(
            allocator.allocate(0x10, 0x10, AllocPolicy::FirstMatch),
            Ok(0x1010)
        );
        assert_eq!(
            allocator.allocate(0x100, 1, AllocPolicy::FirstMatch),
            Ok(0x1020)
        );
        // Does not fit before 0x2000 anymore.
        assert_eq!(
            allocator.allocate(0xf00, 1, AllocPolicy::FirstMatch),
            Ok(0x2100)
        );
        assert_eq!(
            ranges(&allocator),
            [
                (0x1010, 0x101f),
                (0x1020, 0x111f),
                (0x2000, 0x20ff),
                (0x2100, 0x2fff)
            ]
        );
        // The space left is [0x3000, 0x11000].
        assert_eq!(
            allocator.allocate(0xe002, 1, AllocPolicy::FirstMatch),
            Err(AllocatorError::ResourceNotAvailable)
        );
        assert_eq!(
            allocator.allocate(0xe001, 1, AllocPolicy::FirstMatch),
            Ok(0x3000)
        );
    }

    #[test]
    fn test_allocate_last_match() {
        let mut allocator = AddressAllocator::new(0x1000, 0x10000);
        assert_eq!(
            allocator.allocate(0x100, 0x1000, AllocPolicy::LastMatch),
            Ok(0x10000)
        );
        assert_eq!(
            allocator.allocate(0x10, 0x10, AllocPolicy::LastMatch),
            Ok(0x10ff0)
        );
        // No address aligned to 0x10000 is free.
        assert_eq!(
            allocator.allocate(0x100, 0x10000, AllocPolicy::LastMatch),
            Err(AllocatorError::ResourceNotAvailable)
        );
        assert_eq!(
            allocator.allocate(0x100, 0x1000, AllocPolicy::LastMatch),
            Ok(0xf000)
        );
        assert_eq!(
            ranges(&allocator),
            [(0xf000, 0xf0ff), (0x10000, 0x100ff), (0x10ff0, 0x10fff)]
        );
    }

    #[test]
    fn test_allocate_exact_match() {
        let mut allocator = AddressAllocator::new(0x1000, 0x2000);
        assert_eq!(
            allocator.allocate(0x1000, 0x1000, AllocPolicy::ExactMatch(0x2000)),
            Ok(0x2000)
        );
        // Overlaps the range at 0x2000.
        for start in [0x1800, 0x2000, 0x2800] {
            assert_eq!(
                allocator.allocate(0x1000, 0x800, AllocPolicy::ExactMatch(start)),
                Err(AllocatorError::ResourceNotAvailable)
            );
        }
        // Outside the address space.
        for start in [0, 0x3000] {
            assert_eq!(
                allocator.allocate(0x10, 0x10, AllocPolicy::ExactMatch(start)),
                Err(AllocatorError::ResourceNotAvailable)
            );
        }
        assert_eq!(
            allocator.allocate(0x1000, 0x1000, AllocPolicy::ExactMatch(0x1000)),
            Ok(0x1000)
        );
        assert_eq!(ranges(&allocator), [(0x1000, 0x1fff), (0x2000, 0x2fff)]);
        assert_eq!(
            allocator.allocate(1, 1, AllocPolicy::FirstMatch),
            Err(AllocatorError::ResourceNotAvailable)
        );
    }

    #[test]
    fn test_allocate_address_space_bounds() {
        let mut allocator = AddressAllocator::new(0, u64::MAX);
        assert_eq!(allocator.allocate(1, 1, AllocPolicy::FirstMatch), Ok(0));
        assert_eq!(
            allocator.allocate(1, 1, AllocPolicy::LastMatch),
            Ok(u64::MAX - 1)
        );
        assert_eq!(
            allocator.allocate(u64::MAX - 2, 1, AllocPolicy::FirstMatch),
            Ok(1)
        );
        assert_eq!(
            allocator.allocate(1, 1, AllocPolicy::FirstMatch),
            Err(AllocatorError::ResourceNotAvailable)
        );

        let mut allocator = AddressAllocator::new(1, u64::MAX);
        assert_eq!(
            allocator.allocate(0x1000, 0x1000, AllocPolicy::LastMatch),
            Ok(u64::MAX - 0xfff)
        );
        assert_eq!(allocator.allocate(1, 1, AllocPolicy::FirstMatch), Ok(1));
        assert_eq!(
            allocator.allocate(0x10, 1 << 63, AllocPolicy::FirstMatch),
            Ok(1 << 63)
        );
        // Aligning up the start of the free range after 1 << 63 overflows.
        assert_eq!(
            allocator.allocate(1, 1 << 63, AllocPolicy::FirstMatch),
            Err(AllocatorError::ResourceNotAvailable)
        );
    }

    #[test]
    fn test_allocate_capacity() {
        let size = ALLOCATED_RANGES_MAX as u64;
        let mut allocator = AddressAllocator::new(0, size + 1);
        for start in 0..size {
            assert_eq!(allocator.allocate(1, 1, AllocPolicy::FirstMatch), Ok(start));
        }
        // There is free space, but no room left to track another range.
        assert_eq!(
            allocator.allocate(1, 1, AllocPolicy::FirstMatch),
            Err(AllocatorError::ResourceNotAvailable)
        );
        allocator.free(7, 1).unwrap();
        assert_eq!(allocator.allocate(1, 1, AllocPolicy::LastMatch), Ok(size));
    }

    #[test]
    fn test_free() {
        let mut allocator = AddressAllocator::new(0x1000, 0x10000);
        let first = allocator
            .allocate(0x1000, 0x1000, AllocPolicy::FirstMatch)
            .unwrap();
        let second = allocator
            .allocate(0x1000, 0x1000, AllocPolicy::FirstMatch)
            .unwrap();
        let third = allocator
            .allocate(0x1000, 0x1000, AllocPolicy::FirstMatch)
            .unwrap();

        // Only exactly allocated ranges can be freed.
        for (start, size) in [
            (second, 0),
            (second, 0x800),
            (second, 0x2000),
            (second + 0x800, 0x800),
            (0x10000, 0x1000),
        ] {
            assert_eq!(
                allocator.free(start, size),
                Err(AllocatorError::ResourceNotAvailable)
            );
        }

        allocator.free(second, 0x1000).unwrap();
        assert_eq!(
            allocator.free(second, 0x1000),
            Err(AllocatorError::ResourceNotAvailable)
        );
        assert_eq!(ranges(&allocator), [(first, 0x1fff), (third, 0x3fff)]);
        // Freed slots are cleared, so equal allocations compare equal.
        let mut expected = AddressAllocator::new(0x1000, 0x10000);
        expected
            .allocate(0x1000, 1, AllocPolicy::ExactMatch(first))
            .unwrap();
        expected
            .allocate(0x1000, 1, AllocPolicy::ExactMatch(third))
            .unwrap();
        assert_eq!(allocator, expected);

        // The freed range merges with the free space around it.
        assert_eq!(
            allocator.allocate(0x1000, 1, AllocPolicy::FirstMatch),
            Ok(second)
        );
        allocator.free(first, 0x1000).unwrap();
        allocator.free(second, 0x1000).unwrap();
        allocator.free(third, 0x1000).unwrap();
        assert_eq!(
            allocator.allocate(0x10000, 1, AllocPolicy::FirstMatch),
            Ok(0x1000)
        );
    }

    #[test]
    fn test_serde() {
        let mut allocator = AddressAllocator::new(0x1000, 0x10000);
        allocator
            .allocate(0x1000, 0x1000, AllocPolicy::FirstMatch)
            .unwrap();
        allocator
            .allocate(0x10, 0x10, AllocPolicy::LastMatch)
            .unwrap();

        let data = bitcode::serialize(&allocator).unwrap();
        let restored: AddressAllocator = bitcode::deserialize(&data).unwrap();
        assert_eq!(restored, allocator);
    }

    #[test]
    fn test_deserialize_invalid() {
        let too_many = std::iter::once(0)
            .chain(std::iter::once(u64::MAX))
            .chain((0..=ALLOCATED_RANGES_MAX as u64).flat_map(|start| [start, start]))
            .collect::<Vec<_>>();
        let too_many = serde_json::to_string(&too_many).unwrap();
        for json in [
            "[]",
            "[4096]",
            // End of the address space before its base.
            "[4096,4095]",
            // Missing range end.
            "[4096,8191,4096]",
            // Range end before its start.
            "[4096,8191,5000,4999]",
            // Range outside the address space.
            "[4096,8191,0,4096]",
            "[4096,8191,8191,8192]",
            "[0,100,50,18446744073709551615]",
            // Overlapping ranges.
            "[4096,8191,4096,5000,5000,6000]",
            // Unsorted ranges.
            "[4096,8191,6000,7000,4096,5000]",
            // A range after one ending at the last address.
            "[0,18446744073709551615,18446744073709551615,18446744073709551615,0,0]",
            &too_many,
        ] {
            serde_json::from_str::<AddressAllocator>(json).unwrap_err();
        }
    }
}
