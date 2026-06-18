// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bitvec::vec::BitVec;
use serde::{Deserialize, Serialize};
use vm_allocator::AddressAllocator;
pub use vm_allocator::AllocPolicy;

use crate::arch;
use crate::snapshot::Persist;

/// Helper function to allocate many ids from an id allocator
fn allocate_many_ids(
    id_allocator: &mut IdAllocator,
    count: u32,
) -> Result<Vec<u32>, vm_allocator::Error> {
    let mut ids = Vec::with_capacity(count as usize);

    for _ in 0..count {
        match id_allocator.allocate_id() {
            Ok(id) => ids.push(id),
            Err(err) => {
                // It is ok to unwrap here, we just allocated the GSI
                ids.into_iter().for_each(|id| {
                    id_allocator.free_id(id).unwrap();
                });
                return Err(err);
            }
        }
    }

    Ok(ids)
}

/// A resource manager for (de)allocating interrupt lines (GSIs) and guest memory
///
/// At the moment, we support:
///
/// * GSIs for legacy x86_64 devices
/// * GSIs for MMIO devicecs
/// * Memory allocations in the MMIO address space
#[derive(Debug, Clone)]
pub struct ResourceAllocator {
    /// Allocator for legacy device interrupt lines
    pub gsi_legacy_allocator: IdAllocator,
    /// Allocator for PCI device GSIs
    pub gsi_msi_allocator: IdAllocator,
    /// Allocator for memory in the 32-bit MMIO address space
    pub mmio32_memory: AddressAllocator,
    /// Allocator for memory in the 64-bit MMIO address space
    pub mmio64_memory: AddressAllocator,
    /// Allocator for memory after the 64-bit MMIO address space
    pub past_mmio64_memory: AddressAllocator,
    /// Memory allocator for system data
    pub system_memory: AddressAllocator,
}

impl Default for ResourceAllocator {
    fn default() -> Self {
        ResourceAllocator::new()
    }
}

impl ResourceAllocator {
    /// Create a new resource allocator for Firecracker devices
    pub fn new() -> Self {
        // It is fine for us to unwrap the following since we know we are passing valid ranges for
        // all allocators
        Self {
            gsi_legacy_allocator: IdAllocator::new(arch::GSI_LEGACY_START, arch::GSI_LEGACY_END)
                .unwrap(),
            gsi_msi_allocator: IdAllocator::new(arch::GSI_MSI_START, arch::GSI_MSI_END).unwrap(),
            mmio32_memory: AddressAllocator::new(
                arch::MEM_32BIT_DEVICES_START,
                arch::MEM_32BIT_DEVICES_SIZE,
            )
            .unwrap(),
            mmio64_memory: AddressAllocator::new(
                arch::MEM_64BIT_DEVICES_START,
                arch::MEM_64BIT_DEVICES_SIZE,
            )
            .unwrap(),
            past_mmio64_memory: AddressAllocator::new(
                arch::FIRST_ADDR_PAST_64BITS_MMIO,
                arch::PAST_64BITS_MMIO_SIZE,
            )
            .unwrap(),
            system_memory: AddressAllocator::new(arch::SYSTEM_MEM_START, arch::SYSTEM_MEM_SIZE)
                .unwrap(),
        }
    }

    /// Allocate a number of legacy GSIs
    ///
    /// # Arguments
    ///
    /// * `gsi_count` - The number of legacy GSIs to allocate
    pub fn allocate_gsi_legacy(&mut self, gsi_count: u32) -> Result<Vec<u32>, vm_allocator::Error> {
        allocate_many_ids(&mut self.gsi_legacy_allocator, gsi_count)
    }

    /// Allocate a number of GSIs for MSI
    ///
    /// # Arguments
    ///
    /// * `gsi_count` - The number of GSIs to allocate
    pub fn allocate_gsi_msi(&mut self, gsi_count: u32) -> Result<Vec<u32>, vm_allocator::Error> {
        allocate_many_ids(&mut self.gsi_msi_allocator, gsi_count)
    }
}

/// Serializable state for the resource allocator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocatorState {
    /// Allocator for legacy device interrupt lines
    pub gsi_legacy_allocator: IdAllocator,
    /// Allocator for memory in the 32-bit MMIO address space
    pub mmio32_memory: AddressAllocator,
    /// Allocator for memory in the 64-bit MMIO address space
    pub mmio64_memory: AddressAllocator,
    /// Allocator for memory after the 64-bit MMIO address space
    pub past_mmio64_memory: AddressAllocator,
    /// Memory allocator for system data
    pub system_memory: AddressAllocator,
}

impl Default for ResourceAllocatorState {
    fn default() -> Self {
        ResourceAllocator::new().save()
    }
}

impl<'a> Persist<'a> for ResourceAllocator {
    type State = ResourceAllocatorState;
    type ConstructorArgs = ();
    type Error = vm_allocator::Error;

    fn save(&self) -> Self::State {
        ResourceAllocatorState {
            gsi_legacy_allocator: self.gsi_legacy_allocator.clone(),
            mmio32_memory: self.mmio32_memory.clone(),
            mmio64_memory: self.mmio64_memory.clone(),
            past_mmio64_memory: self.past_mmio64_memory.clone(),
            system_memory: self.system_memory.clone(),
        }
    }

    fn restore(
        _constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        Ok(ResourceAllocator {
            gsi_legacy_allocator: state.gsi_legacy_allocator.clone(),
            gsi_msi_allocator: IdAllocator::new(arch::GSI_MSI_START, arch::GSI_MSI_END)?,
            mmio32_memory: state.mmio32_memory.clone(),
            mmio64_memory: state.mmio64_memory.clone(),
            past_mmio64_memory: state.past_mmio64_memory.clone(),
            system_memory: state.system_memory.clone(),
        })
    }
}

/// An unique ID allocator that allows management of IDs in a given interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdAllocator {
    // Beginning of the range of IDs that we want to manage.
    range_base: u32,
    // One bit per id in the managed range. A set bit means the corresponding
    // id is currently allocated.
    allocated: BitVec,
}

impl IdAllocator {
    /// Create a new IdAllocator with IDs in [`range_base`, `range_end`].
    pub fn new(range_base: u32, range_end: u32) -> Result<Self, vm_allocator::Error> {
        if range_end < range_base {
            return Err(vm_allocator::Error::InvalidRange(
                range_base.into(),
                range_end.into(),
            ));
        }

        let num_ids = u64::from(range_end) - u64::from(range_base) + 1;
        let num_ids = usize::try_from(num_ids).map_err(|_| vm_allocator::Error::Overflow)?;
        let mut allocated = BitVec::with_capacity(num_ids);
        allocated.resize(num_ids, false);

        Ok(IdAllocator {
            range_base,
            allocated,
        })
    }

    /// Map `id` to its corresponding index in the bitmap.
    fn index_for(&self, id: u32) -> Result<usize, vm_allocator::Error> {
        let offset = id
            .checked_sub(self.range_base)
            .ok_or(vm_allocator::Error::OutOfRange(id))?;
        let index = offset as usize;
        self.allocated
            .get(index)
            .map(|_| index)
            .ok_or(vm_allocator::Error::OutOfRange(id))
    }

    // Given `index` into the bitmap, return the `id` in that position
    // Returns `vm_allocator::Error::Overflow` if the index would map to an overflowed id.
    fn id_for_index(&self, index: usize) -> Result<u32, vm_allocator::Error> {
        let offset = u32::try_from(index).map_err(|_| vm_allocator::Error::Overflow)?;
        self.range_base
            .checked_add(offset)
            .ok_or(vm_allocator::Error::Overflow)
    }

    /// Allocate an ID from the managed range.Returns the first available id
    /// from the managed range, or `ResourceNotAvailable` if every id has been
    /// handed out.
    pub fn allocate_id(&mut self) -> Result<u32, vm_allocator::Error> {
        if let Some(index) = self.allocated.first_zero() {
            self.allocated.set(index, true);
            let id = self.id_for_index(index)?;
            Ok(id)
        } else {
            Err(vm_allocator::Error::ResourceNotAvailable)
        }
    }

    /// Allocate the specified ID from the managed range.
    ///
    /// Returns `id` on success, `OutOfRange` if `id` is outside the managed
    /// range, or `ResourceNotAvailable` if `id` has already been allocated.
    pub fn allocate_id_at(&mut self, id: u32) -> Result<u32, vm_allocator::Error> {
        let index = self.index_for(id)?;
        if !self.allocated[index] {
            self.allocated.set(index, true);
            Ok(id)
        } else {
            Err(vm_allocator::Error::ResourceNotAvailable)
        }
    }

    /// Returns `true` if `id` is currently allocated from the managed range.
    ///
    /// Ids outside the managed range are considered never allocated, so return false.
    pub fn is_allocated(&self, id: u32) -> bool {
        match self.index_for(id) {
            Ok(index) => self.allocated[index],
            Err(_) => false,
        }
    }

    /// Frees an id from the managed range.
    pub fn free_id(&mut self, id: u32) -> Result<u32, vm_allocator::Error> {
        let index = self.index_for(id)?;
        if self.allocated[index] {
            self.allocated.set(index, false);
            Ok(id)
        } else {
            Err(vm_allocator::Error::NeverAllocated(id))
        }
    }
}

#[cfg(test)]
mod tests {
    mod resource_allocator {
        use super::super::{AllocPolicy, ResourceAllocator};
        use crate::arch::{self, GSI_LEGACY_NUM, GSI_MSI_NUM};
        use crate::snapshot::Persist;

        #[test]
        fn test_allocate_irq() {
            let mut allocator = ResourceAllocator::new();
            // asking for 0 IRQs should return us an empty vector
            assert_eq!(allocator.allocate_gsi_legacy(0), Ok(vec![]));
            // We cannot allocate more GSIs than available
            assert_eq!(
                allocator.allocate_gsi_legacy(GSI_LEGACY_NUM + 1),
                Err(vm_allocator::Error::ResourceNotAvailable)
            );
            // But allocating all of them at once should work
            assert_eq!(
                allocator.allocate_gsi_legacy(GSI_LEGACY_NUM),
                Ok((arch::GSI_LEGACY_START..=arch::GSI_LEGACY_END).collect::<Vec<_>>())
            );
            // And now we ran out of GSIs
            assert_eq!(
                allocator.allocate_gsi_legacy(1),
                Err(vm_allocator::Error::ResourceNotAvailable)
            );
            // But we should be able to ask for 0 GSIs
            assert_eq!(allocator.allocate_gsi_legacy(0), Ok(vec![]));

            let mut allocator = ResourceAllocator::new();
            // We should be able to allocate 1 GSI
            assert_eq!(
                allocator.allocate_gsi_legacy(1),
                Ok(vec![arch::GSI_LEGACY_START])
            );
            // We can't allocate MAX_IRQS any more
            assert_eq!(
                allocator.allocate_gsi_legacy(GSI_LEGACY_NUM),
                Err(vm_allocator::Error::ResourceNotAvailable)
            );
            // We can allocate another one and it should be the second available
            assert_eq!(
                allocator.allocate_gsi_legacy(1),
                Ok(vec![arch::GSI_LEGACY_START + 1])
            );
            // Let's allocate the rest in a loop
            for i in arch::GSI_LEGACY_START + 2..=arch::GSI_LEGACY_END {
                assert_eq!(allocator.allocate_gsi_legacy(1), Ok(vec![i]));
            }
        }

        #[test]
        fn test_allocate_gsi() {
            let mut allocator = ResourceAllocator::new();
            // asking for 0 IRQs should return us an empty vector
            assert_eq!(allocator.allocate_gsi_msi(0), Ok(vec![]));
            // We cannot allocate more GSIs than available
            assert_eq!(
                allocator.allocate_gsi_msi(GSI_MSI_NUM + 1),
                Err(vm_allocator::Error::ResourceNotAvailable)
            );
            // But allocating all of them at once should work
            assert_eq!(
                allocator.allocate_gsi_msi(GSI_MSI_NUM),
                Ok((arch::GSI_MSI_START..=arch::GSI_MSI_END).collect::<Vec<_>>())
            );
            // And now we ran out of GSIs
            assert_eq!(
                allocator.allocate_gsi_msi(1),
                Err(vm_allocator::Error::ResourceNotAvailable)
            );
            // But we should be able to ask for 0 GSIs
            assert_eq!(allocator.allocate_gsi_msi(0), Ok(vec![]));

            let mut allocator = ResourceAllocator::new();
            // We should be able to allocate 1 GSI
            assert_eq!(allocator.allocate_gsi_msi(1), Ok(vec![arch::GSI_MSI_START]));
            // We can't allocate MAX_IRQS any more
            assert_eq!(
                allocator.allocate_gsi_msi(GSI_MSI_NUM),
                Err(vm_allocator::Error::ResourceNotAvailable)
            );
            // We can allocate another one and it should be the second available
            assert_eq!(
                allocator.allocate_gsi_msi(1),
                Ok(vec![arch::GSI_MSI_START + 1])
            );
            // Let's allocate the rest in a loop
            for i in arch::GSI_MSI_START + 2..=arch::GSI_MSI_END {
                assert_eq!(allocator.allocate_gsi_msi(1), Ok(vec![i]));
            }
        }

        #[test]
        fn test_persist_omits_msi_gsi_allocator() {
            let mut allocator = ResourceAllocator::new();

            let legacy_gsi = allocator.allocate_gsi_legacy(1).unwrap()[0];
            let msi_gsi = allocator.allocate_gsi_msi(1).unwrap()[0];
            let mmio_range = allocator
                .mmio32_memory
                .allocate(1024, 1024, AllocPolicy::FirstMatch)
                .unwrap();

            let state = allocator.save();
            let mut restored = ResourceAllocator::restore((), &state).unwrap();

            // Legacy GSIs and MMIO ranges are serialized, so their allocations survive restore.
            assert_eq!(restored.allocate_gsi_legacy(1).unwrap()[0], legacy_gsi + 1);
            restored
                .mmio32_memory
                .allocate(1024, 1024, AllocPolicy::ExactMatch(mmio_range.start()))
                .unwrap_err();

            // MSI GSIs are intentionally omitted from ResourceAllocatorState and replayed by the
            // restored PCI devices, so the allocator starts empty after restore.
            assert_eq!(restored.allocate_gsi_msi(1).unwrap()[0], msi_gsi);
        }
    }

    mod id_allocator {

        use super::super::IdAllocator;
        use vm_allocator::Error;

        #[test]
        fn test_slot_id_allocation() {
            let faulty_allocator = IdAllocator::new(23, 5);
            assert_eq!(faulty_allocator.unwrap_err(), Error::InvalidRange(23, 5));
            let mut legacy_irq_allocator = IdAllocator::new(5, 23).unwrap();
            assert_eq!(legacy_irq_allocator.range_base, 5);
            assert_eq!(legacy_irq_allocator.allocated.len(), 19);

            let id = legacy_irq_allocator.allocate_id().unwrap();
            assert_eq!(id, 5);
            assert!(legacy_irq_allocator.is_allocated(id));
            assert_eq!(legacy_irq_allocator.allocate_id().unwrap(), 6);

            for _ in 2..19 {
                legacy_irq_allocator.allocate_id().unwrap();
            }

            assert_eq!(
                legacy_irq_allocator.allocate_id().unwrap_err(),
                Error::ResourceNotAvailable
            );
        }

        #[test]
        fn test_u32_max_exhaustion() {
            let mut allocator = IdAllocator::new(u32::MAX - 1, u32::MAX).unwrap();
            assert_eq!(allocator.allocate_id().unwrap(), u32::MAX - 1);
            assert_eq!(allocator.allocate_id().unwrap(), u32::MAX);
            let res = allocator.allocate_id();
            assert_eq!(res.unwrap_err(), Error::ResourceNotAvailable);
        }

        #[test]
        fn test_slot_id_free() {
            let mut legacy_irq_allocator = IdAllocator::new(5, 23).unwrap();
            assert_eq!(
                legacy_irq_allocator.free_id(3).unwrap_err(),
                Error::OutOfRange(3)
            );

            for _ in 1..10 {
                let _id = legacy_irq_allocator.allocate_id().unwrap();
            }

            let irq = 10;
            legacy_irq_allocator.free_id(irq).unwrap();
            assert!(!legacy_irq_allocator.is_allocated(irq));
            assert_eq!(
                legacy_irq_allocator.free_id(10).unwrap_err(),
                Error::NeverAllocated(10)
            );
            let irq = 9;
            legacy_irq_allocator.free_id(irq).unwrap();
            assert!(!legacy_irq_allocator.is_allocated(irq));

            let irq = legacy_irq_allocator.allocate_id().unwrap();
            assert_eq!(irq, 9);
            assert!(legacy_irq_allocator.is_allocated(irq));
            assert!(!legacy_irq_allocator.is_allocated(10));
            assert_eq!(
                legacy_irq_allocator.free_id(21).unwrap_err(),
                Error::NeverAllocated(21)
            );
        }

        #[test]
        fn test_free_id_never_allocated_boundary() {
            let mut allocator = IdAllocator::new(5, 23).unwrap();

            assert_eq!(allocator.free_id(5).unwrap_err(), Error::NeverAllocated(5));

            for _ in 0..3 {
                allocator.allocate_id().unwrap();
            }
            assert!(allocator.is_allocated(7));
            assert!(!allocator.is_allocated(8));
            assert_eq!(allocator.free_id(8).unwrap_err(), Error::NeverAllocated(8));
        }

        #[test]
        fn test_is_allocated() {
            let mut allocator = IdAllocator::new(5, 23).unwrap();

            assert!(!allocator.is_allocated(4));
            assert!(!allocator.is_allocated(24));

            assert!(!allocator.is_allocated(10));

            let id = allocator.allocate_id().unwrap();
            assert_eq!(id, 5);
            assert!(allocator.is_allocated(5));
            assert!(!allocator.is_allocated(6));

            allocator.free_id(5).unwrap();
            assert!(!allocator.is_allocated(5));

            let id = allocator.allocate_id().unwrap();
            assert_eq!(id, 5);
            assert!(allocator.is_allocated(5));
        }

        #[test]
        fn test_is_allocated_full_range() {
            let mut allocator = IdAllocator::new(u32::MAX - 1, u32::MAX).unwrap();

            assert!(!allocator.is_allocated(u32::MAX - 1));
            assert!(!allocator.is_allocated(u32::MAX));

            assert_eq!(allocator.allocate_id().unwrap(), u32::MAX - 1);
            assert!(allocator.is_allocated(u32::MAX - 1));
            assert!(!allocator.is_allocated(u32::MAX));

            assert_eq!(allocator.allocate_id().unwrap(), u32::MAX);
            assert!(allocator.is_allocated(u32::MAX));

            allocator.free_id(u32::MAX).unwrap();
            assert!(!allocator.is_allocated(u32::MAX));
            assert!(allocator.is_allocated(u32::MAX - 1));
        }

        #[test]
        fn test_is_allocated_with_freed() {
            let mut allocator = IdAllocator::new(5, 23).unwrap();
            allocator.allocate_id().unwrap();
            allocator.allocate_id().unwrap();

            assert!(allocator.is_allocated(6));
            assert!(!allocator.is_allocated(7));

            allocator.free_id(5).unwrap();
            assert!(!allocator.is_allocated(5));
            assert!(allocator.is_allocated(6));
            assert!(!allocator.is_allocated(7));
        }

        #[test]
        fn test_allocate_id_at() {
            let mut allocator = IdAllocator::new(5, 8).unwrap();

            assert_eq!(allocator.allocate_id_at(7).unwrap(), 7);
            assert!(allocator.is_allocated(7));
            assert_eq!(
                allocator.allocate_id_at(7).unwrap_err(),
                Error::ResourceNotAvailable
            );
            assert_eq!(
                allocator.allocate_id_at(4).unwrap_err(),
                Error::OutOfRange(4)
            );
            assert_eq!(
                allocator.allocate_id_at(9).unwrap_err(),
                Error::OutOfRange(9)
            );
            assert_eq!(allocator.allocate_id().unwrap(), 5);
            assert_eq!(allocator.allocate_id().unwrap(), 6);
            assert_eq!(allocator.allocate_id().unwrap(), 8);
            assert_eq!(
                allocator.allocate_id().unwrap_err(),
                Error::ResourceNotAvailable
            );
        }

        #[test]
        fn test_out_of_range_checks() {
            let legacy_irq_allocator = IdAllocator::new(5, 23).unwrap();

            assert!(!legacy_irq_allocator.is_allocated(4));
            assert!(!legacy_irq_allocator.is_allocated(25));
        }
    }
}
