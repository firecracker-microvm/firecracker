// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;

use serde::{Deserialize, Serialize};
pub use vm_allocator::AllocPolicy;
use vm_allocator::{AddressAllocator, IdAllocator};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Allocate a memory range in 32-bit MMIO address space
    ///
    /// If it succeeds, it returns the first address of the allocated range
    ///
    /// # Arguments
    ///
    /// * `size` - The size in bytes of the memory to allocate
    /// * `alignment` - The alignment of the address of the first byte
    /// * `policy` - A [`vm_allocator::AllocPolicy`] variant for determining the allocation policy
    pub fn allocate_32bit_mmio_memory(
        &mut self,
        size: u64,
        alignment: u64,
        policy: AllocPolicy,
    ) -> Result<u64, vm_allocator::Error> {
        Ok(self
            .mmio32_memory
            .allocate(size, alignment, policy)?
            .start())
    }

    /// Allocate a memory range in 64-bit MMIO address space
    ///
    /// If it succeeds, it returns the first address of the allocated range
    ///
    /// # Arguments
    ///
    /// * `size` - The size in bytes of the memory to allocate
    /// * `alignment` - The alignment of the address of the first byte
    /// * `policy` - A [`vm_allocator::AllocPolicy`] variant for determining the allocation policy
    pub fn allocate_64bit_mmio_memory(
        &mut self,
        size: u64,
        alignment: u64,
        policy: AllocPolicy,
    ) -> Result<u64, vm_allocator::Error> {
        Ok(self
            .mmio64_memory
            .allocate(size, alignment, policy)?
            .start())
    }

    /// Allocate a memory range for system data
    ///
    /// If it succeeds, it returns the first address of the allocated range
    ///
    /// # Arguments
    ///
    /// * `size` - The size in bytes of the memory to allocate
    /// * `alignment` - The alignment of the address of the first byte
    /// * `policy` - A [`vm_allocator::AllocPolicy`] variant for determining the allocation policy
    pub fn allocate_system_memory(
        &mut self,
        size: u64,
        alignment: u64,
        policy: AllocPolicy,
    ) -> Result<u64, vm_allocator::Error> {
        Ok(self
            .system_memory
            .allocate(size, alignment, policy)?
            .start())
    }
}

impl<'a> Persist<'a> for ResourceAllocator {
    type State = ResourceAllocator;
    type ConstructorArgs = ();
    type Error = Infallible;

    fn save(&self) -> Self::State {
        self.clone()
    }

    fn restore(
        _constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        Ok(state.clone())
    }
}

#[cfg(test)]
mod tests {
    use vm_allocator::AllocPolicy;

    use super::ResourceAllocator;
    use crate::arch::{self, GSI_LEGACY_NUM, GSI_LEGACY_START, GSI_MSI_NUM, GSI_MSI_START};
    use crate::snapshot::{Persist, Snapshot};

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

    fn clone_allocator(allocator: &ResourceAllocator) -> ResourceAllocator {
        let mut buf = vec![0u8; 1024];
        Snapshot::new(allocator.save())
            .save(&mut buf.as_mut_slice())
            .unwrap();
        let restored_state: ResourceAllocator = Snapshot::load_without_crc_check(buf.as_slice())
            .unwrap()
            .data;
        ResourceAllocator::restore((), &restored_state).unwrap()
    }

    #[test]
    fn test_save_restore() {
        let mut allocator0 = ResourceAllocator::new();
        let irq_0 = allocator0.allocate_gsi_legacy(1).unwrap()[0];
        assert_eq!(irq_0, GSI_LEGACY_START);
        let gsi_0 = allocator0.allocate_gsi_msi(1).unwrap()[0];
        assert_eq!(gsi_0, GSI_MSI_START);

        let mut allocator1 = clone_allocator(&allocator0);
        let irq_1 = allocator1.allocate_gsi_legacy(1).unwrap()[0];
        assert_eq!(irq_1, GSI_LEGACY_START + 1);
        let gsi_1 = allocator1.allocate_gsi_msi(1).unwrap()[0];
        assert_eq!(gsi_1, GSI_MSI_START + 1);
        let mmio32_mem = allocator1
            .allocate_32bit_mmio_memory(0x42, 1, AllocPolicy::FirstMatch)
            .unwrap();
        assert_eq!(mmio32_mem, arch::MEM_32BIT_DEVICES_START);
        let mmio64_mem = allocator1
            .allocate_64bit_mmio_memory(0x42, 1, AllocPolicy::FirstMatch)
            .unwrap();
        assert_eq!(mmio64_mem, arch::MEM_64BIT_DEVICES_START);
        let system_mem = allocator1
            .allocate_system_memory(0x42, 1, AllocPolicy::FirstMatch)
            .unwrap();
        assert_eq!(system_mem, arch::SYSTEM_MEM_START);

        let mut allocator2 = clone_allocator(&allocator1);
        allocator2
            .allocate_32bit_mmio_memory(0x42, 1, AllocPolicy::ExactMatch(mmio32_mem))
            .unwrap_err();
        allocator2
            .allocate_64bit_mmio_memory(0x42, 1, AllocPolicy::ExactMatch(mmio64_mem))
            .unwrap_err();
        allocator2
            .allocate_system_memory(0x42, 1, AllocPolicy::ExactMatch(system_mem))
            .unwrap_err();

        let irq_2 = allocator2.allocate_gsi_legacy(1).unwrap()[0];
        assert_eq!(irq_2, GSI_LEGACY_START + 2);
        let gsi_2 = allocator2.allocate_gsi_msi(1).unwrap()[0];
        assert_eq!(gsi_2, GSI_MSI_START + 2);
        let mmio32_mem = allocator1
            .allocate_32bit_mmio_memory(0x42, 1, AllocPolicy::FirstMatch)
            .unwrap();
        assert_eq!(mmio32_mem, arch::MEM_32BIT_DEVICES_START + 0x42);
        let mmio64_mem = allocator1
            .allocate_64bit_mmio_memory(0x42, 1, AllocPolicy::FirstMatch)
            .unwrap();
        assert_eq!(mmio64_mem, arch::MEM_64BIT_DEVICES_START + 0x42);
        let system_mem = allocator1
            .allocate_system_memory(0x42, 1, AllocPolicy::FirstMatch)
            .unwrap();
        assert_eq!(system_mem, arch::SYSTEM_MEM_START + 0x42);
    }
}
