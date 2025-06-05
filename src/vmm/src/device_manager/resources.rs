// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use pci::DeviceRelocation;
use serde::{Deserialize, Serialize};
pub use vm_allocator::AllocPolicy;
use vm_allocator::{AddressAllocator, IdAllocator};
use vm_device::Bus;

use crate::arch;
use crate::snapshot::Persist;

/// A resource manager for (de)allocating interrupt lines (GSIs) and guest memory
///
/// At the moment, we support:
///
/// * GSIs for legacy x86_64 devices
/// * GSIs for MMIO devicecs
/// * Memory allocations in the MMIO address space
#[derive(Debug)]
pub struct ResourceAllocator {
    // Allocator for device interrupt lines
    pub gsi_allocator: Arc<Mutex<IdAllocator>>,
    // Allocator for memory in the 32-bit MMIO address space
    pub mmio32_memory: Arc<Mutex<AddressAllocator>>,
    // Allocator for memory in the 64-bit MMIO address space
    pub mmio64_memory: Arc<Mutex<AddressAllocator>>,
    // Memory allocator for system data
    pub system_memory: Arc<Mutex<AddressAllocator>>,
    /// MMIO bus
    pub mmio_bus: Arc<vm_device::Bus>,
    #[cfg(target_arch = "x86_64")]
    /// Port IO bus
    pub pio_bus: Arc<vm_device::Bus>,
}

impl ResourceAllocator {
    /// Create a new resource allocator for Firecracker devices
    pub fn new() -> Result<Self, vm_allocator::Error> {
        Ok(Self {
            gsi_allocator: Arc::new(Mutex::new(IdAllocator::new(arch::GSI_BASE, arch::GSI_MAX)?)),
            mmio32_memory: Arc::new(Mutex::new(AddressAllocator::new(
                arch::MEM_32BIT_DEVICES_START,
                arch::MEM_32BIT_DEVICES_SIZE,
            )?)),
            mmio64_memory: Arc::new(Mutex::new(AddressAllocator::new(
                arch::MEM_64BIT_DEVICES_START,
                arch::MEM_64BIT_DEVICES_SIZE,
            )?)),
            system_memory: Arc::new(Mutex::new(AddressAllocator::new(
                arch::SYSTEM_MEM_START,
                arch::SYSTEM_MEM_SIZE,
            )?)),
            mmio_bus: Arc::new(Bus::new()),
            #[cfg(target_arch = "x86_64")]
            pio_bus: Arc::new(Bus::new()),
        })
    }

    /// Allocate a number of GSIs
    ///
    /// # Arguments
    ///
    /// * `gsi_count` - The number of GSIs to allocate
    pub fn allocate_gsi(&self, gsi_count: u32) -> Result<Vec<u32>, vm_allocator::Error> {
        let mut gsi_allocator = self.gsi_allocator.lock().expect("Poisoned lock");
        let mut gsis = Vec::with_capacity(gsi_count as usize);

        for _ in 0..gsi_count {
            match gsi_allocator.allocate_id() {
                Ok(gsi) => gsis.push(gsi),
                Err(err) => {
                    // It is ok to unwrap here, we just allocated the GSI
                    gsis.into_iter().for_each(|gsi| {
                        gsi_allocator.free_id(gsi).unwrap();
                    });
                    return Err(err);
                }
            }
        }

        Ok(gsis)
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
        &self,
        size: u64,
        alignment: u64,
        policy: AllocPolicy,
    ) -> Result<u64, vm_allocator::Error> {
        Ok(self
            .mmio32_memory
            .lock()
            .expect("Poisoned lock")
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
        &self,
        size: u64,
        alignment: u64,
        policy: AllocPolicy,
    ) -> Result<u64, vm_allocator::Error> {
        Ok(self
            .mmio64_memory
            .lock()
            .expect("Poisoned lock")
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
        &self,
        size: u64,
        alignment: u64,
        policy: AllocPolicy,
    ) -> Result<u64, vm_allocator::Error> {
        Ok(self
            .system_memory
            .lock()
            .expect("Poisoned lock")
            .allocate(size, alignment, policy)?
            .start())
    }
}

impl<'a> Persist<'a> for ResourceAllocator {
    type State = ResourceAllocatorState;
    type ConstructorArgs = ();
    type Error = Infallible;

    fn save(&self) -> Self::State {
        ResourceAllocatorState {
            gsi_allocator: self.gsi_allocator.clone(),
            mmio32_memory: self.mmio32_memory.clone(),
            mmio64_memory: self.mmio64_memory.clone(),
            system_memory: self.system_memory.clone(),
        }
    }

    fn restore(
        _constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        Ok(ResourceAllocator {
            gsi_allocator: state.gsi_allocator.clone(),
            mmio32_memory: state.mmio32_memory.clone(),
            mmio64_memory: state.mmio64_memory.clone(),
            system_memory: state.system_memory.clone(),
            mmio_bus: Arc::new(Bus::new()),
            #[cfg(target_arch = "x86_64")]
            pio_bus: Arc::new(Bus::new()),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocatorState {
    // Allocator for device interrupt lines
    pub gsi_allocator: Arc<Mutex<IdAllocator>>,
    // Allocator for memory in the 32-bit MMIO address space
    pub mmio32_memory: Arc<Mutex<AddressAllocator>>,
    // Allocator for memory in the 64-bit MMIO address space
    pub mmio64_memory: Arc<Mutex<AddressAllocator>>,
    // Memory allocator for system data
    pub system_memory: Arc<Mutex<AddressAllocator>>,
}

impl Default for ResourceAllocatorState {
    fn default() -> Self {
        Self {
            gsi_allocator: Arc::new(Mutex::new(
                IdAllocator::new(arch::IRQ_BASE, arch::IRQ_MAX).unwrap(),
            )),
            mmio32_memory: Arc::new(Mutex::new(
                AddressAllocator::new(arch::MEM_32BIT_DEVICES_START, arch::MEM_32BIT_DEVICES_SIZE)
                    .unwrap(),
            )),
            mmio64_memory: Arc::new(Mutex::new(
                AddressAllocator::new(arch::MEM_64BIT_DEVICES_START, arch::MEM_64BIT_DEVICES_SIZE)
                    .unwrap(),
            )),
            system_memory: Arc::new(Mutex::new(
                AddressAllocator::new(arch::SYSTEM_MEM_START, arch::SYSTEM_MEM_SIZE).unwrap(),
            )),
        }
    }
}

impl DeviceRelocation for ResourceAllocator {
    fn move_bar(
        &self,
        _old_base: u64,
        _new_base: u64,
        _len: u64,
        _pci_dev: &mut dyn pci::PciDevice,
        _region_type: pci::PciBarRegionType,
    ) -> Result<(), std::io::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use vm_allocator::AllocPolicy;

    use super::{ResourceAllocator, ResourceAllocatorState};
    use crate::arch::{self, GSI_BASE};
    use crate::snapshot::{Persist, Snapshot};

    const MAX_IRQS: u32 = arch::GSI_MAX - arch::GSI_BASE + 1;

    #[test]
    fn test_allocate_gsi() {
        let allocator = ResourceAllocator::new().unwrap();
        // asking for 0 IRQs should return us an empty vector
        assert_eq!(allocator.allocate_gsi(0), Ok(vec![]));
        // We cannot allocate more GSIs than available
        assert_eq!(
            allocator.allocate_gsi(MAX_IRQS + 1),
            Err(vm_allocator::Error::ResourceNotAvailable)
        );
        // But allocating all of them at once should work
        assert_eq!(
            allocator.allocate_gsi(MAX_IRQS),
            Ok((arch::GSI_BASE..=arch::GSI_MAX).collect::<Vec<_>>())
        );
        // And now we ran out of GSIs
        assert_eq!(
            allocator.allocate_gsi(1),
            Err(vm_allocator::Error::ResourceNotAvailable)
        );
        // But we should be able to ask for 0 GSIs
        assert_eq!(allocator.allocate_gsi(0), Ok(vec![]));

        let allocator = ResourceAllocator::new().unwrap();
        // We should be able to allocate 1 GSI
        assert_eq!(allocator.allocate_gsi(1), Ok(vec![arch::GSI_BASE]));
        // We can't allocate MAX_IRQS any more
        assert_eq!(
            allocator.allocate_gsi(MAX_IRQS),
            Err(vm_allocator::Error::ResourceNotAvailable)
        );
        // We can allocate another one and it should be the second available
        assert_eq!(allocator.allocate_gsi(1), Ok(vec![arch::GSI_BASE + 1]));
        // Let's allocate the rest in a loop
        for i in arch::GSI_BASE + 2..=arch::GSI_MAX {
            assert_eq!(allocator.allocate_gsi(1), Ok(vec![i]));
        }
    }

    fn clone_allocator(allocator: &ResourceAllocator) -> ResourceAllocator {
        let mut buf = vec![0u8; 1024];
        Snapshot::serialize(&mut buf.as_mut_slice(), &allocator.save()).unwrap();
        let restored_state: ResourceAllocatorState =
            Snapshot::deserialize(&mut buf.as_slice()).unwrap();
        ResourceAllocator::restore((), &restored_state).unwrap()
    }

    #[test]
    fn test_save_restore() {
        let allocator0 = ResourceAllocator::new().unwrap();
        let gsi_0 = allocator0.allocate_gsi(1).unwrap()[0];
        assert_eq!(gsi_0, GSI_BASE);

        let allocator1 = clone_allocator(&allocator0);
        let gsi_1 = allocator1.allocate_gsi(1).unwrap()[0];
        assert_eq!(gsi_1, GSI_BASE + 1);
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

        let allocator2 = clone_allocator(&allocator1);
        allocator2
            .allocate_32bit_mmio_memory(0x42, 1, AllocPolicy::ExactMatch(mmio32_mem))
            .unwrap_err();
        allocator2
            .allocate_64bit_mmio_memory(0x42, 1, AllocPolicy::ExactMatch(mmio64_mem))
            .unwrap_err();
        allocator2
            .allocate_system_memory(0x42, 1, AllocPolicy::ExactMatch(system_mem))
            .unwrap_err();

        let gsi_2 = allocator2.allocate_gsi(1).unwrap()[0];
        assert_eq!(gsi_2, GSI_BASE + 2);
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
