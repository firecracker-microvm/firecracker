// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub use vm_allocator::AllocPolicy;
use vm_allocator::{AddressAllocator, IdAllocator};

pub type Result<T> = std::result::Result<T, vm_allocator::Error>;

/// A manager type for handline guest VM GSIs and GuestMemory allocations for devices.
///
/// At the moment, we support:
///
/// * GSIs for legacy devices (for x86) by hardcoding the GSI that the PIC expects.
/// * GSIs for MMIO devices. We use GSIs not assigned to legacy devices (if any). These are
///   allocated dynamically at runtime.
/// * MMIO address range memory allocation
pub struct ResourceManager {
    gsi_allocator: IdAllocator,
    mmio_address_allocator: AddressAllocator,
}

impl ResourceManager {
    /// x86 global system interrupt for communication events on serial ports 1
    /// & 3. See
    /// <https://en.wikipedia.org/wiki/Interrupt_request_(PC_architecture)>.
    #[cfg(target_arch = "x86_64")]
    const COM_EVT_1_3_GSI: u32 = 4;
    /// x86 global system interrupt for communication events on serial ports 2
    /// & 4. See
    /// <https://en.wikipedia.org/wiki/Interrupt_request_(PC_architecture)>.
    #[cfg(target_arch = "x86_64")]
    const COM_EVT_2_4_GSI: u32 = 3;
    /// x86 global system interrupt for keyboard port.
    /// See <https://en.wikipedia.org/wiki/Interrupt_request_(PC_architecture)>.
    #[cfg(target_arch = "x86_64")]
    const KBD_EVT_GSI: u32 = 1;

    /// Create a new manager
    pub fn new() -> Result<Self> {
        Ok(Self {
            gsi_allocator: IdAllocator::new(arch::IRQ_BASE, arch::IRQ_MAX)?,
            mmio_address_allocator: AddressAllocator::new(
                arch::MMIO_MEM_START,
                arch::MMIO_MEM_SIZE,
            )?,
        })
    }

    #[cfg(target_arch = "x86_64")]
    /// Returns the GSI allocated for serial consoles 1 & 3
    pub fn serial_1_3_gsi() -> u32 {
        Self::COM_EVT_1_3_GSI
    }

    #[cfg(target_arch = "x86_64")]
    /// Returns the GSI allocated for serial consoles 2 & 4
    pub fn serial_2_4_gsi() -> u32 {
        Self::COM_EVT_2_4_GSI
    }

    #[cfg(target_arch = "x86_64")]
    /// Returns the GSI allocated for the i8042 device
    pub fn i8042_gsi() -> u32 {
        Self::KBD_EVT_GSI
    }

    /// Allocate a number of GSIs
    ///
    /// # Arguments
    ///
    /// * `gsi_count` - The number of GSIs to allocate
    pub fn allocate_gsi(&mut self, gsi_count: u32) -> Result<Vec<u32>> {
        let mut gsis = Vec::with_capacity(gsi_count as usize);

        for _ in 0..gsi_count {
            match self.gsi_allocator.allocate_id() {
                Ok(gsi) => gsis.push(gsi),
                Err(err) => {
                    for allocated in &gsis {
                        // It is ok to unwrap() here, because we just allocated it
                        self.gsi_allocator.free_id(*allocated).unwrap();
                    }
                    return Err(err);
                }
            }
        }

        Ok(gsis)
    }

    /// Allocate a memory range in MMIO address space
    ///
    /// If it succeeds, it returns the start address of the allocated range
    ///
    /// # Arguments
    ///
    /// * `size` - The size of memory to allocate
    /// * `alignment` - The desired alignment of the range's start address
    /// * `policy` - A [`vm_allocator::AllocPolicy`] variant for determining the allocation policy
    pub fn allocate_mmio_addresses(
        &mut self,
        size: u64,
        alignment: u64,
        policy: AllocPolicy,
    ) -> Result<u64> {
        Ok(self
            .mmio_address_allocator
            .allocate(size, alignment, policy)?
            .start())
    }
}

#[cfg(test)]
mod tests {
    use super::ResourceManager;

    #[test]
    fn test_allocate_gsi() {
        let mut resource_manager = ResourceManager::new().unwrap();

        assert!(resource_manager.allocate_gsi(0).unwrap().is_empty());

        let gsis = resource_manager.allocate_gsi(1).unwrap();
        assert_eq!(gsis, vec![arch::IRQ_BASE]);

        let gsis = resource_manager.allocate_gsi(2).unwrap();
        assert_eq!(gsis, vec![arch::IRQ_BASE + 1, arch::IRQ_BASE + 2]);

        let mut resource_manager = ResourceManager::new().unwrap();
        assert!(resource_manager
            .allocate_gsi(arch::IRQ_MAX - arch::IRQ_BASE + 2)
            .is_err());
        assert!(resource_manager
            .allocate_gsi(arch::IRQ_MAX - arch::IRQ_BASE + 1)
            .is_ok());
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_fixed_gsis() {
        assert_eq!(ResourceManager::serial_1_3_gsi(), 4);
        assert_eq!(ResourceManager::serial_2_4_gsi(), 3);
        assert_eq!(ResourceManager::i8042_gsi(), 1);
    }
}
