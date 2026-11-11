// Copyright 2026 CoreWeave, Inc.
// SPDX-License-Identifier: Apache-2.0

//! PCI MMIO64 configuration.

use serde::{Deserialize, Serialize};

use crate::arch::{MMIO64_MEM_SIZE, MMIO64_MEM_START, PAST_64BITS_MMIO_SIZE};
use crate::vstate::resources::ResourceAllocatorState;

const GIB: u64 = 1 << 30;

/// PCI MMIO64 configuration errors.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum PciMmio64Error {
    /// PCI MMIO64 base must be at least 4 GiB, size must be nonzero, and the aperture and following memory pool must fit in 52 address bits.
    InvalidRange,
    /// PCI MMIO64 aperture, following memory pool, or guest RAM exceed the supported physical address width.
    AddressWidth,
}

/// Preboot PCI MMIO64 aperture in GiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PciMmio64Config {
    /// Guest physical base (GiB).
    pub base_gib: u64,
    /// Aperture size (GiB).
    pub size_gib: u64,
}

impl PciMmio64Config {
    /// Validate range and pool bounds.
    pub fn validate(self) -> Result<(), PciMmio64Error> {
        let end = self
            .base_gib
            .checked_add(self.size_gib)
            .and_then(|end| end.checked_mul(GIB))
            .and_then(|end| end.checked_add(PAST_64BITS_MMIO_SIZE));
        if self.base_gib < 4 || self.size_gib == 0 || end.is_none_or(|end| end > 1 << 52) {
            return Err(PciMmio64Error::InvalidRange);
        }
        Ok(())
    }

    /// Base in bytes after validation.
    pub fn base(self) -> u64 {
        self.base_gib * GIB
    }

    /// Size in bytes after validation.
    pub fn size(self) -> u64 {
        self.size_gib * GIB
    }

    /// Check aperture and pool address bounds.
    pub fn validate_address_width(self, bits: u32) -> Result<(), PciMmio64Error> {
        self.validate()?;
        let limit = 1u64.checked_shl(bits).ok_or(PciMmio64Error::AddressWidth)?;
        if self.base() + self.size() + PAST_64BITS_MMIO_SIZE > limit {
            return Err(PciMmio64Error::AddressWidth);
        }
        Ok(())
    }

    /// Check aperture, pool and RAM address bounds.
    pub fn validate_memory_layout(
        self,
        bits: u32,
        mem_size_mib: usize,
    ) -> Result<(), PciMmio64Error> {
        self.validate_address_width(bits)?;
        let ram_size = mem_size_mib
            .checked_mul(1 << 20)
            .filter(|size| *size > 0)
            .ok_or(PciMmio64Error::AddressWidth)?;
        let limit = 1u64.checked_shl(bits).ok_or(PciMmio64Error::AddressWidth)?;
        let regions =
            crate::arch::arch_memory_regions_with_mmio64(ram_size, self.base(), self.size())
                .map_err(|_| PciMmio64Error::AddressWidth)?;
        if regions
            .iter()
            .any(|(base, size)| base.0 + *size as u64 > limit)
        {
            return Err(PciMmio64Error::AddressWidth);
        }
        Ok(())
    }

    /// Recover the aperture from existing snapshot allocator bounds.
    pub fn from_allocator(
        allocator: &ResourceAllocatorState,
    ) -> Result<Option<Self>, PciMmio64Error> {
        let base = allocator.mmio64_memory.base();
        let size = allocator
            .mmio64_memory
            .end()
            .checked_sub(base)
            .and_then(|size| size.checked_add(1))
            .ok_or(PciMmio64Error::InvalidRange)?;
        if base == MMIO64_MEM_START && size == MMIO64_MEM_SIZE {
            return Ok(None);
        }
        if !base.is_multiple_of(GIB) || !size.is_multiple_of(GIB) {
            return Err(PciMmio64Error::InvalidRange);
        }
        let config = Self {
            base_gib: base / GIB,
            size_gib: size / GIB,
        };
        config.validate()?;
        if allocator.past_mmio64_memory.base() != base + size
            || allocator.past_mmio64_memory.end() != base + size + PAST_64BITS_MMIO_SIZE - 1
        {
            return Err(PciMmio64Error::InvalidRange);
        }
        Ok(Some(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Persist;
    use crate::vstate::resources::ResourceAllocator;

    #[test]
    fn test_pci_mmio64_validation() {
        let config = PciMmio64Config {
            base_gib: 2048,
            size_gib: 2048,
        };
        config.validate().unwrap();
        config.validate_address_width(42).unwrap_err();
        config.validate_address_width(43).unwrap();
        config.validate_memory_layout(43, 4096).unwrap();
        config.validate_memory_layout(43, 0).unwrap_err();
        config.validate_memory_layout(43, usize::MAX).unwrap_err();
        PciMmio64Config {
            base_gib: 4,
            size_gib: 2,
        }
        .validate_memory_layout(40, (1 << 20) - 1024)
        .unwrap_err();
        assert_eq!(config.base(), 2 << 40);
        assert_eq!(config.size(), 2 << 40);
        for (base_gib, size_gib) in [
            (0, 1),
            (3, 1),
            (4, 0),
            (u64::MAX, 1),
            (4, u64::MAX),
            (1 << 22, 1),
        ] {
            PciMmio64Config { base_gib, size_gib }
                .validate()
                .unwrap_err();
        }
        // Only individual BARs require power-of-two alignment.
        PciMmio64Config {
            base_gib: 5,
            size_gib: 3,
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn test_pci_mmio64_snapshot_layout() {
        assert_eq!(
            PciMmio64Config::from_allocator(&ResourceAllocator::new().save()).unwrap(),
            None
        );
        let config = PciMmio64Config {
            base_gib: 2048,
            size_gib: 2048,
        };
        let allocator = ResourceAllocator::with_mmio64_range(config.base(), config.size()).unwrap();
        let state = allocator.save();
        let bytes = bitcode::serialize(&state).unwrap();
        let restored: ResourceAllocatorState = bitcode::deserialize(&bytes).unwrap();
        assert_eq!(
            PciMmio64Config::from_allocator(&restored).unwrap(),
            Some(config)
        );
        let mut invalid = restored;
        invalid.past_mmio64_memory = ResourceAllocator::new().past_mmio64_memory;
        PciMmio64Config::from_allocator(&invalid).unwrap_err();
    }

    #[test]
    fn test_pci_mmio64_ram_does_not_overlap_pmem_pool() {
        let config = PciMmio64Config {
            base_gib: 4,
            size_gib: 2,
        };
        let mut allocator =
            ResourceAllocator::with_mmio64_range(config.base(), config.size()).unwrap();
        let regions = crate::arch::arch_memory_regions_with_mmio64(
            8usize << 30,
            config.base(),
            config.size(),
        )
        .unwrap();
        allocator.reserve_past_mmio64_ram(regions).unwrap();
        let allocation = allocator
            .past_mmio64_memory
            .allocate(1 << 30, 1 << 30, vm_allocator::AllocPolicy::FirstMatch)
            .unwrap();
        // Account for each architecture's low RAM gap.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(allocation.start(), 11 << 30);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(allocation.start(), 12 << 30);
    }
}
