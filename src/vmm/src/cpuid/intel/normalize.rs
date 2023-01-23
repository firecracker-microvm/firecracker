// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use bit_fields::CheckedAssignError;

use super::registers;
use crate::cpuid::intel::DefaultBrandStringError;
use crate::cpuid::{CpuidTrait, MissingBrandStringLeaves};

/// Error type for [`IntelCpuid::normalize`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NormalizeCpuidError {
    /// Failed to set deterministic cache leaf.
    #[error("Failed to set deterministic cache leaf: {0}")]
    DeterministicCache(#[from] DeterministicCacheError),
    /// Leaf 0x6 is missing from CPUID.
    #[error("Leaf 0x6 is missing from CPUID.")]
    MissingLeaf6,
    /// Leaf 0xA is missing from CPUID.
    #[error("Leaf 0xA is missing from CPUID.")]
    MissingLeafA,
    /// Failed to get brand string.
    #[error("Failed to get brand string: {0}")]
    GetBrandString(DefaultBrandStringError),
    /// Failed to set brand string.
    #[error("Failed to set brand string: {0}")]
    ApplyBrandString(MissingBrandStringLeaves),
}

/// Error type for setting leaf 4 section of `IntelCpuid::normalize`.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum DeterministicCacheError {
    /// Failed to set `Maximum number of addressable IDs for logical processors sharing this
    /// cache` due to underflow in cpu count.
    #[error(
        "Failed to set `Maximum number of addressable IDs for logical processors sharing this \
         cache` due to underflow in cpu count."
    )]
    MaxCpusPerCoreUnderflow,
    /// Failed to set `Maximum number of addressable IDs for logical processors sharing this
    /// cache`.
    #[error(
        "Failed to set `Maximum number of addressable IDs for logical processors sharing this \
         cache`: {0}"
    )]
    MaxCpusPerCore(CheckedAssignError),
    /// Failed to set `Maximum number of addressable IDs for processor cores in the physical
    /// package` due to underflow in cores
    #[error(
        "Failed to set `Maximum number of addressable IDs for processor cores in the physical \
         package` due to underflow in cores."
    )]
    MaxCorePerPackageUnderflow,
    /// Failed to set `Maximum number of addressable IDs for processor cores in the physical
    /// package`.
    #[error(
        "Failed to set `Maximum number of addressable IDs for processor cores in the physical \
         package`: {0}"
    )]
    MaxCorePerPackage(CheckedAssignError),
}

// We use this 2nd implementation so we can conveniently define functions only used within
// `normalize`.
#[allow(clippy::multiple_inherent_impl)]
impl super::IntelCpuid {
    /// Applies required modifications to CPUID respective of a vCPU.
    ///
    /// # Errors
    ///
    /// When attempting to access missing leaves or set fields within leaves to values that don't
    /// fit.
    #[inline]
    pub fn normalize(
        &mut self,
        // The index of the current logical CPU in the range [0..cpu_count].
        _cpu_index: u8,
        // The total number of logical CPUs.
        cpu_count: u8,
        // The number of logical CPUs per core.
        cpus_per_core: u8,
    ) -> Result<(), NormalizeCpuidError> {
        self.update_deterministic_cache_entry(cpu_count, cpus_per_core)?;
        self.update_power_management_entry()?;
        self.update_performance_monitoring_entry()?;
        self.update_brand_string_entry()?;

        Ok(())
    }

    /// Update deterministic cache entry
    fn update_deterministic_cache_entry(
        &mut self,
        cpu_count: u8,
        cpus_per_core: u8,
    ) -> Result<(), DeterministicCacheError> {
        let leaf_4 = self.leaf_mut::<0x4>();
        for subleaf in leaf_4.0 {
            match u32::from(&subleaf.eax.cache_level()) {
                // L1 & L2 Cache
                // The L1 & L2 cache is shared by at most 2 hyperthreads
                1 | 2 => subleaf
                    .eax
                    .max_num_addressable_ids_for_logical_processors_sharing_this_cache_mut()
                    // SAFETY: We know `cpus_per_core > 0` therefore this is always safe.
                    .checked_assign(u32::from(unsafe {
                        cpus_per_core.checked_sub(1).unwrap_unchecked()
                    }))
                    .map_err(DeterministicCacheError::MaxCpusPerCore)?,
                // L3 Cache
                // The L3 cache is shared among all the logical threads
                3 => subleaf
                    .eax
                    .max_num_addressable_ids_for_logical_processors_sharing_this_cache_mut()
                    .checked_assign(u32::from(
                        cpu_count
                            .checked_sub(1)
                            .ok_or(DeterministicCacheError::MaxCpusPerCoreUnderflow)?,
                    ))
                    .map_err(DeterministicCacheError::MaxCpusPerCore)?,
                _ => (),
            }
            // SAFETY: We know `cpus_per_core !=0` therefore this is always safe.
            let cores = unsafe { cpu_count.checked_div(cpus_per_core).unwrap_unchecked() };
            // Put all the cores in the same socket
            subleaf
                .eax
                .max_num_addressable_ids_for_processor_cores_in_physical_package_mut()
                .checked_assign(
                    u32::from(cores)
                        .checked_sub(1)
                        .ok_or(DeterministicCacheError::MaxCorePerPackageUnderflow)?,
                )
                .map_err(DeterministicCacheError::MaxCorePerPackage)?;
        }
        Ok(())
    }

    /// Update power management entry
    fn update_power_management_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        let leaf_6 = self
            .leaf_mut::<0x6>()
            .ok_or(NormalizeCpuidError::MissingLeaf6)?;
        leaf_6.eax.intel_turbo_boost_technology_mut().off();
        // Clear X86 EPB feature. No frequency selection in the hypervisor.
        leaf_6.ecx.performance_energy_bias_mut().off();
        Ok(())
    }

    /// Update performance monitoring entry
    fn update_performance_monitoring_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        let leaf_a = self
            .leaf_mut::<0xA>()
            .ok_or(NormalizeCpuidError::MissingLeafA)?;
        *leaf_a = super::leaves::LeafA::from((
            registers::LeafAEax::from(0),
            registers::LeafAEbx::from(0),
            registers::LeafAEcx::from(0),
            registers::LeafAEdx::from(0),
        ));
        Ok(())
    }

    /// Update brand string entry
    fn update_brand_string_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        let default_brand_string =
            Self::default_brand_string().map_err(NormalizeCpuidError::GetBrandString)?;

        self.apply_brand_string(&default_brand_string)
            .map_err(NormalizeCpuidError::ApplyBrandString)?;
        Ok(())
    }
}
