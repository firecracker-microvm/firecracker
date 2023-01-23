// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use bit_fields::CheckedAssignError;

use super::registers;
use crate::CpuidTrait;

/// Error type for [`IntelCpuid::normalize`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NormalizeCpuidError {
    /// Provided `cpu_bits` is >=8.
    #[error("Provided `cpu_bits` is >=8: {0}.")]
    CpuBits(u8),
    /// Failed to set deterministic cache leaf.
    #[error("Failed to set deterministic cache leaf: {0}")]
    DeterministicCache(#[from] DeterministicCacheError),
    /// Leaf 0x6 is missing from CPUID.
    #[error("Leaf 0x6 is missing from CPUID.")]
    MissingLeaf6,
    /// Leaf 0xA is missing from CPUID.
    #[error("Leaf 0xA is missing from CPUID.")]
    MissingLeafA,
    /// Failed to set extended topology leaf.
    #[error("Failed to set extended topology leaf: {0}")]
    ExtendedTopology(#[from] ExtendedTopologyError),
    /// Failed to get brand string.
    #[error("Failed to get brand string: {0}")]
    GetBrandString(super::DefaultBrandStringError),
    /// Failed to set brand string.
    #[error("Failed to set brand string: {0}")]
    ApplyBrandString(crate::MissingBrandStringLeaves),
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

/// Error type for setting leaf b section of `IntelCpuid::normalize`.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ExtendedTopologyError {
    /// Failed to set `Number of bits to shift right on x2APIC ID to get a unique topology ID of
    /// the next level type`.
    #[error(
        "Failed to set `Number of bits to shift right on x2APIC ID to get a unique topology ID of \
         the next level type`: {0}"
    )]
    ApicId(CheckedAssignError),
    /// Failed to set `Number of logical processors at this level type`.
    #[error("Failed to set `Number of logical processors at this level type`: {0}")]
    LogicalProcessors(CheckedAssignError),
    /// Failed to set `Level Type`.
    #[error("Failed to set `Level Type`: {0}")]
    LevelType(CheckedAssignError),
    /// Failed to set `Level Number`.
    #[error("Failed to set `Level Number`: {0}")]
    LevelNumber(CheckedAssignError),
    /// Failed to set all leaves, as more than `u32::MAX` sub-leaves are present.
    #[error("Failed to set all leaves, as more than `u32::MAX` sub-leaves are present: {0}")]
    Overflow(<u32 as TryFrom<usize>>::Error),
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
        cpu_index: u8,
        // The total number of logical CPUs.
        cpu_count: u8,
        // The number of bits needed to enumerate logical CPUs per core.
        cpu_bits: u8,
    ) -> Result<(), NormalizeCpuidError> {
        let cpus_per_core = 1u8
            .checked_shl(u32::from(cpu_bits))
            .ok_or(NormalizeCpuidError::CpuBits(cpu_bits))?;

        self.update_deterministic_cache_entry(cpu_count, cpus_per_core)?;
        self.update_power_management_entry()?;
        self.update_performance_monitoring_entry()?;
        self.update_extended_topology_entry(cpu_index, cpu_count, cpu_bits, cpus_per_core)?;
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

    /// Update extended topology entry
    fn update_extended_topology_entry(
        &mut self,
        cpu_index: u8,
        cpu_count: u8,
        cpu_bits: u8,
        cpus_per_core: u8,
    ) -> Result<(), ExtendedTopologyError> {
        /// Level type used for setting thread level processor topology.
        const LEVEL_TYPE_THREAD: u32 = 1;
        /// Level type used for setting core level processor topology.
        const LEVEL_TYPE_CORE: u32 = 2;
        /// The APIC ID shift in leaf 0xBh specifies the number of bits to shit the x2APIC ID to
        /// get a unique topology of the next level. This allows 128 logical
        /// processors/package.
        const LEAFBH_INDEX1_APICID: u32 = 7;

        let leaf_b = self.leaf_mut::<0xB>();
        for (index, subleaf) in leaf_b.0.into_iter().enumerate() {
            // reset eax, ebx, ecx
            subleaf.eax.0 = 0;
            subleaf.ebx.0 = 0;
            subleaf.ecx.0 = 0;
            // EDX bits 31..0 contain x2APIC ID of current logical processor
            // x2APIC increases the size of the APIC ID from 8 bits to 32 bits
            subleaf.edx.0 = u32::from(cpu_index);

            // "If SMT is not present in a processor implementation but CPUID leaf 0BH is
            // supported, CPUID.EAX=0BH, ECX=0 will return EAX = 0, EBX = 1 and
            // level type = 1. Number of logical processors at the core level is
            // reported at level type = 2." (Intel® 64 Architecture x2APIC
            // Specification, Ch. 2.8)
            match index {
                // Thread Level Topology; index = 0
                0 => {
                    // To get the next level APIC ID, shift right with at most 1 because we have
                    // maximum 2 hyperthreads per core that can be represented by 1 bit.
                    subleaf
                        .eax
                        .bit_shifts_right_2x_apic_id_unique_topology_id_mut()
                        .checked_assign(u32::from(cpu_bits))
                        .map_err(ExtendedTopologyError::ApicId)?;
                    // When cpu_count == 1 or HT is disabled, there is 1 logical core at this
                    // level Otherwise there are 2
                    subleaf
                        .ebx
                        .logical_processors_mut()
                        .checked_assign(u32::from(cpus_per_core))
                        .map_err(ExtendedTopologyError::LogicalProcessors)?;

                    subleaf
                        .ecx
                        .level_type_mut()
                        .checked_assign(LEVEL_TYPE_THREAD)
                        .map_err(ExtendedTopologyError::LevelType)?;
                }
                // Core Level Processor Topology; index = 1
                1 => {
                    subleaf
                        .eax
                        .bit_shifts_right_2x_apic_id_unique_topology_id_mut()
                        .checked_assign(LEAFBH_INDEX1_APICID)
                        .map_err(ExtendedTopologyError::ApicId)?;
                    subleaf
                        .ebx
                        .logical_processors_mut()
                        .checked_assign(u32::from(cpu_count))
                        .map_err(ExtendedTopologyError::LogicalProcessors)?;
                    // We expect here as this is an extremely rare case that is unlikely to ever
                    // occur. It would require manual editing of the CPUID structure to push
                    // more than 2^32 subleaves.
                    subleaf
                        .ecx
                        .level_number_mut()
                        .checked_assign(
                            u32::try_from(index).map_err(ExtendedTopologyError::Overflow)?,
                        )
                        .map_err(ExtendedTopologyError::LevelNumber)?;
                    subleaf
                        .ecx
                        .level_type_mut()
                        .checked_assign(LEVEL_TYPE_CORE)
                        .map_err(ExtendedTopologyError::LevelType)?;
                }
                // Core Level Processor Topology; index >=2
                // No other levels available; This should already be set correctly,
                // and it is added here as a "re-enforcement" in case we run on
                // different hardware
                _ => {
                    // We expect here as this is an extremely rare case that is unlikely to ever
                    // occur. It would require manual editing of the CPUID structure to push
                    // more than 2^32 subleaves.
                    subleaf.ecx.0 =
                        u32::try_from(index).map_err(ExtendedTopologyError::Overflow)?;
                }
            }
        }
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
