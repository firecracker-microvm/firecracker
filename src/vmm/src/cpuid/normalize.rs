// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bit_fields::CheckedAssignError;

use crate::cpuid::{CpuidEntry, CpuidKey, CpuidRegisters, CpuidTrait, KvmCpuidFlags};

/// Error type for [`Cpuid::normalize`].
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NormalizeCpuidError {
    /// Provided `cpu_bits` is >=8.
    #[error("Provided `cpu_bits` is >=8: {0}.")]
    CpuBits(u8),
    /// Failed to apply modifications to Intel CPUID.
    #[error("Failed to apply modifications to Intel CPUID: {0}")]
    Intel(#[from] crate::cpuid::intel::NormalizeCpuidError),
    /// Failed to apply modifications to AMD CPUID.
    #[error("Failed to apply modifications to AMD CPUID: {0}")]
    Amd(#[from] crate::cpuid::amd::NormalizeCpuidError),
    /// Failed to set feature information leaf.
    #[error("Failed to set feature information leaf: {0}")]
    FeatureInformation(#[from] FeatureInformationError),
    /// Failed to set extended topology leaf.
    #[error("Failed to set extended topology leaf: {0}")]
    ExtendedTopology(#[from] ExtendedTopologyError),
}

/// Error type for setting leaf 1 section of `IntelCpuid::normalize`.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FeatureInformationError {
    /// Leaf 0x1 is missing from CPUID.
    #[error("Leaf 0x1 is missing from CPUID.")]
    MissingLeaf1,
    /// Failed to set `Initial APIC ID`.
    #[error("Failed to set `Initial APIC ID`: {0}")]
    InitialApicId(CheckedAssignError),
    /// Failed to set `CLFLUSH line size`.
    #[error("Failed to set `CLFLUSH line size`: {0}")]
    Clflush(CheckedAssignError),
    /// Failed to get max CPUs per package.
    #[error("Failed to get max CPUs per package: {0}")]
    GetMaxCpusPerPackage(GetMaxCpusPerPackageError),
    /// Failed to set max CPUs per package.
    #[error("Failed to set max CPUs per package: {0}")]
    SetMaxCpusPerPackage(CheckedAssignError),
}

/// Error type for `get_max_cpus_per_package`.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GetMaxCpusPerPackageError {
    /// Failed to get max CPUs per package as `cpu_count == 0`.
    #[error("Failed to get max CPUs per package as `cpu_count == 0`")]
    Underflow,
    /// Failed to get max CPUs per package as `cpu_count > 128`.
    #[error("Failed to get max CPUs per package as `cpu_count > 128`")]
    Overflow,
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
impl super::Cpuid {
    /// Applies required modifications to CPUID respective of a vCPU.
    ///
    /// # Errors
    ///
    /// When:
    /// - [`IntelCpuid::normalize`] errors.
    /// - [`AmdCpuid::normalize`] errors.
    // As we pass through host frequency, we require CPUID and thus `cfg(cpuid)`.
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
        self.update_feature_info_entry(cpu_index, cpu_count)
            .map_err(NormalizeCpuidError::FeatureInformation)?;
        self.update_extended_topology_entry(cpu_index, cpu_count, cpu_bits, cpus_per_core)
            .map_err(NormalizeCpuidError::ExtendedTopology)?;

        // Apply manufacturer specific modifications.
        match self {
            // Apply Intel specific modifications.
            Self::Intel(intel_cpuid) => intel_cpuid
                .normalize(cpu_index, cpu_count, cpus_per_core)
                .map_err(NormalizeCpuidError::Intel),
            // Apply AMD specific modifications.
            Self::Amd(amd_cpuid) => amd_cpuid
                .normalize(cpu_index, cpu_count, cpus_per_core)
                .map_err(NormalizeCpuidError::Amd),
        }
    }

    // Update feature information entry
    fn update_feature_info_entry(
        &mut self,
        cpu_index: u8,
        cpu_count: u8,
    ) -> Result<(), FeatureInformationError> {
        /// Flush a cache line size.
        const EBX_CLFLUSH_CACHELINE: u32 = 8;

        /// CPU is running on a hypervisor.
        pub const HYPERVISOR_BITINDEX: u8 = 31;

        let leaf_1 = self
            .leaf_mut::<0x1>()
            .ok_or(FeatureInformationError::MissingLeaf1)?;

        // X86 hypervisor feature
        leaf_1.ecx.tsc_deadline_mut().on();
        // Hypervisor bit
        leaf_1.ecx.bit_mut::<HYPERVISOR_BITINDEX>().on();

        leaf_1
            .ebx
            .initial_apic_id_mut()
            .checked_assign(u32::from(cpu_index))
            .map_err(FeatureInformationError::InitialApicId)?;
        leaf_1
            .ebx
            .clflush_mut()
            .checked_assign(EBX_CLFLUSH_CACHELINE)
            .map_err(FeatureInformationError::Clflush)?;
        let max_cpus_per_package = u32::from(
            get_max_cpus_per_package(cpu_count)
                .map_err(FeatureInformationError::GetMaxCpusPerPackage)?,
        );
        leaf_1
            .ebx
            .max_addressable_logical_processor_ids_mut()
            .checked_assign(max_cpus_per_package)
            .map_err(FeatureInformationError::SetMaxCpusPerPackage)?;

        // A value of 1 for HTT indicates the value in CPUID.1.EBX[23:16]
        // (the Maximum number of addressable IDs for logical processors in this package)
        // is valid for the package
        leaf_1.edx.htt_mut().set(cpu_count > 1);

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

        // The following commit changed the behavior of KVM_GET_SUPPORTED_CPUID to no longer
        // include leaf 0xB / sub-leaf 1.
        // https://lore.kernel.org/all/20221027092036.2698180-1-pbonzini@redhat.com/
        self.inner_mut()
            .entry(CpuidKey::subleaf(0xB, 0x1))
            .or_insert(CpuidEntry {
                flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            });

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
}

/// The maximum number of logical processors per package is computed as the closest
/// power of 2 higher or equal to the CPU count configured by the user.
const fn get_max_cpus_per_package(cpu_count: u8) -> Result<u8, GetMaxCpusPerPackageError> {
    // This match is better than but approximately equivalent to
    // `2.pow((cpu_count as f32).log2().ceil() as u8)` (`2^ceil(log_2(c))`).
    match cpu_count {
        0 => Err(GetMaxCpusPerPackageError::Underflow),
        // `0u8.checked_next_power_of_two()` returns `Some(1)`, this is not the desired behaviour so
        // we use `next_power_of_two()` instead.
        1..=128 => Ok(cpu_count.next_power_of_two()),
        129..=u8::MAX => Err(GetMaxCpusPerPackageError::Overflow),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_max_cpus_per_package_test() {
        assert_eq!(
            get_max_cpus_per_package(0),
            Err(GetMaxCpusPerPackageError::Underflow)
        );
        assert_eq!(get_max_cpus_per_package(1), Ok(1));
        assert_eq!(get_max_cpus_per_package(2), Ok(2));
        assert_eq!(get_max_cpus_per_package(3), Ok(4));
        assert_eq!(get_max_cpus_per_package(4), Ok(4));
        assert_eq!(get_max_cpus_per_package(5), Ok(8));
        assert_eq!(get_max_cpus_per_package(8), Ok(8));
        assert_eq!(get_max_cpus_per_package(9), Ok(16));
        assert_eq!(get_max_cpus_per_package(16), Ok(16));
        assert_eq!(get_max_cpus_per_package(17), Ok(32));
        assert_eq!(get_max_cpus_per_package(32), Ok(32));
        assert_eq!(get_max_cpus_per_package(33), Ok(64));
        assert_eq!(get_max_cpus_per_package(64), Ok(64));
        assert_eq!(get_max_cpus_per_package(65), Ok(128));
        assert_eq!(get_max_cpus_per_package(128), Ok(128));
        assert_eq!(
            get_max_cpus_per_package(129),
            Err(GetMaxCpusPerPackageError::Overflow)
        );
        assert_eq!(
            get_max_cpus_per_package(u8::MAX),
            Err(GetMaxCpusPerPackageError::Overflow)
        );
    }
}
