// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use bit_fields::CheckedAssignError;

use crate::CpuidTrait;

/// Error type for [`Cpuid::normalize`].
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NormalizeCpuidError {
    /// Failed to apply modifications to Intel CPUID.
    #[error("Failed to apply modifications to Intel CPUID: {0}")]
    Intel(#[from] crate::intel::NormalizeCpuidError),
    /// Failed to apply modifications to AMD CPUID.
    #[error("Failed to apply modifications to AMD CPUID: {0}")]
    Amd(#[from] crate::amd::NormalizeCpuidError),
    /// Failed to set feature information leaf.
    #[error("Failed to set feature information leaf: {0}")]
    FeatureInfomation(#[from] FeatureInformationError),
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
        // Update feature information entry
        {
            /// Flush a cache line size.
            const EBX_CLFLUSH_CACHELINE: u32 = 8;

            /// CPU is running on a hypervisor.
            pub const HYPERVISOR_BITINDEX: u8 = 31;

            /// The maximum number of logical processors per package is computed as the closest
            /// power of 2 higher or equal to the CPU count configured by the user.
            const fn get_max_cpus_per_package(
                cpu_count: u8,
            ) -> Result<u8, GetMaxCpusPerPackageError> {
                // This match is better than but approximately equivalent to
                // `2.pow((cpu_count as f32).log2().ceil() as u8)` (`2^ceil(log_2(c))`).
                match cpu_count {
                    0 => Err(GetMaxCpusPerPackageError::Underflow),
                    1 => Ok(1),
                    2 => Ok(2),
                    3..=4 => Ok(4),
                    5..=8 => Ok(8),
                    9..=16 => Ok(16),
                    17..=32 => Ok(32),
                    33..=64 => Ok(64),
                    65..=128 => Ok(128),
                    129..=u8::MAX => Err(GetMaxCpusPerPackageError::Overflow),
                }
            }

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
        }

        // Apply manufacturer specific modifications.
        match self {
            // Apply Intel specific modifications.
            Self::Intel(intel_cpuid) => intel_cpuid
                .normalize(cpu_index, cpu_count, cpu_bits)
                .map_err(NormalizeCpuidError::Intel),
            // Apply AMD specific modifications.
            Self::Amd(amd_cpuid) => amd_cpuid
                .normalize(cpu_index, cpu_count, cpu_bits)
                .map_err(NormalizeCpuidError::Amd),
        }
    }
}
