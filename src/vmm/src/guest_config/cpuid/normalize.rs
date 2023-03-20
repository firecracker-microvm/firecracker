// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::guest_config::cpuid::{CpuidKey, CpuidTrait};

/// Error type for [`Cpuid::normalize`].
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NormalizeCpuidError {
    /// Failed to apply modifications to Intel CPUID.
    #[error("Failed to apply modifications to Intel CPUID: {0}")]
    Intel(#[from] crate::guest_config::cpuid::intel::NormalizeCpuidError),
    /// Failed to apply modifications to AMD CPUID.
    #[error("Failed to apply modifications to AMD CPUID: {0}")]
    Amd(#[from] crate::guest_config::cpuid::amd::NormalizeCpuidError),
    /// Failed to set feature information leaf.
    #[error("Failed to set feature information leaf: {0}")]
    FeatureInformation(#[from] FeatureInformationError),
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

/// Error type for setting a bit range.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Given value is greater than maximum storable value in bit range.")]
pub struct CheckedAssignError;

/// Sets a given bit to a true or false (1 or 0).
#[allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)]
pub fn set_bit(x: &mut u32, bit: u8, y: bool) {
    debug_assert!(bit < 32);
    *x = (*x & !(1 << bit)) | ((u32::from(u8::from(y))) << bit);
}

/// Sets a given range to a given value.
#[allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)]
pub fn set_range(
    x: &mut u32,
    range: std::ops::Range<u8>,
    y: u32,
) -> Result<(), CheckedAssignError> {
    debug_assert!(range.end >= range.start);
    match range.end - range.start {
        z @ 0..=31 => {
            if y >= 2u32.pow(u32::from(z)) {
                Err(CheckedAssignError)
            } else {
                let shift = y << range.start;
                *x = shift | (*x & !mask(range));
                Ok(())
            }
        }
        32 => {
            let shift = y << range.start;
            *x = shift | (*x & !mask(range));
            Ok(())
        }
        33.. => Err(CheckedAssignError),
    }
}

/// Returns a mask where the given range is ones.
#[allow(
    clippy::as_conversions,
    clippy::integer_arithmetic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
const fn mask(range: std::ops::Range<u8>) -> u32 {
    /// Returns a value where in the binary representation all bits to the right of the x'th bit
    /// from the left are 1.
    #[allow(clippy::unreachable)]
    const fn shift(x: u8) -> u32 {
        if x == 0 {
            0
        } else if x < u32::BITS as u8 {
            (1 << x) - 1
        } else if x == u32::BITS as u8 {
            u32::MAX
        } else {
            unreachable!()
        }
    }

    debug_assert!(range.end >= range.start);
    debug_assert!(range.end <= u32::BITS as u8);

    let front = shift(range.start);
    let back = shift(range.end);
    !front & back
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

            let leaf_1 = self
                .get_mut(&CpuidKey::leaf(0x1))
                .ok_or(FeatureInformationError::MissingLeaf1)?;

            // A value of 1 indicates that the processor’s local APIC timer supports one-shot
            // operation using a TSC deadline value.
            //
            // tsc_deadline: 24,

            // X86 hypervisor feature
            set_bit(&mut leaf_1.result.ecx, 24, true);

            // Hypervisor bit
            set_bit(&mut leaf_1.result.ecx, HYPERVISOR_BITINDEX, true);

            // Initial APIC ID.
            //
            // The 8-bit initial APIC ID in EBX[31:24] is replaced by the 32-bit x2APIC ID,
            // available in Leaf 0BH and Leaf 1FH.
            //
            // initial_apic_id: 24..32,
            set_range(&mut leaf_1.result.ebx, 24..32, u32::from(cpu_index))
                .map_err(FeatureInformationError::InitialApicId)?;

            // CLFLUSH line size (Value ∗ 8 = cache line size in bytes; used also by CLFLUSHOPT).
            //
            // clflush: 8..16,
            set_range(&mut leaf_1.result.ebx, 8..16, EBX_CLFLUSH_CACHELINE)
                .map_err(FeatureInformationError::Clflush)?;

            let max_cpus_per_package = u32::from(
                get_max_cpus_per_package(cpu_count)
                    .map_err(FeatureInformationError::GetMaxCpusPerPackage)?,
            );

            // Maximum number of addressable IDs for logical processors in this physical package.
            //
            // The nearest power-of-2 integer that is not smaller than EBX[23:16] is the number of
            // unique initial APIC IDs reserved for addressing different logical
            // processors in a physical package. This field is only valid if
            // CPUID.1.EDX.HTT[bit 28]= 1.
            //
            // max_addressable_logical_processor_ids: 16..24,
            set_range(&mut leaf_1.result.ebx, 16..24, max_cpus_per_package)
                .map_err(FeatureInformationError::SetMaxCpusPerPackage)?;

            // Max APIC IDs reserved field is Valid. A value of 0 for HTT indicates there is only a
            // single logical processor in the package and software should assume only a
            // single APIC ID is reserved. A value of 1 for HTT indicates the value in
            // CPUID.1.EBX[23:16] (the Maximum number of addressable IDs for logical
            // processors in this package) is valid for the package.
            //
            // htt: 28,

            // A value of 1 for HTT indicates the value in CPUID.1.EBX[23:16]
            // (the Maximum number of addressable IDs for logical processors in this package)
            // is valid for the package
            set_bit(&mut leaf_1.result.edx, 28, cpu_count > 1);
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
