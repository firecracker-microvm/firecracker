// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use bit_fields::CheckedAssignError;

use super::registers;
use crate::cpuid::{host_brand_string, CpuidTrait, MissingBrandStringLeaves, BRAND_STRING_LENGTH};

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
        // Get host brand string.
        let host_brand_string: [u8; BRAND_STRING_LENGTH] = host_brand_string();

        let default_brand_string =
            default_brand_string(host_brand_string).map_err(NormalizeCpuidError::GetBrandString)?;

        self.apply_brand_string(&default_brand_string)
            .map_err(NormalizeCpuidError::ApplyBrandString)?;
        Ok(())
    }
}

/// Error type for [`IntelCpuid::default_brand_string`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum DefaultBrandStringError {
    /// Missing frequency.
    #[error("Missing frequency: {0:?}.")]
    MissingFrequency([u8; BRAND_STRING_LENGTH]),
    /// Missing space.
    #[error("Missing space: {0:?}.")]
    MissingSpace([u8; BRAND_STRING_LENGTH]),
    /// Insufficient space in brand string.
    #[error("Insufficient space in brand string.")]
    Overflow,
}

/// Normalize brand string to a generic Xeon(R) processor, with the actual CPU frequency
///
/// # Errors
///
/// When unable to parse the host brand string.
/// `brand_string.try_into().unwrap()` cannot panic as we know
/// `brand_string.len() == BRAND_STRING_LENGTH`
///
/// # Panics
///
/// Never.
// As we pass through host frequency, we require CPUID and thus `cfg(cpuid)`.
// TODO: Use `split_array_ref`
// (https://github.com/firecracker-microvm/firecracker/issues/3347)
#[allow(
    clippy::indexing_slicing,
    clippy::integer_arithmetic,
    clippy::arithmetic_side_effects
)]
#[inline]
fn default_brand_string(
    // Host brand string.
    // This should look like b"Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz".
    host_brand_string: [u8; BRAND_STRING_LENGTH],
) -> Result<[u8; BRAND_STRING_LENGTH], DefaultBrandStringError> {
    /// We always use this brand string.
    const DEFAULT_BRAND_STRING_BASE: &[u8] = b"Intel(R) Xeon(R) Processor @";

    // The slice of the host string before the frequency suffix
    // e.g. b"Intel(4) Xeon(R) Processor Platinum 8275CL CPU @ 3.00" and b"GHz"
    let (before, after) = 'outer: {
        for i in 0..host_brand_string.len() {
            // Find position of b"THz" or b"GHz" or b"MHz"
            if let [b'T' | b'G' | b'M', b'H', b'z', ..] = host_brand_string[i..] {
                break 'outer Ok(host_brand_string.split_at(i));
            }
        }
        Err(DefaultBrandStringError::MissingFrequency(host_brand_string))
    }?;
    debug_assert_eq!(
        before.len().checked_add(after.len()),
        Some(BRAND_STRING_LENGTH)
    );

    // We iterate from the end until hitting a space, getting the frequency number
    // e.g. b"Intel(4) Xeon(R) Processor Platinum 8275CL CPU @ " and b"3.00"
    let (_, frequency) = 'outer: {
        for i in (0..before.len()).rev() {
            let c = before[i];
            match c {
                b' ' => break 'outer Ok(before.split_at(i)),
                b'0'..=b'9' | b'.' => continue,
                _ => break,
            }
        }
        Err(DefaultBrandStringError::MissingSpace(host_brand_string))
    }?;
    debug_assert!(frequency.len() <= before.len());

    debug_assert!(
        matches!(frequency.len().checked_add(after.len()), Some(x) if x <= BRAND_STRING_LENGTH)
    );
    debug_assert!(DEFAULT_BRAND_STRING_BASE.len() <= BRAND_STRING_LENGTH);
    debug_assert!(BRAND_STRING_LENGTH.checked_mul(2).is_some());

    // As `DEFAULT_BRAND_STRING_BASE.len() + frequency.len() + after.len()` is guaranteed
    // to be less than or equal to  `2*BRAND_STRING_LENGTH` and we know
    // `2*BRAND_STRING_LENGTH <= usize::MAX` since `BRAND_STRING_LENGTH==48`, this is always
    // safe.
    let len = DEFAULT_BRAND_STRING_BASE.len() + frequency.len() + after.len();

    let brand_string = DEFAULT_BRAND_STRING_BASE
        .iter()
        .copied()
        // Include frequency e.g. "3.00"
        .chain(frequency.iter().copied())
        // Include frequency suffix e.g. "GHz"
        .chain(after.iter().copied())
        // Pad with 0s to `BRAND_STRING_LENGTH`
        .chain(
            std::iter::repeat(b'\0').take(
                BRAND_STRING_LENGTH
                    .checked_sub(len)
                    .ok_or(DefaultBrandStringError::Overflow)?,
            ),
        )
        .collect::<Vec<_>>();
    debug_assert_eq!(brand_string.len(), BRAND_STRING_LENGTH);

    // SAFETY: Padding ensures `brand_string.len() == BRAND_STRING_LENGTH`.
    Ok(unsafe { brand_string.try_into().unwrap_unchecked() })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::undocumented_unsafe_blocks,
        clippy::unwrap_used,
        clippy::as_conversions
    )]

    use super::*;

    #[test]
    fn default_brand_string_test() {
        let brand_string = b"Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz\0\0";
        let ok_result = default_brand_string(*brand_string);
        let expected = Ok(*b"Intel(R) Xeon(R) Processor @ 3.00GHz\0\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(
            ok_result,
            expected,
            "{:?} != {:?}",
            ok_result.as_ref().map(|s| unsafe {
                std::ffi::CStr::from_ptr((s as *const u8).cast())
                    .to_str()
                    .unwrap()
            }),
            expected.as_ref().map(|s| unsafe {
                std::ffi::CStr::from_ptr((s as *const u8).cast())
                    .to_str()
                    .unwrap()
            })
        );
    }
    #[test]
    fn default_brand_string_test_missing_frequency() {
        let brand_string = b"Intel(R) Xeon(R) Platinum 8275CL CPU @ \0\0\0\0\0\0\0\0\0";
        let result = default_brand_string(*brand_string);
        let expected = Err(DefaultBrandStringError::MissingFrequency(*brand_string));
        assert_eq!(
            result,
            expected,
            "{:?} != {:?}",
            result.as_ref().map(|s| unsafe {
                std::ffi::CStr::from_ptr((s as *const u8).cast())
                    .to_str()
                    .unwrap()
            }),
            unsafe {
                std::ffi::CStr::from_ptr((brand_string as *const u8).cast())
                    .to_str()
                    .unwrap()
            }
        );
    }
    #[test]
    fn default_brand_string_test_missing_space() {
        let brand_string = b"Intel(R) Xeon(R) Platinum 8275CL CPU @3.00GHz\0\0\0";
        let result = default_brand_string(*brand_string);
        let expected = Err(DefaultBrandStringError::MissingSpace(*brand_string));
        assert_eq!(
            result,
            expected,
            "{:?} != {:?}",
            result.as_ref().map(|s| unsafe {
                std::ffi::CStr::from_ptr((s as *const u8).cast())
                    .to_str()
                    .unwrap()
            }),
            unsafe {
                std::ffi::CStr::from_ptr((brand_string as *const u8).cast())
                    .to_str()
                    .unwrap()
            }
        );
    }
    #[test]
    fn default_brand_string_test_overflow() {
        let brand_string = b"@ 123456789876543212345678987654321234567898GHz\0";
        let result = default_brand_string(*brand_string);
        assert_eq!(
            result,
            Err(DefaultBrandStringError::Overflow),
            "{:?}",
            result.as_ref().map(|s| unsafe {
                std::ffi::CStr::from_ptr((s as *const u8).cast())
                    .to_str()
                    .unwrap()
            }),
        );
    }
}
