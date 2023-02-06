// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use bit_fields::CheckedAssignError;

use super::registers;
use crate::cpuid::{CpuidTrait, BRAND_STRING_LENGTH};

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
    GetBrandString(DefaultBrandStringError),
    /// Failed to set brand string.
    #[error("Failed to set brand string: {0}")]
    ApplyBrandString(crate::cpuid::MissingBrandStringLeaves),
}

/// Error type for setting leaf 4 section of `IntelCpuid::normalize`.
#[allow(clippy::enum_variant_names)]
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
        // Get host brand string.
        let host_brand_string: [u8; BRAND_STRING_LENGTH] = crate::cpuid::host_brand_string();

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
    MissingFrequency([u8; crate::cpuid::BRAND_STRING_LENGTH]),
    /// Missing space.
    #[error("Missing space: {0:?}.")]
    MissingSpace([u8; crate::cpuid::BRAND_STRING_LENGTH]),
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
    // e.g. b"Intel(R) Xeon(R) Processor Platinum 8275CL CPU @ 3.00" and b"GHz"
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
    // e.g. b"Intel(R) Xeon(R) Processor Platinum 8275CL CPU @ " and b"3.00"
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
