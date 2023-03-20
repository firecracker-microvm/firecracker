// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::guest_config::cpuid::normalize::{set_bit, set_range, CheckedAssignError};
use crate::guest_config::cpuid::{
    host_brand_string, CpuidEntry, CpuidKey, CpuidRegisters, CpuidTrait, KvmCpuidFlags,
    MissingBrandStringLeaves, BRAND_STRING_LENGTH,
};

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
    ApplyBrandString(MissingBrandStringLeaves),
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
    Overflow(<u32 as TryFrom<u32>>::Error),
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
    #[allow(clippy::unwrap_in_result)]
    fn update_deterministic_cache_entry(
        &mut self,
        cpu_count: u8,
        cpus_per_core: u8,
    ) -> Result<(), DeterministicCacheError> {
        for i in 0.. {
            if let Some(subleaf) = self.get_mut(&CpuidKey::subleaf(0x4, i)) {
                // Cache Type Field.
                // - 0 = Null - No more caches.
                // - 1 = Data Cache.
                // - 2 = Instruction Cache.
                // - 3 = Unified Cache.
                // - 4-31 = Reserved.
                //
                // cache_type_field: 0..5,
                let cache_level = subleaf.result.eax & 15;

                // Maximum number of addressable IDs for logical processors sharing this cache.
                // - Add one to the return value to get the result.
                // - The nearest power-of-2 integer that is not smaller than (1 + EAX[25:14]) is the
                //   number of unique initial APIC IDs reserved for addressing different logical
                //   processors sharing this cache.
                //
                // max_num_addressable_ids_for_logical_processors_sharing_this_cache: 14..26,

                // We know `cpus_per_core > 0` therefore `cpus_per_core.checked_sub(1).unwrap()` is
                // always safe.
                #[allow(clippy::unwrap_used)]
                match cache_level {
                    // L1 & L2 Cache
                    // The L1 & L2 cache is shared by at most 2 hyperthreads
                    1 | 2 => {
                        let sub = u32::from(cpus_per_core.checked_sub(1).unwrap());
                        set_range(&mut subleaf.result.eax, 14..26, sub)
                            .map_err(DeterministicCacheError::MaxCpusPerCore)?;
                    }
                    // L3 Cache
                    // The L3 cache is shared among all the logical threads
                    3 => {
                        let sub = u32::from(
                            cpu_count
                                .checked_sub(1)
                                .ok_or(DeterministicCacheError::MaxCpusPerCoreUnderflow)?,
                        );
                        set_range(&mut subleaf.result.eax, 14..26, sub)
                            .map_err(DeterministicCacheError::MaxCpusPerCore)?;
                    }
                    _ => (),
                }

                // We know `cpus_per_core !=0` therefore this is always safe.
                #[allow(clippy::unwrap_used)]
                let cores = cpu_count.checked_div(cpus_per_core).unwrap();

                // Maximum number of addressable IDs for processor cores in the physical package.
                // - Add one to the return value to get the result.
                // - The nearest power-of-2 integer that is not smaller than (1 + EAX[31:26]) is the
                //   number of unique Core_IDs reserved for addressing different processor cores in
                //   a physical package. Core ID is a subset of bits of the initial APIC ID.
                // - The returned value is constant for valid initial values in ECX. Valid ECX
                //   values start from 0.
                //
                // max_num_addressable_ids_for_processor_cores_in_physical_package: 26..32,

                // Put all the cores in the same socket
                let sub = u32::from(cores)
                    .checked_sub(1)
                    .ok_or(DeterministicCacheError::MaxCorePerPackageUnderflow)?;
                set_range(&mut subleaf.result.eax, 26..32, sub)
                    .map_err(DeterministicCacheError::MaxCorePerPackage)?;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Update power management entry
    fn update_power_management_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        let leaf_6 = self
            .get_mut(&CpuidKey::leaf(0x6))
            .ok_or(NormalizeCpuidError::MissingLeaf6)?;

        // Intel Turbo Boost Technology available (see description of IA32_MISC_ENABLE[38]).
        //
        // intel_turbo_boost_technology: 1,
        set_bit(&mut leaf_6.result.eax, 1, false);

        // The processor supports performance-energy bias preference if CPUID.06H:ECX.SETBH[bit 3]
        // is set and it also implies the presence of a new architectural MSR called
        // IA32_ENERGY_PERF_BIAS (1B0H).
        //
        // performance_energy_bias: 3,

        // Clear X86 EPB feature. No frequency selection in the hypervisor.
        set_bit(&mut leaf_6.result.ecx, 3, false);
        Ok(())
    }

    /// Update performance monitoring entry
    fn update_performance_monitoring_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        let leaf_a = self
            .get_mut(&CpuidKey::leaf(0xA))
            .ok_or(NormalizeCpuidError::MissingLeafA)?;
        leaf_a.result = CpuidRegisters {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        };
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
        self.0
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

        for index in 0.. {
            if let Some(subleaf) = self.get_mut(&CpuidKey::subleaf(0xB, index)) {
                // reset eax, ebx, ecx
                subleaf.result.eax = 0;
                subleaf.result.ebx = 0;
                subleaf.result.ecx = 0;
                // EDX bits 31..0 contain x2APIC ID of current logical processor
                // x2APIC increases the size of the APIC ID from 8 bits to 32 bits
                subleaf.result.edx = u32::from(cpu_index);

                // "If SMT is not present in a processor implementation but CPUID leaf 0BH is
                // supported, CPUID.EAX=0BH, ECX=0 will return EAX = 0, EBX = 1 and
                // level type = 1. Number of logical processors at the core level is
                // reported at level type = 2." (Intel® 64 Architecture x2APIC
                // Specification, Ch. 2.8)
                match index {
                    // Number of bits to shift right on x2APIC ID to get a unique topology ID of the
                    // next level type*. All logical processors with the same
                    // next level ID share current level.
                    //
                    // *Software should use this field (EAX[4:0]) to enumerate processor topology of
                    // the system.
                    //
                    // bit_shifts_right_2x_apic_id_unique_topology_id: 0..5

                    // Number of logical processors at this level type. The number reflects
                    // configuration as shipped by Intel**.
                    //
                    // **Software must not use EBX[15:0] to enumerate processor topology of the
                    // system. This value in this field (EBX[15:0]) is only
                    // intended for display/diagnostic purposes. The actual
                    // number of  logical processors available to BIOS/OS/Applications may be
                    // different from the value of  EBX[15:0], depending on
                    // software and platform hardware configurations.
                    //
                    // logical_processors: 0..16

                    // Level number. Same value in ECX input.
                    //
                    // level_number: 0..8,

                    // Level type***
                    //
                    // If an input value n in ECX returns the invalid level-type of 0 in ECX[15:8],
                    // other input values with ECX>n also return 0 in ECX[15:8].
                    //
                    // ***The value of the “level type” field is not related to level numbers in any
                    // way, higher “level type” values do not mean higher
                    // levels. Level type field has the following encoding:
                    // - 0: Invalid.
                    // - 1: SMT.
                    // - 2: Core.
                    // - 3-255: Reserved.
                    //
                    // level_type: 8..16

                    // Thread Level Topology; index = 0
                    0 => {
                        // To get the next level APIC ID, shift right with at most 1 because we have
                        // maximum 2 hyperthreads per core that can be represented by 1 bit.
                        set_range(&mut subleaf.result.eax, 0..5, u32::from(cpu_bits))
                            .map_err(ExtendedTopologyError::ApicId)?;

                        // When cpu_count == 1 or HT is disabled, there is 1 logical core at this
                        // level Otherwise there are 2
                        set_range(&mut subleaf.result.ebx, 0..16, u32::from(cpus_per_core))
                            .map_err(ExtendedTopologyError::LogicalProcessors)?;

                        set_range(&mut subleaf.result.ecx, 8..16, LEVEL_TYPE_THREAD)
                            .map_err(ExtendedTopologyError::LevelType)?;
                    }
                    // Core Level Processor Topology; index = 1
                    1 => {
                        set_range(&mut subleaf.result.eax, 0..5, LEAFBH_INDEX1_APICID)
                            .map_err(ExtendedTopologyError::ApicId)?;

                        set_range(&mut subleaf.result.ebx, 0..16, u32::from(cpu_count))
                            .map_err(ExtendedTopologyError::LogicalProcessors)?;

                        // We expect here as this is an extremely rare case that is unlikely to ever
                        // occur. It would require manual editing of the CPUID structure to push
                        // more than 2^32 subleaves.
                        let sub = index;
                        set_range(&mut subleaf.result.ecx, 0..8, sub)
                            .map_err(ExtendedTopologyError::LevelNumber)?;

                        set_range(&mut subleaf.result.ecx, 8..16, LEVEL_TYPE_CORE)
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
                        subleaf.result.ecx = index;
                    }
                }
            } else {
                break;
            }
        }
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

    // Padding ensures `brand_string.len() == BRAND_STRING_LENGTH` thus
    // `brand_string.try_into().unwrap()` is safe.
    #[allow(clippy::unwrap_used)]
    Ok(brand_string.try_into().unwrap())
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
