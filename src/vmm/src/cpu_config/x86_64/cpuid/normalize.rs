// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cpu_config::x86_64::cpuid::{
    cpuid, CpuidEntry, CpuidKey, CpuidRegisters, CpuidTrait, KvmCpuidFlags,
};
use crate::vmm_config::machine_config::MAX_SUPPORTED_VCPUS;

/// Error type for [`super::Cpuid::normalize`].
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
pub enum NormalizeCpuidError {
    /// Provided `cpu_bits` is >=8: {0}.
    CpuBits(u8),
    /// Failed to apply modifications to Intel CPUID: {0}
    Intel(#[from] crate::cpu_config::x86_64::cpuid::intel::NormalizeCpuidError),
    /// Failed to apply modifications to AMD CPUID: {0}
    Amd(#[from] crate::cpu_config::x86_64::cpuid::amd::NormalizeCpuidError),
    /// Failed to set feature information leaf: {0}
    FeatureInformation(#[from] FeatureInformationError),
    /// Failed to set extended topology leaf: {0}
    ExtendedTopology(#[from] ExtendedTopologyError),
    /// Failed to set extended cache features leaf: {0}
    ExtendedCacheFeatures(#[from] ExtendedCacheFeaturesError),
    /// Failed to set vendor ID in leaf 0x0: {0}
    VendorId(#[from] VendorIdError),
}

/// Error type for setting leaf 0 section.
#[derive(Debug, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
pub enum VendorIdError {
    /// Leaf 0x0 is missing from CPUID.
    MissingLeaf0,
}

/// Error type for setting leaf 1 section of `IntelCpuid::normalize`.
#[derive(Debug, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
pub enum FeatureInformationError {
    /// Leaf 0x1 is missing from CPUID.
    MissingLeaf1,
    /// Failed to set `Initial APIC ID`: {0}
    InitialApicId(CheckedAssignError),
    /// Failed to set `CLFLUSH line size`: {0}
    Clflush(CheckedAssignError),
    /// Failed to get max CPUs per package: {0}
    GetMaxCpusPerPackage(GetMaxCpusPerPackageError),
    /// Failed to set max CPUs per package: {0}
    SetMaxCpusPerPackage(CheckedAssignError),
}

/// Error type for `get_max_cpus_per_package`.
#[derive(Debug, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
pub enum GetMaxCpusPerPackageError {
    /// Failed to get max CPUs per package as `cpu_count == 0`
    Underflow,
    /// Failed to get max CPUs per package as `cpu_count > 128`
    Overflow,
}

/// Error type for setting leaf b section of `IntelCpuid::normalize`.
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
pub enum ExtendedTopologyError {
    /// Failed to set `Number of bits to shift right on x2APIC ID to get a unique topology ID of the next level type`: {0}
    ApicId(CheckedAssignError),
    /// Failed to set `Number of logical processors at this level type`: {0}
    LogicalProcessors(CheckedAssignError),
    /// Failed to set `Level Type`: {0}
    LevelType(CheckedAssignError),
    /// Failed to set `Level Number`: {0}
    LevelNumber(CheckedAssignError),
    /// Failed to set all leaves, as more than `u32::MAX` sub-leaves are present: {0}
    Overflow(<u32 as TryFrom<usize>>::Error),
}

/// Error type for setting leaf 0x80000006 of Cpuid::normalize().
#[derive(Debug, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
pub enum ExtendedCacheFeaturesError {
    /// Leaf 0x80000005 is missing from CPUID.
    MissingLeaf0x80000005,
    /// Leaf 0x80000006 is missing from CPUID.
    MissingLeaf0x80000006,
}

/// Error type for setting a bit range.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Given value is greater than maximum storable value in bit range.")]
pub struct CheckedAssignError;

/// Sets a given bit to a true or false (1 or 0).
#[allow(clippy::arithmetic_side_effects)]
pub fn set_bit(x: &mut u32, bit: u8, y: bool) {
    debug_assert!(bit < 32);
    *x = (*x & !(1 << bit)) | ((u32::from(u8::from(y))) << bit);
}

/// Sets a given range to a given value.
#[allow(clippy::arithmetic_side_effects)]
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
/// Gets a given range within a given value.
#[allow(clippy::arithmetic_side_effects)]
pub fn get_range(x: u32, range: std::ops::Range<u8>) -> u32 {
    debug_assert!(range.end >= range.start);
    (x & mask(range.clone())) >> range.start
}

/// Returns a mask where the given range is ones.
#[allow(
    clippy::as_conversions,
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
    /// - [`super::IntelCpuid::normalize`] errors.
    /// - [`super::AmdCpuid::normalize`] errors.
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
        self.update_vendor_id()?;
        self.update_feature_info_entry(cpu_index)?;
        self.update_extended_topology_entry(cpu_index, cpu_bits, cpus_per_core)?;
        self.update_extended_cache_features()?;

        // Apply manufacturer specific modifications.
        match self {
            // Apply Intel specific modifications.
            Self::Intel(intel_cpuid) => {
                intel_cpuid.normalize(cpus_per_core)?;
            }
            // Apply AMD specific modifications.
            Self::Amd(amd_cpuid) => amd_cpuid.normalize(cpu_index, cpu_count, cpus_per_core)?,
        }

        Ok(())
    }

    /// Pass-through the vendor ID from the host. This is used to prevent modification of the vendor
    /// ID via custom CPU templates.
    fn update_vendor_id(&mut self) -> Result<(), VendorIdError> {
        let leaf_0 = self
            .get_mut(&CpuidKey::leaf(0x0))
            .ok_or(VendorIdError::MissingLeaf0)?;

        let host_leaf_0 = cpuid(0x0);

        leaf_0.result.ebx = host_leaf_0.ebx;
        leaf_0.result.ecx = host_leaf_0.ecx;
        leaf_0.result.edx = host_leaf_0.edx;

        Ok(())
    }

    // Update feature information entry
    fn update_feature_info_entry(&mut self, cpu_index: u8) -> Result<(), FeatureInformationError> {
        // Flush a cache line size.
        const EBX_CLFLUSH_CACHELINE: u32 = 8;

        // PDCM: Perfmon and Debug Capability.
        const ECX_PDCM_BITINDEX: u8 = 15;

        // TSC-Deadline.
        const ECX_TSC_DEADLINE_BITINDEX: u8 = 24;

        // CPU is running on a hypervisor.
        const ECX_HYPERVISOR_BITINDEX: u8 = 31;

        let leaf_1 = self
            .get_mut(&CpuidKey::leaf(0x1))
            .ok_or(FeatureInformationError::MissingLeaf1)?;

        // A value of 1 indicates the processor supports the performance and debug feature
        // indication MSR IA32_PERF_CAPABILITIES.
        //
        // pdcm: 15,
        set_bit(&mut leaf_1.result.ecx, ECX_PDCM_BITINDEX, false);

        // A value of 1 indicates that the processor’s local APIC timer supports one-shot
        // operation using a TSC deadline value.
        //
        // tsc_deadline: 24,
        set_bit(&mut leaf_1.result.ecx, ECX_TSC_DEADLINE_BITINDEX, true);

        // Hypervisor bit
        set_bit(&mut leaf_1.result.ecx, ECX_HYPERVISOR_BITINDEX, true);

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
            get_max_cpus_per_package(MAX_SUPPORTED_VCPUS)
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
        set_bit(&mut leaf_1.result.edx, 28, true);

        Ok(())
    }

    /// Update extended topology entry
    fn update_extended_topology_entry(
        &mut self,
        cpu_index: u8,
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

        for index in 0.. {
            if let Some(subleaf) = self.get_mut(&CpuidKey::subleaf(0xB, index)) {
                // reset eax, ebx, ecx
                subleaf.result.eax = 0;
                subleaf.result.ebx = 0;
                subleaf.result.ecx = 0;
                // EDX bits 31..0 contain x2APIC ID of current logical processor
                // x2APIC increases the size of the APIC ID from 8 bits to 32 bits
                subleaf.result.edx = u32::from(cpu_index);
                subleaf.flags = KvmCpuidFlags::SIGNIFICANT_INDEX;

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

                        set_range(
                            &mut subleaf.result.ebx,
                            0..16,
                            u32::from(MAX_SUPPORTED_VCPUS),
                        )
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

    // Update extended cache features entry
    fn update_extended_cache_features(&mut self) -> Result<(), ExtendedCacheFeaturesError> {
        // Leaf 0x800000005 indicates L1 Cache and TLB Information.
        let guest_leaf_0x80000005 = self
            .get_mut(&CpuidKey::leaf(0x80000005))
            .ok_or(ExtendedCacheFeaturesError::MissingLeaf0x80000005)?;
        guest_leaf_0x80000005.result = cpuid(0x80000005).into();

        // Leaf 0x80000006 indicates L2 Cache and TLB and L3 Cache Information.
        let guest_leaf_0x80000006 = self
            .get_mut(&CpuidKey::leaf(0x80000006))
            .ok_or(ExtendedCacheFeaturesError::MissingLeaf0x80000006)?;
        guest_leaf_0x80000006.result = cpuid(0x80000006).into();
        guest_leaf_0x80000006.result.edx &= !0x00030000; // bits [17:16] are reserved
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
    use std::collections::BTreeMap;

    use super::*;
    use crate::cpu_config::x86_64::cpuid::{AmdCpuid, Cpuid, IntelCpuid};

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

    #[test]
    fn test_update_vendor_id() {
        // Check `update_vendor_id()` passes through the vendor ID from the host correctly.

        // Pseudo CPUID with invalid vendor ID.
        let mut guest_cpuid = Cpuid::Intel(IntelCpuid(BTreeMap::from([(
            CpuidKey {
                leaf: 0x0,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags::EMPTY,
                result: CpuidRegisters {
                    eax: 0,
                    ebx: 0x0123_4567,
                    ecx: 0x89ab_cdef,
                    edx: 0x55aa_55aa,
                },
            },
        )])));

        // Pass through vendor ID from host.
        guest_cpuid.update_vendor_id().unwrap();

        // Check if the guest vendor ID matches the host one.
        let guest_leaf_0 = guest_cpuid
            .get(&CpuidKey {
                leaf: 0x0,
                subleaf: 0x0,
            })
            .unwrap();
        let host_leaf_0 = cpuid(0x0);
        assert_eq!(guest_leaf_0.result.ebx, host_leaf_0.ebx);
        assert_eq!(guest_leaf_0.result.ecx, host_leaf_0.ecx);
        assert_eq!(guest_leaf_0.result.edx, host_leaf_0.edx);
    }

    #[test]
    fn check_leaf_0xb_subleaf_0x1_added() {
        // Check leaf 0xb / subleaf 0x1 is added in `update_extended_topology_entry()` even when it
        // isn't included.

        // Pseudo CPU setting
        let smt = false;
        let cpu_index = 0;
        let cpu_count = 2;
        let cpu_bits = u8::from(cpu_count > 1 && smt);
        let cpus_per_core = 1u8
            .checked_shl(u32::from(cpu_bits))
            .ok_or(NormalizeCpuidError::CpuBits(cpu_bits))
            .unwrap();

        // Case 1: Intel CPUID
        let mut intel_cpuid = Cpuid::Intel(IntelCpuid(BTreeMap::from([(
            CpuidKey {
                leaf: 0xb,
                subleaf: 0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                result: CpuidRegisters {
                    eax: 0,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                },
            },
        )])));
        let result = intel_cpuid.update_extended_topology_entry(cpu_index, cpu_bits, cpus_per_core);
        result.unwrap();
        assert!(intel_cpuid.inner().contains_key(&CpuidKey {
            leaf: 0xb,
            subleaf: 0x1
        }));

        // Case 2: AMD CPUID
        let mut amd_cpuid = Cpuid::Amd(AmdCpuid(BTreeMap::from([(
            CpuidKey {
                leaf: 0xb,
                subleaf: 0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                result: CpuidRegisters {
                    eax: 0,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                },
            },
        )])));
        let result = amd_cpuid.update_extended_topology_entry(cpu_index, cpu_bits, cpus_per_core);
        result.unwrap();
        assert!(amd_cpuid.inner().contains_key(&CpuidKey {
            leaf: 0xb,
            subleaf: 0x1
        }));
    }
}
