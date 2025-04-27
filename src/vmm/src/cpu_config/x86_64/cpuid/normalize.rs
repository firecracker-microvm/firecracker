// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cpu_config::x86_64::cpuid::{
    CpuidEntry, CpuidKey, CpuidRegisters, CpuidTrait, KvmCpuidFlags, cpuid,
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
    /// Failed to set domain type (CPUID.(EAX=0xB,ECX={0}):ECX[15:8]): {1}
    DomainType(u32, CheckedAssignError),
    /// Failed to set input ECX (CPUID.(EAX=0xB,ECX={0}):ECX[7:0]): {1}
    InputEcx(u32, CheckedAssignError),
    /// Failed to set number of logical processors (CPUID.(EAX=0xB,ECX={0}):EBX[15:0]): {1}
    NumLogicalProcs(u32, CheckedAssignError),
    /// Failed to set right-shift bits (CPUID.(EAX=0xB,ECX={0}):EAX[4:0]): {1}
    RightShiftBits(u32, CheckedAssignError),
    /// Unexpected subleaf: {0}
    UnexpectedSubleaf(u32)
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
pub fn set_range(
    x: &mut u32,
    range: std::ops::RangeInclusive<u8>,
    y: u32,
) -> Result<(), CheckedAssignError> {
    let start = *range.start();
    let end = *range.end();

    debug_assert!(end >= start);
    debug_assert!(end < 32);

    // Ensure `y` fits within the number of bits in the specified range.
    // Note that
    // - 1 <= `num_bits` <= 32 from the above assertion
    // - if `num_bits` equals to 32, `y` always fits within it since `y` is `u32`.
    let num_bits = end - start + 1;
    if num_bits < 32 && y >= (1u32 << num_bits) {
        return Err(CheckedAssignError);
    }

    let mask = get_mask(range);
    *x = (*x & !mask) | (y << start);

    Ok(())
}

/// Gets a given range within a given value.
pub fn get_range(x: u32, range: std::ops::RangeInclusive<u8>) -> u32 {
    let start = *range.start();
    let end = *range.end();

    debug_assert!(end >= start);
    debug_assert!(end < 32);

    let mask = get_mask(range);
    (x & mask) >> start
}

/// Returns a mask where the given range is ones.
const fn get_mask(range: std::ops::RangeInclusive<u8>) -> u32 {
    let num_bits = *range.end() - *range.start() + 1;
    let shift = *range.start();

    if num_bits == 32 {
        u32::MAX
    } else {
        ((1u32 << num_bits) - 1) << shift
    }
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
        self.update_feature_info_entry(cpu_index, cpu_count)?;
        self.update_extended_topology_entry(cpu_index, cpu_count, cpu_bits, cpus_per_core)?;
        self.update_extended_cache_features()?;

        // Apply manufacturer specific modifications.
        match self {
            // Apply Intel specific modifications.
            Self::Intel(intel_cpuid) => {
                intel_cpuid.normalize(cpu_index, cpu_count, cpus_per_core)?;
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
    fn update_feature_info_entry(
        &mut self,
        cpu_index: u8,
        cpu_count: u8,
    ) -> Result<(), FeatureInformationError> {
        let leaf_1 = self
            .get_mut(&CpuidKey::leaf(0x1))
            .ok_or(FeatureInformationError::MissingLeaf1)?;

        // CPUID.01H:EBX[15:08]
        // CLFLUSH line size (Value * 8 = cache line size in bytes; used also by CLFLUSHOPT).
        set_range(&mut leaf_1.result.ebx, 8..=15, 8).map_err(FeatureInformationError::Clflush)?;

        // CPUID.01H:EBX[23:16]
        // Maximum number of addressable IDs for logical processors in this physical package.
        //
        // The nearest power-of-2 integer that is not smaller than EBX[23:16] is the number of
        // unique initial APIC IDs reserved for addressing different logical processors in a
        // physical package. This field is only valid if CPUID.1.EDX.HTT[bit 28]= 1.
        let max_cpus_per_package = u32::from(
            get_max_cpus_per_package(cpu_count)
                .map_err(FeatureInformationError::GetMaxCpusPerPackage)?,
        );
        set_range(&mut leaf_1.result.ebx, 16..=23, max_cpus_per_package)
            .map_err(FeatureInformationError::SetMaxCpusPerPackage)?;

        // CPUID.01H:EBX[31:24]
        // Initial APIC ID.
        //
        // The 8-bit initial APIC ID in EBX[31:24] is replaced by the 32-bit x2APIC ID, available
        // in Leaf 0BH and Leaf 1FH.
        set_range(&mut leaf_1.result.ebx, 24..=31, u32::from(cpu_index))
            .map_err(FeatureInformationError::InitialApicId)?;

        // CPUID.01H:ECX[15] (Mnemonic: PDCM)
        // Performance and Debug Capability: A value of 1 indicates the processor supports the
        // performance and debug feature indication MSR IA32_PERF_CAPABILITIES.
        set_bit(&mut leaf_1.result.ecx, 15, false);

        // CPUID.01H:ECX[24] (Mnemonic: TSC-Deadline)
        // A value of 1 indicates that the processor’s local APIC timer supports one-shot operation
        // using a TSC deadline value.
        set_bit(&mut leaf_1.result.ecx, 24, true);

        // CPUID.01H:ECX[31] (Mnemonic: Hypervisor)
        set_bit(&mut leaf_1.result.ecx, 31, true);

        // CPUID.01H:EDX[28] (Mnemonic: HTT)
        // Max APIC IDs reserved field is Valid. A value of 0 for HTT indicates there is only a
        // single logical processor in the package and software should assume only a single APIC ID
        // is reserved. A value of 1 for HTT indicates the value in CPUID.1.EBX[23:16] (the Maximum
        // number of addressable IDs for logical processors in this package) is valid for the
        // package.
        set_bit(&mut leaf_1.result.edx, 28, cpu_count > 1);

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
        // The following commit changed the behavior of KVM_GET_SUPPORTED_CPUID to no longer
        // include CPUID.(EAX=0BH,ECX=1).
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
                // Reset eax, ebx, ecx
                subleaf.result.eax = 0;
                subleaf.result.ebx = 0;
                subleaf.result.ecx = 0;
                // CPUID.(EAX=0BH,ECX=N).EDX[31:0]
                // x2APIC ID of the current logical processor.
                subleaf.result.edx = u32::from(cpu_index);
                subleaf.flags = KvmCpuidFlags::SIGNIFICANT_INDEX;

                match index {
                    // CPUID.(EAX=0BH,ECX=N):EAX[4:0]
                    // The number of bits that the x2APIC ID must be shifted to the right to address
                    // instances of the next higher-scoped domain. When logical processor is not
                    // supported by the processor, the value of this field at the Logical Processor
                    // domain sub-leaf may be returned as either 0 (no allocated bits in the x2APIC
                    // ID) or 1 (one allocated bit in the x2APIC ID); software should plan
                    // accordingly.

                    // CPUID.(EAX=0BH,ECX=N):EBX[15:0]
                    // The number of logical processors across all instances of this domain within
                    // the next-higher scoped domain. (For example, in a processor socket/package
                    // comprising "M" dies of "N" cores each, where each core has "L" logical
                    // processors, the "die" domain sub-leaf value of this field would be M*N*L.)
                    // This number reflects configuration as shipped by Intel. Note, software must
                    // not use this field to enumerate processor topology.

                    // CPUID.(EAX=0BH,ECX=N):ECX[7:0]
                    // The input ECX sub-leaf index.

                    // CPUID.(EAX=0BH,ECX=N):ECX[15:8]
                    // Domain Type. This field provides an identification value which indicates the
                    // domain as shown below. Although domains are ordered, their assigned
                    // identification values are not and software should not depend on it.
                    //
                    // Hierarchy    Domain              Domain Type Identification Value
                    // -----------------------------------------------------------------
                    // Lowest       Logical Processor   1
                    // Highest      Core                2
                    //
                    // (Note that enumeration values of 0 and 3-255 are reserved.)

                    // Logical processor domain
                    0 => {
                        // To get the next level APIC ID, shift right with at most 1 because we have
                        // maximum 2 logical procerssors per core that can be represented by 1 bit.
                        set_range(&mut subleaf.result.eax, 0..=4, u32::from(cpu_bits))
                            .map_err(|err| ExtendedTopologyError::RightShiftBits(index, err))?;

                        // When cpu_count == 1 or HT is disabled, there is 1 logical core at this
                        // domain; otherwise there are 2
                        set_range(&mut subleaf.result.ebx, 0..=15, u32::from(cpus_per_core))
                            .map_err(|err| ExtendedTopologyError::NumLogicalProcs(index, err))?;

                        // Skip setting 0 to ECX[7:0] since it's already reset to 0.

                        // Set the domain type identification value for logical processor,
                        set_range(&mut subleaf.result.ecx, 8..=15, 1)
                            .map_err(|err| ExtendedTopologyError::DomainType(index, err))?;
                    }
                    // Core domain
                    1 => {
                        // Configure such that the next higher-scoped domain (i.e. socket) include
                        // all logical processors.
                        //
                        // The CPUID.(EAX=0BH,ECX=1).EAX[4:0] value must be an integer N such that
                        // 2^N is greater than or equal to the maximum number of vCPUs.
                        set_range(
                            &mut subleaf.result.eax,
                            0..=4,
                            MAX_SUPPORTED_VCPUS.next_power_of_two().ilog2(),
                        )
                        .map_err(|err| ExtendedTopologyError::RightShiftBits(index, err))?;
                        set_range(&mut subleaf.result.ebx, 0..=15, u32::from(cpu_count))
                            .map_err(|err| ExtendedTopologyError::NumLogicalProcs(index, err))?;

                        // Setting the input ECX value (i.e. `index`)
                        set_range(&mut subleaf.result.ecx, 0..=7, index)
                            .map_err(|err| ExtendedTopologyError::InputEcx(index, err))?;

                        // Set the domain type identification value for core.
                        set_range(&mut subleaf.result.ecx, 8..=15, 2)
                            .map_err(|err| ExtendedTopologyError::DomainType(index, err))?;
                    }
                    _ => {
                        // KVM no longer returns any subleaf numbers greater than 0. The patch was
                        // merged in v6.2 and backported to v5.10. Subleaves >= 2 should not be
                        // included.
                        // https://github.com/torvalds/linux/commit/45e966fcca03ecdcccac7cb236e16eea38cc18af
                        return Err(ExtendedTopologyError::UnexpectedSubleaf(index));
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
        let result = intel_cpuid.update_extended_topology_entry(
            cpu_index,
            cpu_count,
            cpu_bits,
            cpus_per_core,
        );
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
        let result =
            amd_cpuid.update_extended_topology_entry(cpu_index, cpu_count, cpu_bits, cpus_per_core);
        result.unwrap();
        assert!(amd_cpuid.inner().contains_key(&CpuidKey {
            leaf: 0xb,
            subleaf: 0x1
        }));
    }
}
