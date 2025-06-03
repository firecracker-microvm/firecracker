// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cpu_config::x86_64::cpuid::normalize::{
    CheckedAssignError, get_range, set_bit, set_range,
};
use crate::cpu_config::x86_64::cpuid::{
    BRAND_STRING_LENGTH, CpuidKey, CpuidRegisters, CpuidTrait, MissingBrandStringLeaves, cpuid,
    host_brand_string,
};

/// Error type for [`super::IntelCpuid::normalize`].
#[derive(Debug, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
pub enum NormalizeCpuidError {
    /// Failed to set deterministic cache leaf: {0}
    DeterministicCache(#[from] DeterministicCacheError),
    /// Leaf {0} is missing from CPUID.
    MissingLeaf(usize),
    /// Failed to get brand string: {0}
    GetBrandString(DefaultBrandStringError),
    /// Failed to set brand string: {0}
    ApplyBrandString(MissingBrandStringLeaves),
}

/// Error type for setting leaf 4 section of [`super::IntelCpuid::normalize`].
// `displaydoc::Display` does not support multi-line comments, `rustfmt` will format these comments
// across multiple lines, so we skip formatting here. This can be removed when
// https://github.com/yaahc/displaydoc/issues/44 is resolved.
#[rustfmt::skip]
#[allow(clippy::enum_variant_names)]
#[derive(Debug, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
pub enum DeterministicCacheError {
    /// Failed to set max addressable core ID in physical package (CPUID.04H:EAX[31:26]): {0}.
    MaxCorePerPackage(CheckedAssignError),
    /// Failed to set max addressable core ID in physical package (CPUID.04H:EAX[31:26]) due to underflow in cores.
    MaxCorePerPackageUnderflow,
    /// Failed to set max addressable processor ID sharing cache (CPUID.04H:EAX[25:14]): {0}.
    MaxCpusPerCore(CheckedAssignError),
    /// Failed to set max addressable processor ID sharing cache (CPUID.04H:EAX[25:14]) due to underflow in cpu count.
    MaxCpusPerCoreUnderflow,
}

/// We always use this brand string.
pub const DEFAULT_BRAND_STRING: &[u8; BRAND_STRING_LENGTH] =
    b"Intel(R) Xeon(R) Processor\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
pub const DEFAULT_BRAND_STRING_BASE: &[u8; 28] = b"Intel(R) Xeon(R) Processor @";

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
        self.update_extended_feature_flags_entry()?;
        self.update_performance_monitoring_entry()?;
        self.update_extended_topology_v2_entry();
        self.update_brand_string_entry()?;
        //self.update_frequency_information();

        Ok(())
    }

    /// Passes through the host value of cpuid leaves 15h and 16h if they
    /// are not already configured via cpu template.
    fn update_frequency_information(&mut self) {
        let Some(leaf_15h) = self.get_mut(&CpuidKey::leaf(0x15)) else {
            return;
        };

        if leaf_15h.result == CpuidRegisters::default() {
            let host_leaf_15 = cpuid(0x15);

            // CPUID.15H:EAX[31:0]
            // Ratio of TSC frequency to Core Crystal Clock frequency, denominator
            leaf_15h.result.eax = host_leaf_15.eax;
            // CPUID.15H:EBX[31:0]
            // Ratio of TSC frequency to Core Crystal Clock frequency, numerator
            leaf_15h.result.ebx = host_leaf_15.ebx;
            // CPUID.15H:ECX[31:0]
            // Core Crystal Clock frequency, in units of Hz
            leaf_15h.result.ecx = host_leaf_15.ecx;
            // edx is reserved
        }

        let Some(leaf_16h) = self.get_mut(&CpuidKey::leaf(0x16)) else {
            return;
        };

        if leaf_16h.result == CpuidRegisters::default() {
            let host_leaf_16 = cpuid(0x16);

            // CPUID.16H:EAX[15:0]
            // Processor Base Frequency (in MHz)
            leaf_16h.result.eax = host_leaf_16.eax;
            // CPUID.16H:EBX[15:0]
            // Processor Maximum Frequency (in MHz)
            leaf_16h.result.ebx = host_leaf_16.ebx;
            // CPUID.16H:ECX[15:0]
            // Bus/Reference frequency (in MHz)
            leaf_16h.result.ecx = host_leaf_16.ecx;
            // edx is reserved
        }
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
                // If ECX contains an invalid subleaf, EAX/EBX/ECX/EDX return 0 and the
                // normalization should not be applied. Exits when it hits such an invalid subleaf.
                if subleaf.result.eax == 0
                    && subleaf.result.ebx == 0
                    && subleaf.result.ecx == 0
                    && subleaf.result.edx == 0
                {
                    break;
                }

                // CPUID.04H:EAX[7:5]
                // Cache Level (Starts at 1)
                let cache_level = get_range(subleaf.result.eax, 5..=7);

                // CPUID.04H:EAX[25:14]
                // Maximum number of addressable IDs for logical processors sharing this cache.
                // - Add one to the return value to get the result.
                // - The nearest power-of-2 integer that is not smaller than (1 + EAX[25:14]) is the
                //   number of unique initial APIC IDs reserved for addressing different logical
                //   processors sharing this cache.

                // We know `cpus_per_core > 0` therefore `cpus_per_core.checked_sub(1).unwrap()` is
                // always safe.
                #[allow(clippy::unwrap_used)]
                match cache_level {
                    // L1 & L2 Cache
                    // The L1 & L2 cache is shared by at most 2 hyperthreads
                    1 | 2 => {
                        let sub = u32::from(cpus_per_core.checked_sub(1).unwrap());
                        set_range(&mut subleaf.result.eax, 14..=25, sub)
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
                        set_range(&mut subleaf.result.eax, 14..=25, sub)
                            .map_err(DeterministicCacheError::MaxCpusPerCore)?;
                    }
                    _ => (),
                }

                // We know `cpus_per_core !=0` therefore this is always safe.
                #[allow(clippy::unwrap_used)]
                let cores = cpu_count.checked_div(cpus_per_core).unwrap();

                // CPUID.04H:EAX[31:26]
                // Maximum number of addressable IDs for processor cores in the physical package.
                // - Add one to the return value to get the result.
                // - The nearest power-of-2 integer that is not smaller than (1 + EAX[31:26]) is the
                //   number of unique Core_IDs reserved for addressing different processor cores in
                //   a physical package. Core ID is a subset of bits of the initial APIC ID.
                // - The returned value is constant for valid initial values in ECX. Valid ECX
                //   values start from 0.

                // Put all the cores in the same socket
                let sub = u32::from(cores)
                    .checked_sub(1)
                    .ok_or(DeterministicCacheError::MaxCorePerPackageUnderflow)?;
                set_range(&mut subleaf.result.eax, 26..=31, sub)
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
            .ok_or(NormalizeCpuidError::MissingLeaf(6))?;

        // CPUID.06H:EAX[1]
        // Intel Turbo Boost Technology available (see description of IA32_MISC_ENABLE[38]).
        set_bit(&mut leaf_6.result.eax, 1, false);

        // CPUID.06H:ECX[3]
        // The processor supports performance-energy bias preference if CPUID.06H:ECX.SETBH[bit 3]
        // is set and it also implies the presence of a new architectural MSR called
        // IA32_ENERGY_PERF_BIAS (1B0H).

        // Clear X86 EPB feature. No frequency selection in the hypervisor.
        set_bit(&mut leaf_6.result.ecx, 3, false);
        Ok(())
    }

    /// Update structured extended feature flags enumeration leaf
    fn update_extended_feature_flags_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        let leaf_7_0 = self
            .get_mut(&CpuidKey::subleaf(0x7, 0))
            .ok_or(NormalizeCpuidError::MissingLeaf(7))?;

        // Set the following bits as recommended in kernel doc. These bits are reserved in AMD.
        // - CPUID.07H:EBX[6] (FDP_EXCPTN_ONLY)
        // - CPUID.07H:EBX[13] (Deprecates FPU CS and FPU DS values)
        // https://lore.kernel.org/all/20220322110712.222449-3-pbonzini@redhat.com/
        // https://github.com/torvalds/linux/commit/45016721de3c714902c6f475b705e10ae0bdd801
        set_bit(&mut leaf_7_0.result.ebx, 6, true);
        set_bit(&mut leaf_7_0.result.ebx, 13, true);

        // CPUID.(EAX=07H,ECX=0):ECX[5] (Mnemonic: WAITPKG)
        //
        // WAITPKG indicates support of user wait instructions (UMONITOR, UMWAIT and TPAUSE).
        // - UMONITOR arms address monitoring hardware that checks for store operations on the
        //   specified address range.
        // - UMWAIT instructs the processor to enter an implementation-dependent optimized state
        //   (either a light-weight power/performance optimized state (C0.1 idle state) or an
        //   improved power/performance optimized state (C0.2 idle state)) while monitoring the
        //   address range specified in UMONITOR. The instruction wakes up when the time-stamp
        //   counter reaches or exceeds the implicit EDX:EAX 64-bit input value.
        // - TPAUSE instructs the processor to enter an implementation-dependent optimized state.
        //   The instruction wakes up when the time-stamp counter reaches or exceeds the implict
        //   EDX:EAX 64-bit input value.
        //
        // These instructions may be executed at any privilege level. Even when UMWAIT/TPAUSE are
        // executed within a guest, the *physical* processor enters the requested optimized state.
        // See Intel SDM vol.3 for more details of the behavior of these instructions in VMX
        // non-root operation.
        //
        // MONITOR/MWAIT instructions are the privileged variant of UMONITOR/UMWAIT and are
        // unconditionally emulated as NOP by KVM.
        // https://github.com/torvalds/linux/commit/87c00572ba05aa8c9db118da75c608f47eb10b9e
        //
        // When UMONITOR/UMWAIT/TPAUSE were initially introduced, KVM clears the WAITPKG CPUID bit
        // in KVM_GET_SUPPORTED_CPUID by default, and KVM exposed them to guest only when VMM
        // explicitly set the bit via KVM_SET_CPUID2 API.
        // https://github.com/torvalds/linux/commit/e69e72faa3a0709dd23df6a4ca060a15e99168a1
        // However, since v5.8, if the processor supports "enable user wait and pause" in Intel VMX,
        // KVM_GET_SUPPORTED_CPUID sets the bit to 1 to let VMM know that it is available. So if the
        // returned value is passed to KVM_SET_CPUID2 API as it is, guests are able to execute them.
        // https://github.com/torvalds/linux/commit/0abcc8f65cc23b65bc8d1614cc64b02b1641ed7c
        //
        // Similar to MONITOR/MWAIT, we disable the guest's WAITPKG in order to prevent a guest from
        // executing those instructions and putting a physical processor to an idle state which may
        // lead to an overhead of waking it up when scheduling another guest on it. By clearing the
        // WAITPKG bit in KVM_SET_CPUID2 API, KVM does not set the "enable user wait and pause" bit
        // (bit 26) of the secondary processor-based VM-execution control, which makes guests get
        // #UD when attempting to executing those instructions.
        //
        // Note that the WAITPKG bit is reserved on AMD.
        set_bit(&mut leaf_7_0.result.ecx, 5, false);

        Ok(())
    }

    /// Update performance monitoring entry
    fn update_performance_monitoring_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        let leaf_a = self
            .get_mut(&CpuidKey::leaf(0xA))
            .ok_or(NormalizeCpuidError::MissingLeaf(0xA))?;
        leaf_a.result = CpuidRegisters {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        };
        Ok(())
    }

    /// Update extended topology v2 entry
    ///
    /// CPUID leaf 1FH is a preferred superset to leaf 0xB. Intel recommends using leaf 0x1F when
    /// available rather than leaf 0xB.
    ///
    /// Since we don't use any domains than ones supported in leaf 0xB, we just copy contents of
    /// leaf 0xB to leaf 0x1F.
    fn update_extended_topology_v2_entry(&mut self) {
        // Skip if leaf 0x1F does not exist.
        if self.get(&CpuidKey::leaf(0x1F)).is_none() {
            return;
        }

        for index in 0.. {
            if let Some(subleaf) = self.get(&CpuidKey::subleaf(0xB, index)) {
                self.0
                    .insert(CpuidKey::subleaf(0x1F, index), subleaf.clone());
            } else {
                break;
            }
        }
    }

    fn update_brand_string_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        // Get host brand string.
        let host_brand_string: [u8; BRAND_STRING_LENGTH] = host_brand_string();

        let default_brand_string =
            default_brand_string(host_brand_string).unwrap_or(*DEFAULT_BRAND_STRING);

        self.apply_brand_string(&default_brand_string)
            .map_err(NormalizeCpuidError::ApplyBrandString)?;
        Ok(())
    }
}

/// Error type for [`default_brand_string`].
#[derive(Debug, Eq, PartialEq, thiserror::Error, displaydoc::Display)]
pub enum DefaultBrandStringError {
    /// Missing frequency: {0:?}.
    MissingFrequency([u8; BRAND_STRING_LENGTH]),
    /// Missing space: {0:?}.
    MissingSpace([u8; BRAND_STRING_LENGTH]),
    /// Insufficient space in brand string.
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
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#[inline]
fn default_brand_string(
    // Host brand string.
    // This could look like "Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz".
    // or this could look like "Intel(R) Xeon(R) Platinum 8275CL CPU\0\0\0\0\0\0\0\0\0\0".
    host_brand_string: [u8; BRAND_STRING_LENGTH],
) -> Result<[u8; BRAND_STRING_LENGTH], DefaultBrandStringError> {
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

    use std::collections::BTreeMap;
    use std::ffi::CStr;

    use super::*;
    use crate::cpu_config::x86_64::cpuid::{CpuidEntry, IntelCpuid, KvmCpuidFlags};

    #[test]
    fn default_brand_string_test() {
        let brand_string = b"Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz\0\0";
        let ok_result = default_brand_string(*brand_string);
        let expected = Ok(*b"Intel(R) Xeon(R) Processor @ 3.00GHz\0\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(ok_result, expected);
    }
    #[test]
    fn default_brand_string_test_missing_frequency() {
        let brand_string = b"Intel(R) Xeon(R) Platinum 8275CL CPU @ \0\0\0\0\0\0\0\0\0";
        let result = default_brand_string(*brand_string);
        let expected = Err(DefaultBrandStringError::MissingFrequency(*brand_string));
        assert_eq!(result, expected);
    }
    #[test]
    fn default_brand_string_test_missing_space() {
        let brand_string = b"Intel(R) Xeon(R) Platinum 8275CL CPU @3.00GHz\0\0\0";
        let result = default_brand_string(*brand_string);
        let expected = Err(DefaultBrandStringError::MissingSpace(*brand_string));
        assert_eq!(result, expected);
    }
    #[test]
    fn default_brand_string_test_overflow() {
        let brand_string = b"@ 123456789876543212345678987654321234567898GHz\0";
        let result = default_brand_string(*brand_string);
        assert_eq!(
            result,
            Err(DefaultBrandStringError::Overflow),
            "{:?}",
            result
                .as_ref()
                .map(|s| CStr::from_bytes_until_nul(s).unwrap()),
        );
    }

    #[test]
    fn test_update_extended_feature_flags_entry() {
        let mut cpuid = IntelCpuid(BTreeMap::from([(
            CpuidKey {
                leaf: 0x7,
                subleaf: 0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                ..Default::default()
            },
        )]));

        cpuid.update_extended_feature_flags_entry().unwrap();

        let leaf_7_0 = cpuid
            .get(&CpuidKey {
                leaf: 0x7,
                subleaf: 0,
            })
            .unwrap();
        assert!((leaf_7_0.result.ebx & (1 << 6)) > 0);
        assert!((leaf_7_0.result.ebx & (1 << 13)) > 0);
        assert_eq!((leaf_7_0.result.ecx & (1 << 5)), 0);
    }

    #[test]
    fn test_update_extended_topology_v2_entry_no_leaf_0x1f() {
        let mut cpuid = IntelCpuid(BTreeMap::from([(
            CpuidKey {
                leaf: 0xB,
                subleaf: 0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                ..Default::default()
            },
        )]));

        cpuid.update_extended_topology_v2_entry();

        assert!(
            cpuid
                .get(&CpuidKey {
                    leaf: 0x1F,
                    subleaf: 0,
                })
                .is_none()
        );
    }

    #[test]
    fn test_update_extended_topology_v2_entry() {
        let mut cpuid = IntelCpuid(BTreeMap::from([
            (
                CpuidKey {
                    leaf: 0xB,
                    subleaf: 0,
                },
                CpuidEntry {
                    flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                    result: CpuidRegisters {
                        eax: 0x1,
                        ebx: 0x2,
                        ecx: 0x3,
                        edx: 0x4,
                    },
                },
            ),
            (
                CpuidKey {
                    leaf: 0xB,
                    subleaf: 1,
                },
                CpuidEntry {
                    flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                    result: CpuidRegisters {
                        eax: 0xa,
                        ebx: 0xb,
                        ecx: 0xc,
                        edx: 0xd,
                    },
                },
            ),
            (
                CpuidKey {
                    leaf: 0x1F,
                    subleaf: 0,
                },
                CpuidEntry {
                    flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                    result: CpuidRegisters {
                        eax: 0xFFFFFFFF,
                        ebx: 0xFFFFFFFF,
                        ecx: 0xFFFFFFFF,
                        edx: 0xFFFFFFFF,
                    },
                },
            ),
        ]));

        cpuid.update_extended_topology_v2_entry();

        // Check leaf 0x1F, subleaf 0 is updated.
        let leaf_1f_0 = cpuid
            .get(&CpuidKey {
                leaf: 0x1F,
                subleaf: 0,
            })
            .unwrap();
        assert_eq!(leaf_1f_0.result.eax, 0x1);
        assert_eq!(leaf_1f_0.result.ebx, 0x2);
        assert_eq!(leaf_1f_0.result.ecx, 0x3);
        assert_eq!(leaf_1f_0.result.edx, 0x4);

        // Check lefa 0x1F, subleaf 1 is inserted.
        let leaf_1f_1 = cpuid
            .get(&CpuidKey {
                leaf: 0x1F,
                subleaf: 1,
            })
            .unwrap();
        assert_eq!(leaf_1f_1.result.eax, 0xa);
        assert_eq!(leaf_1f_1.result.ebx, 0xb);
        assert_eq!(leaf_1f_1.result.ecx, 0xc);
        assert_eq!(leaf_1f_1.result.edx, 0xd);
    }
}
