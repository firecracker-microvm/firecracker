// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::module_name_repetitions,
    clippy::unreadable_literal,
    clippy::unsafe_derive_deserialize
)]

/// CPUID normalize implementation.
mod normalize;

pub use normalize::{DeterministicCacheError, NormalizeCpuidError};

use super::{CpuidEntry, CpuidKey, CpuidRegisters, CpuidTrait, KvmCpuidFlags};

/// A structure matching the Intel CPUID specification as described in
/// [Intel® 64 and IA-32 Architectures Software Developer's Manual Combined Volumes 2A, 2B, 2C, and 2D: Instruction Set Reference, A-Z](https://cdrdv2.intel.com/v1/dl/getContent/671110)
/// .
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IntelCpuid(pub std::collections::BTreeMap<CpuidKey, CpuidEntry>);

impl CpuidTrait for IntelCpuid {
    /// Gets a given sub-leaf.
    #[inline]
    fn get(&self, key: &CpuidKey) -> Option<&CpuidEntry> {
        self.0.get(key)
    }

    /// Gets a given sub-leaf.
    #[inline]
    fn get_mut(&mut self, key: &CpuidKey) -> Option<&mut CpuidEntry> {
        self.0.get_mut(key)
    }
}

/// Returns MSRs to be saved based on the Intel CPUID features that are enabled.
#[must_use]
pub(crate) fn intel_msrs_to_save_by_cpuid(
    cpuid: &kvm_bindings::CpuId,
) -> std::collections::HashSet<u32> {
    /// Memory Protection Extensions
    const MPX_BITINDEX: u32 = 14;

    /// Memory Type Range Registers
    const MTRR_BITINDEX: u32 = 12;

    /// Memory Check Exception
    const MCE_BITINDEX: u32 = 7;

    /// Scans through the CPUID and determines if a feature bit is set.
    // TODO: This currently involves a linear search which would be improved
    //       when we'll refactor the cpuid crate.
    macro_rules! cpuid_is_feature_set {
        ($cpuid:ident, $leaf:expr, $index:expr, $reg:tt, $feature_bit:expr) => {{
            let mut res = false;
            for entry in $cpuid.as_slice().iter() {
                if entry.function == $leaf && entry.index == $index {
                    if entry.$reg & (1 << $feature_bit) != 0 {
                        res = true;
                        break;
                    }
                }
            }
            res
        }};
    }

    let mut msrs = std::collections::HashSet::new();

    // Macro used for easy definition of CPUID-MSR dependencies.
    macro_rules! cpuid_msr_dep {
        ($leaf:expr, $index:expr, $reg:tt, $feature_bit:expr, $msr:expr) => {
            if cpuid_is_feature_set!(cpuid, $leaf, $index, $reg, $feature_bit) {
                msrs.extend($msr)
            }
        };
    }

    // TODO: Add more dependencies.
    cpuid_msr_dep!(
        0x7,
        0,
        ebx,
        MPX_BITINDEX,
        [crate::arch_gen::x86::msr_index::MSR_IA32_BNDCFGS]
    );

    // IA32_MTRR_PHYSBASEn, IA32_MTRR_PHYSMASKn
    cpuid_msr_dep!(0x1, 0, edx, MTRR_BITINDEX, 0x200..0x210);

    // Other MTRR MSRs
    cpuid_msr_dep!(
        0x1,
        0,
        edx,
        MTRR_BITINDEX,
        [
            0x250, // IA32_MTRR_FIX64K_00000
            0x258, // IA32_MTRR_FIX16K_80000
            0x259, // IA32_MTRR_FIX16K_A0000
            0x268, // IA32_MTRR_FIX4K_C0000
            0x269, // IA32_MTRR_FIX4K_C8000
            0x26a, // IA32_MTRR_FIX4K_D0000
            0x26b, // IA32_MTRR_FIX4K_D8000
            0x26c, // IA32_MTRR_FIX4K_E0000
            0x26d, // IA32_MTRR_FIX4K_E8000
            0x26e, // IA32_MTRR_FIX4K_F0000
            0x26f, // IA32_MTRR_FIX4K_F8000
            0x277, // IA32_PAT
            0x2ff  // IA32_MTRR_DEF_TYPE
        ]
    );

    // MCE MSRs
    // We are saving 32 MCE banks here as this is the maximum number supported by KVM
    // and configured by default.
    // The physical number of the MCE banks depends on the CPU.
    // The number of emulated MCE banks can be configured via KVM_X86_SETUP_MCE.
    cpuid_msr_dep!(0x1, 0, edx, MCE_BITINDEX, 0x400..0x480);

    msrs
}

impl From<kvm_bindings::CpuId> for IntelCpuid {
    #[inline]
    fn from(kvm_cpuid: kvm_bindings::CpuId) -> Self {
        let map = kvm_cpuid
            .as_slice()
            .iter()
            .map(|entry| {
                (
                    CpuidKey {
                        leaf: entry.function,
                        subleaf: entry.index,
                    },
                    CpuidEntry {
                        flags: KvmCpuidFlags(entry.flags),
                        result: CpuidRegisters {
                            eax: entry.eax,
                            ebx: entry.ebx,
                            ecx: entry.ecx,
                            edx: entry.edx,
                        },
                    },
                )
            })
            .collect();
        Self(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get() {
        let cpuid = IntelCpuid(std::collections::BTreeMap::new());
        assert_eq!(
            cpuid.get(&CpuidKey {
                leaf: 0,
                subleaf: 0
            }),
            None
        );
    }

    #[test]
    fn get_mut() {
        let mut cpuid = IntelCpuid(std::collections::BTreeMap::new());
        assert_eq!(
            cpuid.get_mut(&CpuidKey {
                leaf: 0,
                subleaf: 0
            }),
            None
        );
    }
}
