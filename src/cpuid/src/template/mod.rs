// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Contains Intel specific templates.
pub mod intel;

use std::collections::HashSet;

use arch_gen::x86::msr_index::*;
use kvm_bindings::CpuId;

use crate::common::{get_vendor_id_from_cpuid, VENDOR_ID_INTEL};
use crate::cpuid_is_feature_set;
use crate::transformer::Error;

/// Returns MSRs to be saved based on the CPUID features that are enabled.
fn cpuid_to_msrs_to_save(cpuid: &CpuId) -> HashSet<u32> {
    use crate::cpu_leaf::*;

    let mut msrs = HashSet::new();

    // Macro used for easy definition of CPUID-MSR dependencies.
    macro_rules! cpuid_msr_dep {
        ($leaf:expr, $index:expr, $reg:tt, $feature_bit:expr, $msr:expr) => {
            if cpuid_is_feature_set!(cpuid, $leaf, $index, $reg, $feature_bit) {
                msrs.extend($msr)
            }
        };
    }

    // MPX bit enables MSR_IA32_BNDCFGS.
    cpuid_msr_dep!(
        0x7,
        0,
        ebx,
        leaf_0x7::index0::ebx::MPX_BITINDEX,
        [MSR_IA32_BNDCFGS]
    );

    // IA32_MTRR_PHYSBASEn, IA32_MTRR_PHYSMASKn.
    cpuid_msr_dep!(0x1, 0, edx, leaf_0x1::edx::MTRR_BITINDEX, 0x200..0x210);

    // Other MTRR MSRs.
    cpuid_msr_dep!(
        0x1,
        0,
        edx,
        leaf_0x1::edx::MTRR_BITINDEX,
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
    cpuid_msr_dep!(0x1, 0, edx, leaf_0x1::edx::MCE_BITINDEX, 0x400..0x480);

    msrs
}

/// Returns MSRs to be saved based on CPUID features that are enabled.
pub fn msrs_to_save_by_cpuid(cpuid: &CpuId) -> Result<HashSet<u32>, Error> {
    let vendor_id = get_vendor_id_from_cpuid(cpuid).map_err(|_| Error::InvalidVendor)?;
    match &vendor_id {
        VENDOR_ID_INTEL => Ok(cpuid_to_msrs_to_save(cpuid)),
        _ => {
            // We don't have MSR-CPUID dependencies set for other vendors yet.
            Ok(HashSet::new())
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_msrs_to_save_by_cpuid_empty() {
        // No CPUID entries are provided.
        let entrs = [];
        let cpuid = CpuId::from_entries(&entrs).unwrap();

        let msrs = cpuid_to_msrs_to_save(&cpuid);

        // No MSRs are expected to match the CPUID features.
        assert!(msrs.is_empty());
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_msrs_to_save_by_cpuid_one() {
        use kvm_bindings::kvm_cpuid_entry2;

        use crate::cpu_leaf::leaf_0x7;

        // One CPUID entry with MPX feature flag is provided
        // that causes MSR_IA32_BNDCFGS to be pulled in.
        let entrs = [kvm_cpuid_entry2 {
            function: 0x7,
            index: 0x0,
            ebx: 1 << leaf_0x7::index0::ebx::MPX_BITINDEX,
            ..Default::default()
        }];
        let cpuid = CpuId::from_entries(&entrs).unwrap();

        let msrs = cpuid_to_msrs_to_save(&cpuid);

        // One MSR is expected to be pulled in by the CPUID feature provided.
        assert_eq!(msrs.len(), 1);

        // The expected MSR is MSR_IA32_BNDCFGS.
        assert!(msrs.contains(&MSR_IA32_BNDCFGS));
    }
}
