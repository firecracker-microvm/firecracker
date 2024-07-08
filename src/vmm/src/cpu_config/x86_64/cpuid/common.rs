// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::restriction)]

/// Error type for [`get_cpuid`].
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum GetCpuidError {
    /// Un-supported leaf: {0}
    UnsupportedLeaf(u32),
    /// Invalid subleaf: {0}
    InvalidSubleaf(u32),
}

/// Extract entry from the cpuid.
///
/// # Errors
///
/// - When the given `leaf` is more than `max_leaf` supported by CPUID.
/// - When the CPUID leaf `sub-leaf` is invalid (all its register equal 0).
pub fn get_cpuid(leaf: u32, subleaf: u32) -> Result<std::arch::x86_64::CpuidResult, GetCpuidError> {
    let max_leaf =
        // JUSTIFICATION: There is no safe alternative.
        // SAFETY: This is safe because the host supports the `cpuid` instruction
        unsafe { std::arch::x86_64::__get_cpuid_max(leaf & 0x8000_0000).0 };
    if leaf > max_leaf {
        return Err(GetCpuidError::UnsupportedLeaf(leaf));
    }

    let entry = crate::cpu_config::x86_64::cpuid::cpuid_count(leaf, subleaf);
    if entry.eax == 0 && entry.ebx == 0 && entry.ecx == 0 && entry.edx == 0 {
        return Err(GetCpuidError::InvalidSubleaf(subleaf));
    }

    Ok(entry)
}

/// Extracts the CPU vendor id from leaf 0x0.
///
/// # Errors
///
/// When CPUID leaf 0 is not supported.
pub fn get_vendor_id_from_host() -> Result<[u8; 12], GetCpuidError> {
    // JUSTIFICATION: There is no safe alternative.
    // SAFETY: Always safe.
    get_cpuid(0, 0).map(|vendor_entry| unsafe {
        // The ordering of the vendor string is ebx,edx,ecx this is not a mistake.
        std::mem::transmute::<[u32; 3], [u8; 12]>([
            vendor_entry.ebx,
            vendor_entry.edx,
            vendor_entry.ecx,
        ])
    })
}

/// Returns MSRs to be saved based on CPUID features that are enabled.
pub(crate) fn msrs_to_save_by_cpuid(cpuid: &kvm_bindings::CpuId) -> Vec<u32> {
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

    let mut msrs = Vec::new();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_cpuid_unsupported_leaf() {
        let max_leaf =
            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: This is safe because the host supports the `cpuid` instruction
            unsafe { std::arch::x86_64::__get_cpuid_max(0).0 };
        let max_leaf_plus_one = max_leaf + 1;

        assert_eq!(
            get_cpuid(max_leaf_plus_one, 0),
            Err(GetCpuidError::UnsupportedLeaf(max_leaf_plus_one))
        );
    }
}
