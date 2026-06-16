// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::restriction)]

use crate::arch::x86_64::generated::msr_index::{
    MSR_IA32_BNDCFGS, MSR_IA32_CR_PAT, MSR_IA32_INT_SSP_TAB, MSR_IA32_PL0_SSP, MSR_IA32_PL1_SSP,
    MSR_IA32_PL2_SSP, MSR_IA32_PL3_SSP, MSR_IA32_S_CET, MSR_IA32_U_CET, MSR_MTRRdefType,
    MSR_MTRRfix4K_C0000, MSR_MTRRfix4K_C8000, MSR_MTRRfix4K_D0000, MSR_MTRRfix4K_D8000,
    MSR_MTRRfix4K_E0000, MSR_MTRRfix4K_E8000, MSR_MTRRfix4K_F0000, MSR_MTRRfix4K_F8000,
    MSR_MTRRfix16K_80000, MSR_MTRRfix16K_A0000, MSR_MTRRfix64K_00000,
};

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
    // TODO: Remove `unsafe` block when Kani nightly toolchain is updated to be >=1.94.0
    #[allow(unused_unsafe)]
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

    /// Shadow Stack (CET_SS), CPUID.(EAX=07H,ECX=0):ECX[bit 7]
    const SHSTK_BITINDEX: u32 = 7;

    /// Indirect Branch Tracking (CET_IBT), CPUID.(EAX=07H,ECX=0):EDX[bit 20]
    const IBT_BITINDEX: u32 = 20;

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
    cpuid_msr_dep!(0x7, 0, ebx, MPX_BITINDEX, [MSR_IA32_BNDCFGS]);

    // IA32_MTRR_PHYSBASEn, IA32_MTRR_PHYSMASKn
    cpuid_msr_dep!(0x1, 0, edx, MTRR_BITINDEX, 0x200..0x210);

    // Other MTRR MSRs
    cpuid_msr_dep!(
        0x1,
        0,
        edx,
        MTRR_BITINDEX,
        [
            MSR_MTRRfix64K_00000,
            MSR_MTRRfix16K_80000,
            MSR_MTRRfix16K_A0000,
            MSR_MTRRfix4K_C0000,
            MSR_MTRRfix4K_C8000,
            MSR_MTRRfix4K_D0000,
            MSR_MTRRfix4K_D8000,
            MSR_MTRRfix4K_E0000,
            MSR_MTRRfix4K_E8000,
            MSR_MTRRfix4K_F0000,
            MSR_MTRRfix4K_F8000,
            MSR_IA32_CR_PAT,
            MSR_MTRRdefType,
        ]
    );

    // MCE MSRs
    // We are saving 32 MCE banks here as this is the maximum number supported by KVM
    // and configured by default.
    // The physical number of the MCE banks depends on the CPU.
    // The number of emulated MCE banks can be configured via KVM_X86_SETUP_MCE.
    cpuid_msr_dep!(0x1, 0, edx, MCE_BITINDEX, 0x400..0x480);

    // Control-flow Enforcement Technology (CET).
    //
    // On host kernels >= 6.18, KVM enumerates the CET MSRs in
    // KVM_GET_MSR_INDEX_LIST when the guest is configured with shadow stacks
    // (SHSTK) and/or indirect branch tracking (IBT). Their values live in the
    // CET_U / CET_S *supervisor* XSTATE components, which KVM masks out of the
    // KVM_GET_XSAVE2 uABI buffer (only user/XCR0 features are exported). Unlike
    // most FPU state they are therefore NOT captured by the saved XSAVE area and
    // must be serialized as MSRs, otherwise they are silently lost across a
    // snapshot/restore.
    //
    // IA32_{U,S}_CET exist if either SHSTK or IBT is supported; the SSP MSRs
    // require SHSTK (IA32_INT_SSP_TAB additionally requires 64-bit mode, which
    // Firecracker guests always have). This mirrors KVM's own gating in
    // __kvm_{get,set}_msr().
    //
    // NOTE: correctly reading the XSAVE-managed CET MSRs (IA32_U_CET and
    // IA32_PL{0..3}_SSP) via KVM_GET_MSRS requires kernel commit e44eb58334bb
    // ("KVM: x86: Load guest FPU state when access XSAVE-managed MSRs"), first
    // released in 6.18.
    let shstk = cpuid_is_feature_set!(cpuid, 0x7, 0, ecx, SHSTK_BITINDEX);
    let ibt = cpuid_is_feature_set!(cpuid, 0x7, 0, edx, IBT_BITINDEX);
    if shstk || ibt {
        msrs.extend([MSR_IA32_U_CET, MSR_IA32_S_CET]);
    }
    if shstk {
        msrs.extend([
            MSR_IA32_PL0_SSP,
            MSR_IA32_PL1_SSP,
            MSR_IA32_PL2_SSP,
            MSR_IA32_PL3_SSP,
            MSR_IA32_INT_SSP_TAB,
        ]);
    }

    msrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_cpuid_unsupported_leaf() {
        // TODO: Remove `unsafe` block when Kani nightly toolchain is updated to be >=1.94.0
        #[allow(unused_unsafe)]
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

    /// Builds a CPUID containing only leaf 0x7 / subleaf 0 with the given ECX/EDX.
    fn leaf7_cpuid(ecx: u32, edx: u32) -> kvm_bindings::CpuId {
        kvm_bindings::CpuId::from_entries(&[kvm_bindings::kvm_cpuid_entry2 {
            function: 0x7,
            index: 0,
            ecx,
            edx,
            ..Default::default()
        }])
        .unwrap()
    }

    const CET_SSP_MSRS: [u32; 5] = [
        MSR_IA32_PL0_SSP,
        MSR_IA32_PL1_SSP,
        MSR_IA32_PL2_SSP,
        MSR_IA32_PL3_SSP,
        MSR_IA32_INT_SSP_TAB,
    ];

    #[test]
    fn cet_msrs_saved_when_shstk_enabled() {
        // SHSTK = CPUID.(EAX=07H,ECX=0):ECX[bit 7].
        let msrs = msrs_to_save_by_cpuid(&leaf7_cpuid(1 << 7, 0));
        for msr in [MSR_IA32_U_CET, MSR_IA32_S_CET]
            .into_iter()
            .chain(CET_SSP_MSRS)
        {
            assert!(msrs.contains(&msr), "missing CET MSR {msr:#x}");
        }
    }

    #[test]
    fn cet_msrs_saved_when_only_ibt_enabled() {
        // IBT = CPUID.(EAX=07H,ECX=0):EDX[bit 20]. Without SHSTK only the
        // {U,S}_CET config MSRs are valid; the SSP MSRs must NOT be requested, as
        // KVM rejects KVM_GET_MSRS for them which would fail the whole snapshot.
        let msrs = msrs_to_save_by_cpuid(&leaf7_cpuid(0, 1 << 20));
        assert!(msrs.contains(&MSR_IA32_U_CET));
        assert!(msrs.contains(&MSR_IA32_S_CET));
        for msr in CET_SSP_MSRS {
            assert!(!msrs.contains(&msr), "unexpected CET SSP MSR {msr:#x}");
        }
    }

    #[test]
    fn cet_msrs_absent_when_unsupported() {
        let msrs = msrs_to_save_by_cpuid(&leaf7_cpuid(0, 0));
        for msr in [MSR_IA32_U_CET, MSR_IA32_S_CET]
            .into_iter()
            .chain(CET_SSP_MSRS)
        {
            assert!(!msrs.contains(&msr), "unexpected CET MSR {msr:#x}");
        }
    }
}
