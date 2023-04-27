// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::restriction)]

use super::CpuidTrait;
use crate::guest_config::cpuid::intel::intel_msrs_to_save_by_cpuid;

/// Error type for [`get_cpuid`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GetCpuidError {
    /// Invalid leaf.
    #[error("Un-supported leaf: {0}")]
    UnsupportedLeaf(u32),
    /// Invalid subleaf.
    #[error("Invalid subleaf: {0}")]
    InvalidSubleaf(u32),
}

/// Extract entry from the cpuid.
///
/// # Errors
///
/// - When the given `leaf` is more than `max_leaf` supported by CPUID.
/// - When the the CPUID leaf `sub-leaf` is invalid (all its register equal 0).
pub fn get_cpuid(leaf: u32, subleaf: u32) -> Result<std::arch::x86_64::CpuidResult, GetCpuidError> {
    let max_leaf =
        // JUSTIFICATION: There is no safe alternative.
        // SAFETY: This is safe because the host supports the `cpuid` instruction
        unsafe { std::arch::x86_64::__get_cpuid_max(leaf & 0x8000_0000).0 };
    if leaf > max_leaf {
        return Err(GetCpuidError::UnsupportedLeaf(leaf));
    }

    let entry = super::cpuid_count(leaf, subleaf);
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

/// Error type for [`msrs_to_save_by_cpuid`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Leaf 0 not found in given `CpuId`.")]
pub struct Leaf0NotFoundInCpuid;

/// Returns MSRs to be saved based on CPUID features that are enabled.
///
/// # Errors
///
/// When CPUID leaf 0 is not supported.
pub fn msrs_to_save_by_cpuid(
    cpuid: &kvm_bindings::CpuId,
) -> Result<std::collections::HashSet<u32>, Leaf0NotFoundInCpuid> {
    let vendor_id = cpuid.vendor_id().ok_or(Leaf0NotFoundInCpuid)?;
    match &vendor_id {
        super::VENDOR_ID_INTEL => Ok(intel_msrs_to_save_by_cpuid(cpuid)),
        // We don't have MSR-CPUID dependencies set for other vendors yet.
        _ => Ok(std::collections::HashSet::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_cpuid_invalid_leaf() {
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
