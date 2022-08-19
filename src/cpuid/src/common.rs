// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(missing_docs, dead_code)]
#[cfg(target_arch = "x86")]
use std::arch::x86::{CpuidResult, __cpuid_count, __get_cpuid_max};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{CpuidResult, __cpuid_count, __get_cpuid_max};
use std::fmt;

#[cfg(target_arch = "x86_64")]
use kvm_bindings::CpuId;

use crate::bit_helper::BitHelper;

#[macro_use]
macro_rules! bit_range {
    ($msb_index:expr, $lsb_index:expr) => {
        crate::bit_helper::BitRange {
            msb_index: $msb_index,
            lsb_index: $lsb_index,
        }
    };
}

// Basic CPUID Information
pub mod leaf_0x1 {
    pub const LEAF_NUM: u32 = 0x1;

    pub mod eax {
        use crate::bit_helper::BitRange;

        pub const EXTENDED_FAMILY_ID_BITRANGE: BitRange = bit_range!(27, 20);
        pub const EXTENDED_PROCESSOR_MODEL_BITRANGE: BitRange = bit_range!(19, 16);
        pub const PROCESSOR_TYPE_BITRANGE: BitRange = bit_range!(13, 12);
        pub const PROCESSOR_FAMILY_BITRANGE: BitRange = bit_range!(11, 8);
        pub const PROCESSOR_MODEL_BITRANGE: BitRange = bit_range!(7, 4);
        pub const STEPPING_BITRANGE: BitRange = bit_range!(3, 0);
    }

    pub mod ebx {
        use crate::bit_helper::BitRange;

        // The bit-range containing the (fixed) default APIC ID.
        pub const APICID_BITRANGE: BitRange = bit_range!(31, 24);
        // The bit-range containing the logical processor count.
        pub const CPU_COUNT_BITRANGE: BitRange = bit_range!(23, 16);
        // The bit-range containing the number of bytes flushed when executing CLFLUSH.
        pub const CLFLUSH_SIZE_BITRANGE: BitRange = bit_range!(15, 8);
    }

    pub mod ecx {
        // DTES64 = 64-bit debug store
        pub const DTES64_BITINDEX: u32 = 2;
        // MONITOR = Monitor/MWAIT
        pub const MONITOR_BITINDEX: u32 = 3;
        // CPL Qualified Debug Store
        pub const DS_CPL_SHIFT: u32 = 4;
        // Virtual Machine Extensions
        pub const VMX_BITINDEX: u32 = 5;
        // 6 = SMX (Safer Mode Extensions)
        pub const SMX_BITINDEX: u32 = 6;
        // 7 = EIST (Enhanced Intel SpeedStep® technology)
        pub const EIST_BITINDEX: u32 = 7;
        // TM2 = Thermal Monitor 2
        pub const TM2_BITINDEX: u32 = 8;
        // CNXT_ID = L1 Context ID (L1 data cache can be set to adaptive/shared mode)
        pub const CNXT_ID_BITINDEX: u32 = 10;
        // SDBG (cpu supports IA32_DEBUG_INTERFACE MSR for silicon debug)
        pub const SDBG_BITINDEX: u32 = 11;
        pub const FMA_BITINDEX: u32 = 12;
        // XTPR_UPDATE = xTPR Update Control
        pub const XTPR_UPDATE_BITINDEX: u32 = 14;
        // PDCM = Perfmon and Debug Capability
        pub const PDCM_BITINDEX: u32 = 15;
        // 18 = DCA Direct Cache Access (prefetch data from a memory mapped device)
        pub const DCA_BITINDEX: u32 = 18;
        pub const MOVBE_BITINDEX: u32 = 22;
        pub const TSC_DEADLINE_TIMER_BITINDEX: u32 = 24;
        pub const OSXSAVE_BITINDEX: u32 = 27;
        // Cpu is running on a hypervisor.
        pub const HYPERVISOR_BITINDEX: u32 = 31;
    }

    pub mod edx {
        pub const PSN_BITINDEX: u32 = 18; // Processor Serial Number
        pub const SSE42_BITINDEX: u32 = 20; // SSE 4.2
        pub const DS_BITINDEX: u32 = 21; // Debug Store.
        pub const ACPI_BITINDEX: u32 = 22; // Thermal Monitor and Software Controlled Clock Facilities.
        pub const SS_BITINDEX: u32 = 27; // Self Snoop
        pub const HTT_BITINDEX: u32 = 28; // Max APIC IDs reserved field is valid
    }
}
// Deterministic Cache Parameters Leaf
pub mod leaf_0x4 {
    pub const LEAF_NUM: u32 = 0x4;

    pub mod eax {
        use crate::bit_helper::BitRange;

        pub const CACHE_LEVEL_BITRANGE: BitRange = bit_range!(7, 5);
        pub const MAX_CPUS_PER_CORE_BITRANGE: BitRange = bit_range!(25, 14);
        pub const MAX_CORES_PER_PACKAGE_BITRANGE: BitRange = bit_range!(31, 26);
    }
}
mod leaf_0x80000000 {
    pub const LEAF_NUM: u32 = 0x8000_0000;

    pub mod eax {
        use crate::bit_helper::BitRange;

        pub const LARGEST_EXTENDED_FN_BITRANGE: BitRange = bit_range!(31, 0);
    }
}

/// Intel brand string.
pub const VENDOR_ID_INTEL: &[u8; 12] = b"GenuineIntel";
/// AMD brand string.
pub const VENDOR_ID_AMD: &[u8; 12] = b"AuthenticAMD";

/// cpuid related error.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The function was called with invalid parameters.
    #[error("The function was called with invalid parameters.")]
    InvalidParameters(String),
    /// Function not supported on the current architecture.
    #[error("Function not supported on the current architecture.")]
    NotSupported,
}

#[cfg(any(
    all(target_arch = "x86", target_feature = "sse", not(target_env = "sgx")),
    all(target_arch = "x86_64", not(target_env = "sgx"))
))]
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
// TODO: Replace checking of CPUID avaiblity with `x86` and `x86_64` check and
// [`std::arch_x86_64::has_cpuid()`] when this is stabilized. CPUID is supported when:
// - We are on an x86 archtecture with `sse` enabled and `sgx disabled`.
// - We are on an x86_64 architecture with `sgx` disabled
#[cfg(any(
    all(target_arch = "x86", target_feature = "sse", not(target_env = "sgx")),
    all(target_arch = "x86_64", not(target_env = "sgx"))
))]
pub fn get_cpuid(leaf: u32, subleaf: u32) -> Result<CpuidResult, GetCpuidError> {
    // This is safe because the host supports the `cpuid` instruction
    let max_leaf = unsafe { __get_cpuid_max(leaf & leaf_0x80000000::LEAF_NUM).0 };
    if leaf > max_leaf {
        return Err(GetCpuidError::UnsupportedLeaf(leaf));
    }

    // This is safe because the host supports the `cpuid` instruction
    let entry = unsafe { __cpuid_count(leaf, subleaf) };
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
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn get_vendor_id_from_host() -> Result<[u8; 12], GetCpuidError> {
    get_cpuid(0, 0).map(|vendor_entry| unsafe {
        std::mem::transmute::<[u32; 3], [u8; 12]>([
            vendor_entry.ebx,
            vendor_entry.edx,
            vendor_entry.ecx,
        ])
    })
}

/// Error type for [`get_vendor_id_from_cpuid`].
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf0NotFoundInCpuid;
impl fmt::Display for Leaf0NotFoundInCpuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Leaf 0 not found in given `CpuId`.")
    }
}
impl std::error::Error for Leaf0NotFoundInCpuid {}

/// Extracts the CPU vendor id from leaf 0x0.
///
/// # Errors
///
/// When CPUID leaf 0 is not supported.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn get_vendor_id_from_cpuid(cpuid: &CpuId) -> Result<[u8; 12], Leaf0NotFoundInCpuid> {
    // Search for vendor id entry.
    let entry_opt = cpuid
        .as_slice()
        .iter()
        .find(|entry| entry.function == 0 && entry.index == 0);
    match entry_opt {
        Some(entry) => {
            let cpu_vendor_id: [u8; 12] =
                unsafe { std::mem::transmute([entry.ebx, entry.edx, entry.ecx]) };
            Ok(cpu_vendor_id)
        }
        None => Err(Leaf0NotFoundInCpuid),
    }
}

/// Validates that the provided CPUID belongs to a CPU of the same
/// model as the host's.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[must_use]
pub fn is_same_model(cpuid: &CpuId) -> bool {
    // Try to get the vendor IDs from the host and the CPUID struct.
    if let (Ok(host_vendor_id), Ok(cpuid_vendor_id)) =
        (get_vendor_id_from_host(), get_vendor_id_from_cpuid(cpuid))
    {
        // If the vendor IDs aren't the same, the CPUs are not identical.
        if host_vendor_id != cpuid_vendor_id {
            return false;
        }
    } else {
        // This only fails when CPUID is not supported, in which case
        // we can't tell if the CPUs are identical.
        return false;
    }

    // Try to get the feature information leaf from the host CPUID.
    let host_feature_info_leaf = get_cpuid(leaf_0x1::LEAF_NUM, 0);

    // The relevant information for this comparison is in the EAX register.
    let host_feature_info_leaf_eax = match host_feature_info_leaf {
        Ok(leaf) => leaf.eax,
        Err(_) => {
            // If this fails, we can't tell if the CPUs are identical.
            return false;
        }
    };

    // Search for the entry for leaf0x1.
    let feature_info_leaf = cpuid
        .as_slice()
        .iter()
        .find(|entry| entry.function == leaf_0x1::LEAF_NUM);

    // The relevant information is in EAX.
    let feature_info_leaf_eax = match feature_info_leaf {
        Some(leaf) => leaf.eax,
        None => {
            // Fail fast if we can't retrieve the relevant
            // information from CPUID.
            return false;
        }
    };

    // Validate that all of these properties are the same.
    for elem in &[
        leaf_0x1::eax::EXTENDED_FAMILY_ID_BITRANGE,
        leaf_0x1::eax::EXTENDED_PROCESSOR_MODEL_BITRANGE,
        leaf_0x1::eax::PROCESSOR_FAMILY_BITRANGE,
        leaf_0x1::eax::PROCESSOR_MODEL_BITRANGE,
        leaf_0x1::eax::STEPPING_BITRANGE,
    ] {
        if feature_info_leaf_eax.read_bits_in_range(elem)
            != host_feature_info_leaf_eax.read_bits_in_range(elem)
        {
            return false;
        }
    }

    true
}
// Extended Cache Topology Leaf
pub mod leaf_0x8000001d {
    use crate::bit_helper::BitRange;
    pub const LEAF_NUM: u32 = 0x8000_001d;

    pub const CACHE_LEVEL_BITRANGE: BitRange = bit_range!(7, 5);
    pub const MAX_CPUS_PER_CORE_BITRANGE: BitRange = bit_range!(25, 14);
}

#[allow(clippy::missing_panics_doc)]
#[cfg(test)]
pub mod tests {
    use super::*;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[must_use]
    pub fn get_topoext_fn() -> u32 {
        let vendor_id = get_vendor_id_from_host();
        assert!(vendor_id.is_ok());
        let function = match &vendor_id.ok().unwrap() {
            VENDOR_ID_INTEL => leaf_0x4::LEAF_NUM,
            VENDOR_ID_AMD => leaf_0x8000001d::LEAF_NUM,
            _ => 0,
        };
        assert!(function != 0);

        function
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_get_cpu_id() {
        // get_cpu_id should work correctly here
        let topoext_fn = get_topoext_fn();

        // check that get_cpuid works for valid parameters
        assert!(matches!(
            get_cpuid(topoext_fn, 0),
            Ok(topoext_entry) if topoext_entry.eax != 0));

        // check that get_cpuid returns correct error for invalid `function`
        assert!(matches!(
            get_cpuid(0x9000_0000, 0),
            Err(GetCpuidError::UnsupportedLeaf(0x9000_0000))
        ));

        // check that get_cpuid returns correct error for invalid `count`
        assert!(matches!(
            get_cpuid(topoext_fn, 100),
            Err(GetCpuidError::InvalidSubleaf(100))
        ));
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_get_vendor_id() {
        let vendor_id = get_vendor_id_from_host();
        assert!(vendor_id.is_ok());
        matches!(&vendor_id.ok().unwrap(), VENDOR_ID_INTEL | VENDOR_ID_AMD);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_is_same_model() {
        let mut curr_cpuid = CpuId::new(2).unwrap();

        // Add the vendor ID leaf.
        let vendor = get_cpuid(0x0, 0).unwrap();
        curr_cpuid.as_mut_slice()[0].function = 0x0;
        curr_cpuid.as_mut_slice()[0].index = 0;
        curr_cpuid.as_mut_slice()[0].ebx = vendor.ebx;
        curr_cpuid.as_mut_slice()[0].ecx = vendor.ecx;
        curr_cpuid.as_mut_slice()[0].edx = vendor.edx;

        // Add the feature info leaf.
        let feature_info = get_cpuid(0x1, 0).unwrap();
        curr_cpuid.as_mut_slice()[1].function = 0x1;
        curr_cpuid.as_mut_slice()[1].index = 0;
        curr_cpuid.as_mut_slice()[1].eax = feature_info.eax;

        assert!(is_same_model(&curr_cpuid));

        let mut diff_vendor_cpuid = curr_cpuid.clone();
        for mut entry in diff_vendor_cpuid.as_mut_slice() {
            if entry.function == 0x0 && entry.index == 0 {
                entry.ebx = 0xFFFF_FFFF;
            }
        }
        assert!(!is_same_model(&diff_vendor_cpuid));

        let mut diff_feature_cpuid = curr_cpuid;
        for mut entry in diff_feature_cpuid.as_mut_slice() {
            if entry.function == 0x1 && entry.index == 0 {
                entry.eax ^= 0x1;
            }
        }
        assert!(!is_same_model(&diff_feature_cpuid));
    }
}
