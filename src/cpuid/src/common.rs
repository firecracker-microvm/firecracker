// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::bit_helper::BitHelper;
use crate::cpu_leaf::*;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::CpuId;
#[cfg(target_arch = "x86")]
use std::arch::x86::{CpuidResult, __cpuid_count, __get_cpuid_max};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{CpuidResult, __cpuid_count, __get_cpuid_max};

/// Intel brand string.
pub const VENDOR_ID_INTEL: &[u8; 12] = b"GenuineIntel";
/// AMD brand string.
pub const VENDOR_ID_AMD: &[u8; 12] = b"AuthenticAMD";

/// cpuid related error.
#[derive(Clone, Debug)]
pub enum Error {
    /// The function was called with invalid parameters.
    InvalidParameters(String),
    /// Function not supported on the current architecture.
    NotSupported,
}

/// Extract entry from the cpuid.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn get_cpuid(function: u32, count: u32) -> Result<CpuidResult, Error> {
    // TODO: replace with validation based on `has_cpuid()` when it becomes stable:
    //  https://doc.rust-lang.org/core/arch/x86/fn.has_cpuid.html
    #[cfg(target_env = "sgx")]
    {
        return Err(Error::NotSupported);
    }
    // For x86 the host supports the `cpuid` instruction if SSE is enabled. Otherwise it's hard to check.
    #[cfg(target_arch = "x86")]
    {
        #[cfg(not(target_feature = "sse"))]
        {
            return Err(Error::NotSupported);
        }
    }

    // this is safe because the host supports the `cpuid` instruction
    let max_function = unsafe { __get_cpuid_max(function & leaf_0x80000000::LEAF_NUM).0 };
    if function > max_function {
        return Err(Error::InvalidParameters(format!(
            "Function not supported: 0x{:x}",
            function
        )));
    }

    // this is safe because the host supports the `cpuid` instruction
    let entry = unsafe { __cpuid_count(function, count) };
    if entry.eax == 0 && entry.ebx == 0 && entry.ecx == 0 && entry.edx == 0 {
        return Err(Error::InvalidParameters(format!(
            "Invalid count: {}",
            count
        )));
    }

    Ok(entry)
}

/// Extracts the CPU vendor id from leaf 0x0.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn get_vendor_id_from_host() -> Result<[u8; 12], Error> {
    match get_cpuid(0, 0) {
        Ok(vendor_entry) => {
            let bytes: [u8; 12] = unsafe {
                std::mem::transmute([vendor_entry.ebx, vendor_entry.edx, vendor_entry.ecx])
            };
            Ok(bytes)
        }
        Err(e) => Err(e),
    }
}

/// Extracts the CPU vendor id from leaf 0x0.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn get_vendor_id_from_cpuid(cpuid: &CpuId) -> Result<[u8; 12], Error> {
    // Search for vendor id entry.
    for entry in cpuid.as_slice().iter() {
        if entry.function == 0 && entry.index == 0 {
            let cpu_vendor_id: [u8; 12] =
                unsafe { std::mem::transmute([entry.ebx, entry.edx, entry.ecx]) };
            return Ok(cpu_vendor_id);
        }
    }

    Err(Error::NotSupported)
}

/// Validates that the provided CPUID belongs to a CPU of the same
/// model as the host's.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
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

#[cfg(test)]
pub mod tests {
    use crate::common::*;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
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
        match get_cpuid(topoext_fn, 0) {
            Ok(topoext_entry) => {
                assert!(topoext_entry.eax != 0);
            }
            _ => panic!("Wrong behavior"),
        }

        // check that get_cpuid returns correct error for invalid `function`
        match get_cpuid(0x9000_0000, 0) {
            Err(Error::InvalidParameters(s)) => {
                assert!(s == "Function not supported: 0x90000000");
            }
            _ => panic!("Wrong behavior"),
        }

        // check that get_cpuid returns correct error for invalid `count`
        match get_cpuid(topoext_fn, 100) {
            Err(Error::InvalidParameters(s)) => {
                assert!(s == "Invalid count: 100");
            }
            _ => panic!("Wrong behavior"),
        }
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
