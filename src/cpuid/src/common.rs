// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

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
}
