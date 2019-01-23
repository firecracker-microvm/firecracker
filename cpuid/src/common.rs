// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86")]
use std::arch::x86::CpuidResult;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::CpuidResult;

#[cfg(target_arch = "x86")]
use std::arch::x86::__get_cpuid_max;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__get_cpuid_max;

#[cfg(target_arch = "x86")]
use std::arch::x86::__cpuid_count;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid_count;

use kvm::CpuId;
use kvm_bindings::kvm_cpuid_entry2;

const INTEL: &[u8; 12] = b"GenuineIntel";
const AMD: &[u8; 12] = b"AuthenticAMD";

const EXT_FUNCTION: u32 = 0x80000000;

pub enum Error {
    InvalidParameters(String),
    NotSupported,
    SizeLimitExceeded,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn get_cpuid(function: u32, count: u32) -> Result<CpuidResult, Error> {
    // For x86 the host supports the `cpuid` instruction if SSE is enabled. Otherwise it's hard to check.
    // TODO: replace with validation based on `has_cpuid()` when it becomes stable:
    //  https://doc.rust-lang.org/core/arch/x86/fn.has_cpuid.html
    #[cfg(target_arch = "x86")]
    {
        #[cfg(not(target_feature = "sse"))]
        {
            return Err(Error::NotSupported);
        }
    }

    // this is safe because the host supports the `cpuid` instruction
    let max_function = unsafe { __get_cpuid_max(function & EXT_FUNCTION).0 };
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
///
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn get_vendor_id() -> Result<[u8; 12], Error> {
    match get_cpuid(0, 0) {
        Ok(vendor_entry) => {
            let bytes: [u8; 12] = unsafe {
                std::mem::transmute([vendor_entry.ebx, vendor_entry.edx, vendor_entry.ecx])
            };
            Ok(bytes)
        }
        Err(_e) => Err(Error::NotSupported),
    }
}

/// Replaces the `cpuid` entries corresponding to `function` with the entries from the host's cpuid.
///
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn emulate_host_cpuid_function(cpuid: &mut CpuId, function: u32) -> Result<(), Error> {
    // copy all the CpuId entries, except for the ones with the provided function
    let mut entries: Vec<kvm_cpuid_entry2> = Vec::new();
    for entry in cpuid.mut_entries_slice().iter() {
        if entry.function != function {
            entries.push(*entry);
        }
    }

    // add all the host leaves with the provided function
    let mut count: u32 = 0;
    while let Ok(entry) = get_cpuid(function, count) {
        // check if there's enough space to add a new entry to the cpuid
        if entries.len() == kvm::MAX_KVM_CPUID_ENTRIES {
            return Err(Error::SizeLimitExceeded);
        }

        entries.push(kvm_cpuid_entry2 {
            function: function,
            index: count,
            flags: 0,
            eax: entry.eax,
            ebx: entry.ebx,
            ecx: entry.ecx,
            edx: entry.edx,
            padding: [0, 0, 0],
        });
        count += 1;
    }

    let cpuid2 = CpuId::from_entries(&entries);
    *cpuid = cpuid2;

    //    cpuid.set_entries(&entries);
    Ok(())
}

#[cfg(test)]
mod tests {
    use common::*;
    use kvm::CpuId;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_topoext_fn() -> u32 {
        let vendor_id = get_vendor_id();
        assert!(vendor_id.is_ok());
        let function = match &vendor_id.ok().unwrap() {
            INTEL => 0x4,
            AMD => 0x8000001d,
            _ => 0,
        };
        assert!(function != 0);

        function
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_cpu_id_test() {
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
        match get_cpuid(0x90000000, 0) {
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
    fn get_vendor_id_test() {
        let vendor_id = get_vendor_id();
        assert!(vendor_id.is_ok());
        assert!(match &vendor_id.ok().unwrap() {
            INTEL => true,
            AMD => true,
            _ => false,
        });
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn emulate_host_cpuid_function_test() {
        // try to emulate the extended cache topology leaves
        let topoext_fn = get_topoext_fn();

        // check that it behaves correctly for TOPOEXT function
        let mut cpuid = CpuId::new(1);
        cpuid.mut_entries_slice()[0].function = topoext_fn;
        emulate_host_cpuid_function(&mut cpuid, topoext_fn);
        let entries = cpuid.mut_entries_slice();
        assert!(entries.len() > 1);
        let mut count = 0;
        for entry in entries.iter_mut() {
            assert!(entry.function == topoext_fn);
            assert!(entry.index == count);
            assert!(entry.eax != 0);
            count = count + 1;
        }

        // check that it returns Err when there are too many entriesentry.function == topoext_fn
        let mut cpuid = CpuId::new(kvm::MAX_KVM_CPUID_ENTRIES);
        match emulate_host_cpuid_function(&mut cpuid, topoext_fn) {
            Err(Error::SizeLimitExceeded) => {}
            _ => panic!("Wrong behavior"),
        }
    }
}
