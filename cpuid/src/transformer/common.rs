// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use bit_helper::BitHelper;
use common::get_cpuid;

use kvm_bindings::kvm_cpuid_entry2;
use kvm_ioctls::CpuId;

// constants for setting the fields of kvm_cpuid2 structures
// CPUID bits in ebx, ecx, and edx.
const EBX_CLFLUSH_CACHELINE: u32 = 8; // Flush a cache line size.

/// The maximum number of logical processors per package is computed as the closest power of 2
/// higher or equal to the CPU count configured by the user.
fn get_max_cpus_per_package(cpu_count: u8) -> Result<u8, Error> {
    let mut max_cpus_per_package: u8 = 1;
    while max_cpus_per_package < cpu_count {
        max_cpus_per_package <<= 1;

        if max_cpus_per_package == 0 {
            return Err(Error::VcpuCountOverflow);
        }
    }

    Ok(max_cpus_per_package)
}

pub fn update_feature_info_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    use cpu_leaf::leaf_0x1::*;

    let max_cpus_per_package = u32::from(common::get_max_cpus_per_package(vm_spec.cpu_count)?);

    // X86 hypervisor feature
    entry.ecx.write_bit(ecx::HYPERVISOR_BITINDEX, true);

    entry
        .ebx
        .write_bits_in_range(&ebx::APICID_BITRANGE, u32::from(vm_spec.cpu_id))
        .write_bits_in_range(&ebx::CLFLUSH_SIZE_BITRANGE, EBX_CLFLUSH_CACHELINE)
        .write_bits_in_range(&ebx::CPU_COUNT_BITRANGE, max_cpus_per_package);

    // A value of 1 for HTT indicates the value in CPUID.1.EBX[23:16]
    // (the Maximum number of addressable IDs for logical processors in this package)
    // is valid for the package
    entry.edx.write_bit(edx::HTT, vm_spec.cpu_count > 1);

    Ok(())
}

pub fn update_brand_string_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    let brand_string = vm_spec.brand_string();
    entry.eax = brand_string.get_reg_for_leaf(entry.function, BsReg::EAX);
    entry.ebx = brand_string.get_reg_for_leaf(entry.function, BsReg::EBX);
    entry.ecx = brand_string.get_reg_for_leaf(entry.function, BsReg::ECX);
    entry.edx = brand_string.get_reg_for_leaf(entry.function, BsReg::EDX);

    Ok(())
}

pub fn update_cache_parameters_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    use cpu_leaf::leaf_cache_parameters::*;

    match entry.eax.read_bits_in_range(&eax::CACHE_LEVEL_BITRANGE) {
        // L1 & L2 Cache
        1 | 2 => {
            // The L1 & L2 cache is shared by at most 2 hyperthreads
            entry.eax.write_bits_in_range(
                &eax::MAX_CPUS_PER_CORE_BITRANGE,
                (vm_spec.cpu_count > 1 && vm_spec.ht_enabled) as u32,
            );
        }
        // L3 Cache
        3 => {
            // The L3 cache is shared among all the logical threads
            entry.eax.write_bits_in_range(
                &eax::MAX_CPUS_PER_CORE_BITRANGE,
                u32::from(vm_spec.cpu_count - 1),
            );
        }
        _ => (),
    }

    Ok(())
}

/// Replaces the `cpuid` entries corresponding to `function` with the entries from the host's cpuid.
///
pub fn use_host_cpuid_function(cpuid: &mut CpuId, function: u32) -> Result<(), Error> {
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
        if entries.len() == kvm_ioctls::MAX_KVM_CPUID_ENTRIES {
            return Err(Error::SizeLimitExceeded);
        }

        entries.push(kvm_cpuid_entry2 {
            function,
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

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use common::tests::get_topoext_fn;
    use common::VENDOR_ID_INTEL;
    use kvm_bindings::kvm_cpuid_entry2;
    use transformer::VmSpec;

    #[test]
    fn test_get_max_cpus_per_package() {
        assert_eq!(get_max_cpus_per_package(1).unwrap(), 1);
        assert_eq!(get_max_cpus_per_package(2).unwrap(), 2);
        assert_eq!(get_max_cpus_per_package(4).unwrap(), 4);
        assert_eq!(get_max_cpus_per_package(6).unwrap(), 8);

        assert!(get_max_cpus_per_package(u8::max_value()).is_err());
    }

    fn check_update_feature_info_entry(cpu_count: u8, expected_htt: bool) {
        use cpu_leaf::leaf_0x1::*;

        let vm_spec = VmSpec::new(VENDOR_ID_INTEL, 0, cpu_count, false);
        let mut entry = &mut kvm_cpuid_entry2 {
            function: 0x0,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_feature_info_entry(&mut entry, &vm_spec).is_ok());

        assert!(entry.edx.read_bit(edx::HTT) == expected_htt)
    }

    fn check_update_cache_parameters_entry(
        cpu_count: u8,
        ht_enabled: bool,
        cache_level: u32,
        expected_max_cpus_per_core: u32,
    ) {
        use cpu_leaf::leaf_cache_parameters::*;

        let vm_spec = VmSpec::new(VENDOR_ID_INTEL, 0, cpu_count, ht_enabled);
        let mut entry = &mut kvm_cpuid_entry2 {
            function: 0x0,
            index: 0,
            flags: 0,
            eax: *(0 as u32).write_bits_in_range(&eax::CACHE_LEVEL_BITRANGE, cache_level),
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_cache_parameters_entry(&mut entry, &vm_spec).is_ok());

        assert!(
            entry
                .eax
                .read_bits_in_range(&eax::MAX_CPUS_PER_CORE_BITRANGE)
                == expected_max_cpus_per_core
        );
    }

    #[test]
    fn test_1vcpu_ht_off() {
        check_update_feature_info_entry(1, false);

        // test update_deterministic_cache_entry
        // test L1
        check_update_cache_parameters_entry(1, false, 1, 0);
        // test L2
        check_update_cache_parameters_entry(1, false, 2, 0);
        // test L3
        check_update_cache_parameters_entry(1, false, 3, 0);
    }

    #[test]
    fn test_1vcpu_ht_on() {
        check_update_feature_info_entry(1, false);

        // test update_deterministic_cache_entry
        // test L1
        check_update_cache_parameters_entry(1, true, 1, 0);
        // test L2
        check_update_cache_parameters_entry(1, true, 2, 0);
        // test L3
        check_update_cache_parameters_entry(1, true, 3, 0);
    }

    #[test]
    fn test_2vcpu_ht_off() {
        check_update_feature_info_entry(2, true);

        // test update_deterministic_cache_entry
        // test L1
        check_update_cache_parameters_entry(2, false, 1, 0);
        // test L2
        check_update_cache_parameters_entry(2, false, 2, 0);
        // test L3
        check_update_cache_parameters_entry(2, false, 3, 1);
    }

    #[test]
    fn test_2vcpu_ht_on() {
        check_update_feature_info_entry(2, true);

        // test update_deterministic_cache_entry
        // test L1
        check_update_cache_parameters_entry(2, true, 1, 1);
        // test L2
        check_update_cache_parameters_entry(2, true, 2, 1);
        // test L3
        check_update_cache_parameters_entry(2, true, 3, 1);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn use_host_cpuid_function_test() {
        // try to emulate the extended cache topology leaves
        let topoext_fn = get_topoext_fn();

        // check that it behaves correctly for TOPOEXT function
        let mut cpuid = CpuId::new(1);
        cpuid.mut_entries_slice()[0].function = topoext_fn;
        assert!(use_host_cpuid_function(&mut cpuid, topoext_fn).is_ok());
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
        let mut cpuid = CpuId::new(kvm_ioctls::MAX_KVM_CPUID_ENTRIES);
        match use_host_cpuid_function(&mut cpuid, topoext_fn) {
            Err(Error::SizeLimitExceeded) => {}
            _ => panic!("Wrong behavior"),
        }
    }
}
