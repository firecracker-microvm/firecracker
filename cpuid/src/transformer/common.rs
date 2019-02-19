// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use bit_helper::BitHelper;

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
    entry
        .ecx
        .write_bit(ecx::TSC_DEADLINE_TIMER_BITINDEX, true)
        .write_bit(ecx::HYPERVISOR_BITINDEX, true);

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

#[cfg(test)]
mod test {
    use super::*;
    use kvm_bindings::kvm_cpuid_entry2;
    use transformer::VmSpec;

    #[test]
    fn test() {
        assert_eq!(get_max_cpus_per_package(1).unwrap(), 1);
        assert_eq!(get_max_cpus_per_package(2).unwrap(), 2);
        assert_eq!(get_max_cpus_per_package(4).unwrap(), 4);
        assert_eq!(get_max_cpus_per_package(6).unwrap(), 8);

        assert!(get_max_cpus_per_package(u8::max_value()).is_err());
    }

    fn check_update_feature_info_entry(cpu_count: u8, expected_htt: bool) {
        use cpu_leaf::leaf_0x1::*;

        let vm_spec = VmSpec::new(0, cpu_count, false);
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

    #[test]
    fn test_1vcpu() {
        check_update_feature_info_entry(1, false);
    }

    #[test]
    fn test_2vcpu() {
        check_update_feature_info_entry(2, true);
    }
}
